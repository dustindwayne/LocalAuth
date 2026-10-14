package com.localauth

import android.app.AlertDialog
import android.content.*
import android.graphics.BitmapFactory
import android.os.*
import android.view.WindowManager
import android.widget.*
import android.hardware.fingerprint.FingerprintManager
import android.os.CancellationSignal

import androidx.activity.result.contract.ActivityResultContracts
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer

@Suppress("DEPRECATION")
class MainActivity : androidx.fragment.app.FragmentActivity() {
    private lateinit var root: LinearLayout
    private lateinit var vault: Vault
    private lateinit var backups: BackupController
    private var pendingExportUri: android.net.Uri? = null
    private var pendingKitUri: android.net.Uri? = null
    private var exported: (() -> Unit)? = null
    private val kitExport = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        pendingExportUri=uri
        if(uri==null)exported=null
        if(unlocked&&active)showVault()else locked()
    }
    private val kitImport = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        pendingKitUri=uri
        if(uri==null)backups.cancelRecoveryKit()
        if(unlocked&&active)showVault()else locked()
    }
    private val localPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted -> if (granted && unlocked) backups.foreground() }
    private val recoveryFile = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) try {
            val blob = contentResolver.openInputStream(uri)?.use { input ->
                val out=java.io.ByteArrayOutputStream();val buffer=ByteArray(8192)
                while(true){val count=input.read(buffer);if(count<0)break;require(out.size()+count<=PortableBackup.MAX);out.write(buffer,0,count)}
                out.toByteArray()
            } ?: error("File unavailable")
            backups.receiveFile(blob)
        } catch (_:Exception) { message("Could not read recovery file") }
    }
    private val handler = Handler(Looper.getMainLooper())
    private var unlocked = false
    private var active = false
    private var authenticating = false
    private var authEpoch = 0
    private var cancellation: CancellationSignal? = null
    private var pending: String? = null
    private var dialog: AlertDialog? = null
    private var copied: String? = null
    private val clipboard by lazy { getSystemService(CLIPBOARD_SERVICE) as ClipboardManager }
    private val rows = mutableListOf<AccountCard>()
    private var firstPromptShown = false
    private var scanToMatchNanos = 0L
    private var matchToScreenNanos = 0L
    private val ticker = object : Runnable { override fun run() { if (unlocked && active) { refresh(); handler.postDelayed(this, 1000) } } }
    private val scan = registerForActivityResult(ScanContract()) { result -> result.contents?.let { receive(it) } }
    private val gallery = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) try {
            val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, options) }
            require(options.outWidth > 0 && options.outHeight > 0) { "Invalid image" }
            var sample = 1
            while (options.outWidth / sample > 2048 || options.outHeight / sample > 2048) sample *= 2
            options.inJustDecodeBounds = false; options.inSampleSize = sample
            val bitmap = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, options) } ?: error("Cannot open image")
            try {
                val pixels = IntArray(bitmap.width * bitmap.height); bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
                val reader = MultiFormatReader()
                val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true)
                val result = try { reader.decode(BinaryBitmap(HybridBinarizer(source)), hints) } catch (_: NotFoundException) { reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints) }
                pixels.fill(0); receive(result.text)
            } finally { bitmap.recycle() }
        } catch (_: Exception) { message("No readable authenticator QR in this image") }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        vault = Vault(this)
        backups = BackupController(this,vault,{active && unlocked && !vault.needsRecoveryExport},{showVault()})
        root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(28, 48, 28, 28); isSaveFromParentEnabled = false }
        setContentView(ScrollView(this).apply { setBackgroundColor(Design.bg); isFillViewport = true; addView(root) })
        root.setOnApplyWindowInsetsListener { view, insets -> view.setPadding(Design.dp(this,24) + insets.systemWindowInsetLeft, Design.dp(this,24) + insets.systemWindowInsetTop, Design.dp(this,24) + insets.systemWindowInsetRight, Design.dp(this,24) + insets.systemWindowInsetBottom); insets }
        root.requestApplyInsets(); locked()
    }
    override fun onResume() { super.onResume(); active = true; if (!vault.exists && !firstPromptShown) { firstPromptShown = true; root.post { if (active) authenticate() } } }
    override fun onPause() {
        backups.pause()
        active = false; scanToMatchNanos = 0; matchToScreenNanos = 0; root.animate().cancel(); authEpoch++; authenticating = false; cancellation?.cancel(); cancellation = null
        dialog?.dismiss(); dialog = null; handler.removeCallbacks(ticker)
        unlocked = false; vault.lock(); rows.clear(); clearClipboard(); locked()
        super.onPause()
    }
    override fun onDestroy() { pending = null; backups.destroy(); handler.removeCallbacksAndMessages(null); super.onDestroy() }
    fun chooseRecoveryFile() { recoveryFile.launch("*/*") }
    fun chooseRecoveryKit() { kitImport.launch("*/*") }
    fun exportRecoveryKit(success:()->Unit) {
        if(!unlocked||!vault.needsRecoveryExport)return
        exported=success
        kitExport.launch("LocalAuth-offline-recovery.json")
    }
    private fun AlertDialog.secureShow():AlertDialog {
        checkNotNull(window).addFlags(WindowManager.LayoutParams.FLAG_SECURE);show();return this
    }
    private fun AlertDialog.Builder.secureShow():AlertDialog=create().secureShow()
    private fun confirmRecoveryCommit() {
        if(!active||!unlocked||authenticating)return
        try {
            val cipher=vault.prepareRecoveryCommit();val signal=CancellationSignal();cancellation=signal;authenticating=true
            val epoch=++authEpoch
            val d=AlertDialog.Builder(this).setTitle("Finish recovery setup").setMessage("Confirm your fingerprint to protect the vault with a new encryption key.")
                .setNegativeButton("Cancel"){_,_->signal.cancel()}.create()
            dialog=d;d.setOnCancelListener {signal.cancel()};d.secureShow()
            getSystemService(FingerprintManager::class.java).authenticate(FingerprintManager.CryptoObject(cipher),signal,0,object:FingerprintManager.AuthenticationCallback(){
                override fun onAuthenticationSucceeded(result:FingerprintManager.AuthenticationResult){
                    if(epoch!=authEpoch||!active||!unlocked)return
                    authenticating=false;cancellation=null;d.dismiss()
                    try {
                        vault.completeRecoveryExport(requireNotNull(result.cryptoObject?.cipher))
                        val callback=exported;exported=null
                        message("Recovery kit saved. Keep it offline and off this phone.")
                        showVault();requestDiscovery();callback?.invoke()
                        pending?.let {pending=null;import(it)}
                    }catch(_:Exception){exported=null;message("Recovery setup could not finish. No accounts were deleted.");showVault()}
                }
                override fun onAuthenticationFailed(){if(epoch==authEpoch)d.setMessage("Fingerprint not recognized. Try again.")}
                override fun onAuthenticationHelp(code:Int,msg:CharSequence){if(epoch==authEpoch)d.setMessage(msg)}
                override fun onAuthenticationError(code:Int,msg:CharSequence){if(epoch==authEpoch){authenticating=false;cancellation=null;exported=null;d.dismiss();if(active)message(msg.toString())}}
            },handler)
        }catch(_:Exception){authenticating=false;cancellation?.cancel();cancellation=null;dialog?.dismiss();exported=null;message("Recovery setup could not finish. Try saving again.")}
    }
    fun requestDiscovery() {
        if(android.os.Build.VERSION.SDK_INT>=37 && checkSelfPermission("android.permission.ACCESS_LOCAL_NETWORK")!=android.content.pm.PackageManager.PERMISSION_GRANTED) localPermission.launch("android.permission.ACCESS_LOCAL_NETWORK")
        else backups.foreground()
    }
    private fun button(text: String, action: () -> Unit) { root.addView(Design.action(this,text,run=action)) }
    private fun locked(error: String? = null) {
        root.removeAllViews()
        root.addView(Design.label(this,"LOCALAUTH",12f,Design.muted).apply { letterSpacing=.18f })
        root.addView(Design.space(this,56))
        root.addView(FingerprintArt(this),LinearLayout.LayoutParams(-1,Design.dp(this,180)))
        root.addView(Design.space(this,24))
        root.addView(Design.label(this,if(vault.exists) "Your keys.\nYour device." else "Make it yours.",36f).apply { typeface=android.graphics.Typeface.create("sans-serif-medium",android.graphics.Typeface.NORMAL) })
        root.addView(Design.space(this,16))
        root.addView(Design.label(this,error ?: if(vault.exists) "A touch unlocks your accounts.\nEverything stays with you." else "Touch your fingerprint sensor to\ncreate your private vault.",16f,Design.muted))
        root.addView(Design.space(this,32))
        button(if(vault.exists) "Unlock with fingerprint" else "Set up with fingerprint") { authenticate() }
        if (pending != null) {
            root.addView(Design.space(this,12)); root.addView(Design.label(this,"An account is ready to import after unlock.",13f,Design.accent))
            root.addView(Design.action(this,"Discard import",false) { pending = null; locked() })
        }
        root.addView(Design.space(this,24))
        root.addView(Design.label(this,"PRIVATE BY DESIGN  /  YOUR OWN BACKUP",10f,Design.muted).apply { letterSpacing=.12f })
        if(active) Design.enter(root)
    }
    private fun authenticate() {
        if (!active || authenticating || unlocked) return
        if (getSharedPreferences("vault", MODE_PRIVATE).all.isNotEmpty()) { locked("Legacy vault detected. This version will not silently replace or discard its accounts. Use the old app and service recovery codes to re-enroll accounts before installing this version with fresh app data."); return }
        val manager = getSystemService(FingerprintManager::class.java)
        if (manager == null || !manager.isHardwareDetected || !manager.hasEnrolledFingerprints()) { locked("Enroll a fingerprint in Android Settings to use LocalAuth. Fingerprint hardware is required."); return }
        val creating = !vault.exists
        try {
            val cipher = vault.prepare(); authenticating = true
            val epoch = ++authEpoch
            val signal = CancellationSignal(); cancellation = signal
            val promptView = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(Design.dp(this@MainActivity,24),0,Design.dp(this@MainActivity,24),Design.dp(this@MainActivity,24)); addView(FingerprintArt(this@MainActivity),LinearLayout.LayoutParams(-1,Design.dp(this@MainActivity,140))) }
            val d = AlertDialog.Builder(this).setTitle("Touch your fingerprint sensor").setMessage("Confirm your identity.").setView(promptView).setNegativeButton("Cancel") { _, _ -> signal.cancel() }.create()
            dialog = d; d.setOnCancelListener { signal.cancel() }; d.secureShow()
            val promptNanos = SystemClock.elapsedRealtimeNanos()
            manager.authenticate(FingerprintManager.CryptoObject(cipher), signal, 0, object : FingerprintManager.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult) {
                    if (epoch != authEpoch) return
                    authenticating = false; cancellation = null
                    if (!active) { vault.lock(); return }
                    try {
                        val matchNanos = SystemClock.elapsedRealtimeNanos()
                        scanToMatchNanos = matchNanos - promptNanos
                        vault.unlock(requireNotNull(result.cryptoObject?.cipher), promptNanos, matchNanos, System.currentTimeMillis())
                        d.dismiss()
                    } catch (e: Exception) {
                        authenticationFailure(e, creating, "crypto"); return
                    }
                    try {
                        unlocked = true; showVault()
                        requestDiscovery()
                        root.postOnAnimation { if (active && unlocked && epoch == authEpoch) matchToScreenNanos = SystemClock.elapsedRealtimeNanos() - (promptNanos + scanToMatchNanos) }
                        if(!vault.needsRecoveryExport)pending?.let { pending = null; import(it) }
                    }
                    catch (e: Exception) { authenticationFailure(e, creating, "screen") }
                }
                override fun onAuthenticationFailed() { if (active && epoch == authEpoch) d.setMessage("Fingerprint not recognized. Touch the sensor to retry.") }
                override fun onAuthenticationHelp(code: Int, msg: CharSequence) { if (active && epoch == authEpoch) d.setMessage(msg) }
                override fun onAuthenticationError(code: Int, msg: CharSequence) { if (epoch != authEpoch) return
                    authenticating = false; cancellation = null; d.dismiss(); if (active && !unlocked) locked(msg.toString()) }
            }, handler)
        } catch (e: Exception) { authenticationFailure(e, creating, "prepare") }
    }
    private fun authenticationFailure(error: Exception, creating: Boolean, phase: String) {
        authenticating=false; authEpoch++; cancellation?.cancel(); cancellation=null; dialog?.dismiss()
        unlocked=false; rows.clear(); handler.removeCallbacks(ticker); vault.lock()
        val explanation = when {
            phase == "screen" -> "Your vault was unlocked, but the screen could not open. Try unlocking again."
            error is android.security.keystore.UserNotAuthenticatedException -> "Fingerprint authorization expired. Please scan again."
            error is android.security.keystore.KeyPermanentlyInvalidatedException && creating -> "Fingerprint settings changed during setup. Try setup again."
            creating -> "Fingerprint matched, but vault setup could not finish. Please retry."
            else -> "The existing vault could not be unlocked. No data was deleted."
        }
        // Only bounded exception types and public codes, never provider messages or secrets.
        val causes = generateSequence<Throwable>(error) { it.cause }.take(6).toList()
        val details = causes.joinToString(">") { cause ->
            val code = if (Build.VERSION.SDK_INT >= 33 && cause is android.security.KeyStoreException) "[${cause.numericErrorCode}]" else ""
            cause.javaClass.simpleName + code
        }
        locked("$explanation\nReference: ${if(creating) "SETUP" else "UNLOCK"}-$phase-$details")
    }
    private fun showVault() {
        if (!unlocked) return
        pendingExportUri?.let {uri->
            pendingExportUri=null
            val kit=vault.recoveryKit()
            try {
                contentResolver.openOutputStream(uri,"wt")?.use {it.write(kit);it.flush()} ?: error("File unavailable")
                confirmRecoveryCommit()
                return
            }catch(_:Exception){exported=null;message("Recovery kit setup did not finish. Try saving again.")}
            finally{kit.fill(0)}
        }
        if(vault.needsRecoveryExport) {
            handler.removeCallbacks(ticker);rows.clear();root.removeAllViews()
            root.addView(Design.label(this,"Protect your recovery.",30f));root.addView(Design.space(this,20))
            root.addView(Design.label(this,"Save a recovery kit to offline storage before adding or accessing accounts. Keep it off this phone and separate from your backup server.\n\nThe app retains only the public encryption key after setup. Losing your kit and phone means losing your accounts.",16f,Design.muted))
            button("Save offline recovery kit") { exportRecoveryKit {showVault()} }
            button("Lock") {unlocked=false;vault.lock();locked()}
            return
        }
        pendingKitUri?.let {uri->
            pendingKitUri=null
            try {
                val bytes=contentResolver.openInputStream(uri)?.use {input->
                    val out=java.io.ByteArrayOutputStream();val buffer=ByteArray(2048)
                    try {while(true){val count=input.read(buffer);if(count<0)break;require(out.size()+count<=16000);out.write(buffer,0,count)};out.toByteArray()}finally{buffer.fill(0)}
                } ?: error("File unavailable")
                try {backups.receiveRecoveryKit(String(bytes,Charsets.UTF_8))}finally{bytes.fill(0)}
            }catch(_:Exception){backups.cancelRecoveryKit();message("Could not read recovery kit")}
        }
        root.removeAllViews(); rows.clear()
        val header=LinearLayout(this).apply { gravity=android.view.Gravity.CENTER_VERTICAL }
        val title=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; addView(Design.label(this@MainActivity,"LocalAuth",28f).apply { typeface=android.graphics.Typeface.create("sans-serif-medium",android.graphics.Typeface.NORMAL) }); addView(Design.label(this@MainActivity,"ON THIS DEVICE",10f,Design.accent).apply { letterSpacing=.14f; setPadding(0,Design.dp(context,8),0,0) }) }
        header.addView(title,LinearLayout.LayoutParams(0,-2,1f))
        header.addView(Design.action(this,"Lock",false) { backups.pause();unlocked=false; rows.clear(); vault.lock(); handler.removeCallbacks(ticker); clearClipboard(); locked() }.apply { layoutParams=LinearLayout.LayoutParams(Design.dp(context,76),Design.dp(context,46)) })
        root.addView(header); root.addView(Design.space(this,32))
        val section=LinearLayout(this).apply { gravity=android.view.Gravity.CENTER_VERTICAL }
        section.addView(Design.label(this,"Your accounts",16f),LinearLayout.LayoutParams(0,-2,1f))
        section.addView(Design.label(this,vault.accounts.size.toString().padStart(2,'0'),13f,Design.muted))
        root.addView(section); root.addView(Design.space(this,4))
        if (vault.accounts.isEmpty()) {
            val empty=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(Design.dp(context,24),Design.dp(context,32),Design.dp(context,24),Design.dp(context,32)); background=Design.shape(context,Design.surface); layoutParams=LinearLayout.LayoutParams(-1,-2).apply { topMargin=Design.dp(context,16) } }
            empty.addView(Design.label(this,"Ready when you are.",24f)); empty.addView(Design.space(this,12)); empty.addView(Design.label(this,"Scan a setup QR code or add a secret.\nYour codes will appear here.",15f,Design.muted)); root.addView(empty)
        }
        vault.accounts.sortedBy { it.label }.forEach { a ->
            val card=AccountCard(this,a,copy={ copyCode(a) },remove={ removeAccount(a); true })
            root.addView(card); rows.add(card)
        }
        root.addView(Design.space(this,12)); button("+  Add account") { addMenu() }
        root.addView(Design.action(this,"Home backup",false) {backups.menu()})
        val lastBackup=vault.settings.optLong("lastBackup",0)
        if(lastBackup>0) root.addView(Design.label(this,"Last backup · "+java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT,java.text.DateFormat.SHORT).format(java.util.Date(lastBackup)),12f,Design.muted).apply {setPadding(0,Design.dp(context,12),0,0)})
        root.addView(Design.space(this,20)); root.addView(Design.label(this,"Tap to scan fingerprint and copy · Hold to remove",12f,Design.muted))
        handler.removeCallbacks(ticker); ticker.run(); Design.enter(root)
    }
    private fun addMenu() {
        if(!unlocked) return
        dialog=AlertDialog.Builder(this).setTitle("Add an account").setItems(arrayOf("Scan QR code","Import QR image","Enter secret manually")) { _, which ->
            if(unlocked) when(which) {
                0 -> scan.launch(ScanOptions().setCaptureActivity(SecureCaptureActivity::class.java).setDesiredBarcodeFormats(ScanOptions.QR_CODE).setPrompt("Scan account setup QR").setBeepEnabled(false).setOrientationLocked(false))
                1 -> gallery.launch("image/*")
                2 -> manual()
            }
        }.setNegativeButton("Cancel",null).secureShow()
    }
    private fun copyCode(a: Account) {
        if(!unlocked || !active || authenticating || vault.needsRecoveryExport) return
        val card=rows.firstOrNull {it.account.id==a.id}?:return
        card.cachedCode(System.currentTimeMillis()/1000)?.let {copyValue(it);return}
        try {
            val mac=HardwareOtp.prepare(a)
            val manager=getSystemService(FingerprintManager::class.java)?:error("Fingerprint unavailable")
            val signal=CancellationSignal();cancellation=signal;authenticating=true
            val epoch=++authEpoch
            val d=AlertDialog.Builder(this).setTitle("Confirm fingerprint").setMessage("Generate a code for ${a.label}.")
                .setNegativeButton("Cancel"){_,_->signal.cancel()}.create()
            dialog=d;d.setOnCancelListener {signal.cancel()};d.secureShow()
            manager.authenticate(FingerprintManager.CryptoObject(mac),signal,0,object:FingerprintManager.AuthenticationCallback(){
                override fun onAuthenticationSucceeded(result:FingerprintManager.AuthenticationResult){
                    if(epoch!=authEpoch||!active||!unlocked)return
                    authenticating=false;cancellation=null;d.dismiss()
                    try {
                        check(result.cryptoObject?.mac===mac)
                        val now=System.currentTimeMillis()/1000
                        val code=HardwareOtp.complete(a,mac,now);card.reveal(code,now);copyValue(code)
                    }catch(_:Exception){message("Hardware could not generate this code. Restore the account if fingerprint settings changed.")}
                }
                override fun onAuthenticationFailed(){if(epoch==authEpoch)d.setMessage("Fingerprint not recognized. Try again.")}
                override fun onAuthenticationHelp(code:Int,msg:CharSequence){if(epoch==authEpoch)d.setMessage(msg)}
                override fun onAuthenticationError(code:Int,msg:CharSequence){if(epoch==authEpoch){authenticating=false;cancellation=null;d.dismiss();if(active)message(msg.toString())}}
            },handler)
        }catch(_:Exception){authenticating=false;cancellation?.cancel();cancellation=null;dialog?.dismiss();message("This device cannot generate this account's code with hardware protection.")}
    }
    private fun copyValue(code:String) {
        copied=code
        val clip=ClipData.newPlainText("LocalAuth code",code)
        if(Build.VERSION.SDK_INT>=33) clip.description.extras=PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE,true) }
        clipboard.setPrimaryClip(clip); message("Code copied")
        handler.postDelayed({ if(copied==code) clearClipboard() },30000)
    }
    private fun removeAccount(a: Account) {
        if(!unlocked) return
        dialog=AlertDialog.Builder(this).setTitle("Remove ${a.label}?").setMessage("Keep your service recovery codes. Removing this account cannot be undone.")
            .setPositiveButton("Remove") { _,_ -> if(unlocked) { val index=vault.accounts.indexOf(a); vault.accounts.remove(a); try { vault.save(); runCatching {HardwareOtp.delete(a.hardwareAlias)};showVault();backups.onAccountsChanged() } catch(_:Exception) { vault.accounts.add(index,a); message("Save failed; account kept") } } }.setNegativeButton("Cancel",null).secureShow()
    }
    private fun refresh() { val now=System.currentTimeMillis()/1000; rows.forEach { it.update(now) } }
    private fun receive(text: String) { pending = text.take(8193); if (unlocked && active) { pending = null; import(text) } else locked() }
    private fun import(text: String) { if(text.startsWith("localauth-pair:")){backups.pairCode(text);return};try { confirm(Otp.parse(text)) } catch (e: Exception) { message(e.message ?: "Unsupported TOTP QR") } }
    private fun confirm(a: Account) {
        if (!unlocked) return
        dialog = AlertDialog.Builder(this).setTitle("Add ${a.label}?").setMessage("${a.algorithm} · ${a.digits} digits · ${a.period} seconds")
            .setPositiveButton("Add") { _, _ -> add(a) }.setNegativeButton("Cancel", null).secureShow()
    }
    private fun add(a: Account) {
        if (!unlocked || vault.needsRecoveryExport) return
        if (vault.accounts.size >= 1000) { message("Account limit reached"); return }
        val seed=Otp.decode(a.secret);val fingerprint=try{PortableBackup.hash(seed)}finally{seed.fill(0)}
        if (vault.accounts.any { it.seedFingerprint == fingerprint && it.algorithm == a.algorithm && it.digits == a.digits && it.period == a.period }) { message("This secret is already saved"); return }
        vault.accounts.add(a)
        try { vault.save(); showVault();backups.onAccountsChanged() } catch (_: Exception) { vault.accounts.remove(a); message("Account was not saved. Hardware support for this secret may be unavailable.") }
    }
    private fun manual() {
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(Design.dp(context,24),Design.dp(context,8),Design.dp(context,24),Design.dp(context,16)) }
        val name = EditText(this).apply { hint = "Account name (for bare secret)"; importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO }
        val secret = EditText(this).apply { hint = "Base32 secret or otpauth://totp URI"; inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD; importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO }
        val algorithm = Spinner(this).apply { adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("SHA1", "SHA256", "SHA512")) }
        val digits = Spinner(this).apply { adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, listOf("6", "8")) }
        val period = EditText(this).apply { hint = "Period in seconds"; setText("30"); inputType = android.text.InputType.TYPE_CLASS_NUMBER }
        listOf(name, secret, algorithm, digits, period).forEach { layout.addView(it) }
        val d = AlertDialog.Builder(this).setTitle("Add account").setView(ScrollView(this).apply { addView(layout) }).setPositiveButton("Add", null).setNegativeButton("Cancel", null).create(); dialog = d; d.secureShow()
        d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            if (unlocked) try {
                val value = secret.text.toString().trim()
                val a = if (value.startsWith("otpauth:")) Otp.parse(value) else Otp.validate(Account(java.util.UUID.randomUUID().toString(), name.text.toString().trim(), value, algorithm.selectedItem.toString(), digits.selectedItem.toString().toInt(), period.text.toString().toInt()))
                add(a); secret.text.clear(); d.dismiss()
            } catch (e: Exception) { secret.error = e.message ?: "Invalid account" }
        }
        d.setOnDismissListener { secret.text.clear(); name.text.clear() }
    }
    private fun clearClipboard() {
        try { if (copied != null && clipboard.primaryClip?.getItemAt(0)?.text?.toString() == copied) clipboard.clearPrimaryClip() } catch (_: Exception) { }
        copied = null
    }
    private fun message(text: String) { Toast.makeText(this, text, Toast.LENGTH_LONG).show() }
}
