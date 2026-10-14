package com.localauth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import android.os.Build
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class Vault(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "vault-v2.json"))
    private val alias = "localauth.biometric.v2"
    private val aad = "LocalAuth vault v2".toByteArray()
    private var dataKey: ByteArray? = null
    private var wrapped: ByteArray? = null
    private var wrapIv: ByteArray? = null
    private var envelope: JSONObject? = null
    private val session = VaultSession()
    private var preparedCipher: Cipher? = null
    private var recoveryCipher: Cipher? = null
    val accounts = mutableListOf<Account>()
    var settings = JSONObject()
        private set
    val exists get() = file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()
    val needsRecoveryExport get() = settings.has("pendingBackupPrivate")
    private fun ensureRecipient() {
        if (!settings.has("backupPublic") || !settings.optBoolean("recoveryConfirmed")) {
            val (publicKey, privateKey) = PublicBackup.generate()
            settings.put("backupPublic",publicKey).put("pendingBackupPrivate",privateKey).put("recoveryConfirmed",false)
        }
    }
    fun recoveryKit():ByteArray {
        checkNotNull(dataKey); check(needsRecoveryExport)
        return JSONObject().put("format","LocalAuth recovery v2").put("public_key",settings.getString("backupPublic"))
            .put("private_key",settings.getString("pendingBackupPrivate")).toString(2).toByteArray(Charsets.UTF_8)
    }
    fun prepareRecoveryCommit():Cipher {
        checkNotNull(dataKey);check(needsRecoveryExport)
        return Cipher.getInstance("AES/GCM/NoPadding").apply {init(Cipher.ENCRYPT_MODE,key(false));recoveryCipher=this}
    }
    fun completeRecoveryExport(cipher:Cipher) {
        checkNotNull(dataKey); check(needsRecoveryExport)
        check(cipher===recoveryCipher)
        val previous=JSONObject(settings.toString())
        val previousKey=dataKey;val previousWrapped=wrapped;val previousIv=wrapIv
        val replacement=ByteArray(32).also {java.security.SecureRandom().nextBytes(it)}
        try {
        cipher.updateAAD(aad)
        wrapped=cipher.doFinal(replacement);wrapIv=cipher.iv;dataKey=replacement
        settings.remove("pendingBackupPrivate");settings.put("recoveryConfirmed",true)
        save();previousKey?.fill(0)
        } catch(e:Exception){settings=previous;dataKey=previousKey;wrapped=previousWrapped;wrapIv=previousIv;replacement.fill(0);throw e}
        finally{recoveryCipher=null}
    }
    private fun hardwareBiometricKey(key: java.security.Key): java.security.Key {
        val info = SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
            .getKeySpec(key as SecretKey, KeyInfo::class.java) as KeyInfo
        @Suppress("DEPRECATION")
        val hardware = if (Build.VERSION.SDK_INT >= 31) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else info.isInsideSecureHardware
        check(hardware && info.isUserAuthenticationRequired &&
            info.isUserAuthenticationRequirementEnforcedBySecureHardware &&
            info.userAuthenticationValidityDurationSeconds <= 0) {
            "This device cannot provide hardware-enforced biometric vault protection."
        }
        if (Build.VERSION.SDK_INT >= 30) check(
            info.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG
        ) { "Vault protection requires a strong biometric for every unlock." }
        return key
    }
    private fun key(create: Boolean): java.security.Key {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!create) return hardwareBiometricKey(checkNotNull(ks.getKey(alias, null)) { "Vault key unavailable. Restore accounts using your service recovery codes." })
        check(!exists) { "Existing vault must not be replaced" }
        // A cancelled setup can leave an unused key, but no existing vault references it.
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        else @Suppress("DEPRECATION") spec.setUserAuthenticationValidityDurationSeconds(-1)
        return hardwareBiometricKey(KeyGenerator.getInstance("AES", "AndroidKeyStore").apply { init(spec.build()) }.generateKey())
    }
    private fun decode(s: String) = android.util.Base64.decode(s, android.util.Base64.NO_WRAP)
    private fun encode(b: ByteArray) = android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP)
    fun prepare(): Cipher {
        lock()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        if (session.begin(exists) == VaultSession.Mode.OPEN) {
            require(file.baseFile.length() <= 4_000_000) { "Vault too large" }
            val e = JSONObject(String(file.readFully(), Charsets.UTF_8)); require(e.getInt("version") == 2)
            envelope = e; wrapIv = decode(e.getString("wrapIv")); wrapped = decode(e.getString("wrapped"))
            c.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, wrapIv))
        } else c.init(Cipher.ENCRYPT_MODE, key(true))
        preparedCipher = c
        return c
    }
    fun unlock(cipher: Cipher, promptNanos: Long, matchNanos: Long, wallMillis: Long) {
        check(cipher === preparedCipher) { "Fingerprint operation changed" }
        // Auth-bound Keystore updateAAD can fail before the operation is authorized.
        // Keep init -> fingerprint CryptoObject -> updateAAD -> doFinal in that order.
        cipher.updateAAD(aad)
        if (session.requireMode() == VaultSession.Mode.OPEN) {
            dataKey = cipher.doFinal(requireNotNull(wrapped))
            require(dataKey!!.size == 32)
            val e = requireNotNull(envelope)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(dataKey, "AES"), GCMParameterSpec(128, decode(e.getString("iv"))))
            c.updateAAD(aad)
            val plain = c.doFinal(decode(e.getString("ciphertext")))
            try {
                val text = String(plain, Charsets.UTF_8)
                val list = if (text.startsWith("[")) JSONArray(text) else JSONObject(text).let { settings = it.optJSONObject("settings") ?: JSONObject(); it.getJSONArray("accounts") }
                require(list.length() <= 1000)
                for (i in 0 until list.length()) { val a = list.getJSONObject(i); accounts.add(Otp.validate(Account(a.getString("id"), a.getString("label"), a.optString("secret"), a.getString("algorithm"), a.getInt("digits"), a.getInt("period"),a.optString("hardwareAlias"),a.optString("seedCapsule"),a.optString("seedFingerprint")))) }
                require(accounts.map {it.id}.toSet().size==accounts.size)
                // A recovery private key is NEVER persisted. Legacy seed migration is
                // deferred until its offline kit has actually been written.
                ensureRecipient()
            } finally { plain.fill(0); envelope = null; session.clear(); preparedCipher = null }
        } else {
            check(!exists) { "Vault appeared during setup; unlock it instead" }
            dataKey = VaultKey.generate(promptNanos, matchNanos, wallMillis)
            wrapped = cipher.doFinal(requireNotNull(dataKey)); wrapIv = cipher.iv; ensureRecipient();save()
        }
    }
    fun save() {
        val k = checkNotNull(dataKey)
        check(settings.has("backupPublic"))
        val previous=accounts.toList()
        val imported=mutableListOf<String>()
        try {
        accounts.indices.forEach {i->
            val a=accounts[i]
            if(a.secret.isNotEmpty()) {
                check(!needsRecoveryExport) { "Save your offline recovery kit before adding accounts" }
                Otp.validate(a)
                val seed=Otp.decode(a.secret)
                try {
                    val capsule=PublicBackup.seal(a,settings.getString("backupPublic"))
                    val hardware=HardwareOtp.import(seed,a.algorithm); imported.add(hardware)
                    accounts[i]=a.copy(secret="",hardwareAlias=hardware,seedCapsule=capsule,seedFingerprint=PortableBackup.hash(seed))
                } finally {seed.fill(0)}
            }
        }
        settings.remove("recovery")
        val list = JSONArray()
        accounts.forEach { a -> Otp.validate(a);list.put(JSONObject().put("id",a.id).put("label",a.label).put("algorithm",a.algorithm).put("digits",a.digits).put("period",a.period).put("hardwareAlias",a.hardwareAlias).put("seedCapsule",a.seedCapsule).put("seedFingerprint",a.seedFingerprint)) }
        val diskSettings=JSONObject(settings.toString()).apply {
            remove("pendingBackupPrivate")
            if(needsRecoveryExport)remove("backupPublic")
        }
        val plain = JSONObject().put("accounts",list).put("settings",diskSettings).toString().toByteArray(Charsets.UTF_8)
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k,"AES")); c.updateAAD(aad)
        val encrypted = try { c.doFinal(plain) } finally { plain.fill(0) }
        val e = JSONObject().put("version",2).put("wrapIv",encode(requireNotNull(wrapIv))).put("wrapped",encode(requireNotNull(wrapped))).put("iv",encode(c.iv)).put("ciphertext",encode(encrypted))
        val bytes=e.toString().toByteArray(Charsets.UTF_8)
        require(bytes.size<=4_000_000) { "Vault storage limit reached" }
        val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) } catch (e: Exception) { file.failWrite(stream); throw e }
        } catch(e:Exception) {
            accounts.clear();accounts.addAll(previous);imported.forEach {runCatching {HardwareOtp.delete(it)}};throw e
        }
    }
    fun portable(): ByteArray {
        checkNotNull(dataKey)
        check(!needsRecoveryExport && settings.optBoolean("recoveryConfirmed")) { "Save your recovery kit first" }
        val list = JSONArray()
        accounts.forEach { a -> list.put(a.seedCapsule) }
        val plain = list.toString().toByteArray(Charsets.UTF_8)
        return try { PublicBackup.encrypt(plain,settings.getString("backupPublic")) } finally { plain.fill(0) }
    }
    fun restore(blob:ByteArray,recovery:String):Int {
        checkNotNull(dataKey)
        check(!needsRecoveryExport) { "Save your recovery kit first" }
        val publicBackup=PublicBackup.isBackup(blob)
        val privateText=if(publicBackup)PublicBackup.recoveryPrivate(recovery) else ""
        val plain=if(publicBackup)PublicBackup.decrypt(blob,privateText) else {
            val key=PortableBackup.parseKey(recovery)
            try {PortableBackup.decrypt(blob,key)} finally {key.fill(0)}
        }
        val restored=mutableListOf<Account>()
        try {
            val list=JSONArray(String(plain,Charsets.UTF_8));require(list.length()<=1000)
            for(i in 0 until list.length()) {
                if(publicBackup)restored.add(PublicBackup.open(list.getString(i),privateText))
                else {val a=list.getJSONObject(i);restored.add(Otp.validate(Account(java.util.UUID.randomUUID().toString(),a.getString("label"),a.getString("secret"),a.getString("algorithm"),a.getInt("digits"),a.getInt("period"))))}
            }
        } finally {plain.fill(0)}
        fun signature(a:Account):String {val hash=if(a.seedFingerprint.isNotEmpty())a.seedFingerprint else {val bytes=Otp.decode(a.secret);try {PortableBackup.hash(bytes)}finally{bytes.fill(0)}};return "$hash/${a.algorithm}/${a.digits}/${a.period}"}
        val previous=accounts.toList();val seen=accounts.map {signature(it)}.toMutableSet()
        val additions=restored.filter {seen.add(signature(it))};require(accounts.size+additions.size<=1000)
        accounts.addAll(additions)
        try {save()} catch(e:Exception){accounts.clear();accounts.addAll(previous);throw e}
        return additions.size
    }
    fun lock() { dataKey?.fill(0); dataKey = null; accounts.clear(); settings = JSONObject(); wrapped = null; wrapIv = null; envelope = null; session.clear(); preparedCipher = null;recoveryCipher=null }
}
