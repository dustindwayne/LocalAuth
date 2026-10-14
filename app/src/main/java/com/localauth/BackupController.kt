package com.localauth

import android.app.AlertDialog
import android.content.Context
import android.widget.*
import org.json.JSONObject
import java.util.concurrent.Executors

/** All plaintext access stays on the foreground UI thread. Workers receive ciphertext only. */
class BackupController(private val activity:MainActivity,private val vault:Vault,private val alive:()->Boolean,private val changed:()->Unit) {
 private val worker=Executors.newSingleThreadExecutor()
 private val main=android.os.Handler(android.os.Looper.getMainLooper())
 private var busy=false
 private var dirty=false
 private var offered=false
 private var epoch=0
 private var pendingFile:ByteArray?=null
 private var recoveryBlob:ByteArray?=null
 private var dialog:AlertDialog?=null
 private fun AlertDialog.secureShow():AlertDialog {checkNotNull(window).addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);show();return this}
 private fun AlertDialog.Builder.secureShow():AlertDialog=create().secureShow()
 private val prefs=activity.getSharedPreferences("backup-ui",Context.MODE_PRIVATE)
 private val discovery=HomeDiscovery(activity){main.post{if(alive()&&!offered&&!busy&&dialog==null&&!vault.settings.has("home")){offered=true;dialog=AlertDialog.Builder(activity).setTitle("Home backup found").setMessage("Set up encrypted backups on your LocalAuth Home server?").setPositiveButton("Set up"){_,_->pairDialog()}.setNegativeButton("Later",null).secureShow()}}}
 fun foreground(){if(prefs.getBoolean("discover",true))discovery.start();pendingFile?.let{pendingFile=null;restoreDialog(it)};if(dirty)onAccountsChanged()}
 fun pause(){epoch++;discovery.stop();dialog?.dismiss();dialog=null}
 fun destroy(){pause();pendingFile?.fill(0);pendingFile=null;recoveryBlob?.fill(0);recoveryBlob=null;worker.shutdownNow()}
 fun receiveFile(bytes:ByteArray){pendingFile?.fill(0);if(alive())restoreDialog(bytes)else pendingFile=bytes}
 private fun message(s:String){if(alive())Toast.makeText(activity,s,Toast.LENGTH_LONG).show()}
 fun menu(){if(!alive())return
  val paired=vault.settings.has("home")
  val choices=mutableListOf(if(paired)"Back up now" else "Pair home server","Import recovery file")
  if(paired){choices.add("Restore latest server backup");choices.add(if(vault.settings.optBoolean("auto"))"Turn off automatic backups" else "Enable automatic backups");choices.add("Recovery kit status");choices.add("Disconnect server")}
  choices.add(if(prefs.getBoolean("discover",true))"Disable nearby discovery" else "Enable nearby discovery")
  dialog=AlertDialog.Builder(activity).setTitle("Home backup").setItems(choices.toTypedArray()){_,i->when(choices[i]){
   "Pair home server"->pairDialog();"Back up now"->prepareBackup();"Import recovery file"->activity.chooseRecoveryFile();"Restore latest server backup"->download()
   "Enable automatic backups"->dialog=AlertDialog.Builder(activity).setTitle("Enable automatic backups?").setMessage("Send an encrypted snapshot to your paired server after account changes while this app is unlocked. Keep your recovery kit separately.").setPositiveButton("Enable"){_,_->if(updateSetting("auto",true))prepareBackup()}.setNegativeButton("Cancel",null).secureShow()
   "Turn off automatic backups"->updateSetting("auto",false);"Recovery kit status"->recoveryDialog(false)
   "Disconnect server"->mutateSettings {vault.settings.remove("home");vault.settings.put("auto",false)}
   "Disable nearby discovery"->{prefs.edit().putBoolean("discover",false).apply();discovery.stop()}
   "Enable nearby discovery"->{prefs.edit().putBoolean("discover",true).apply();activity.requestDiscovery()}
  }}.setNegativeButton("Done",null).secureShow()
 }
 private fun mutateSettings(change:()->Unit):Boolean {
  val previous=JSONObject(vault.settings.toString())
  change()
  if(saveSettings())return true
  vault.settings.keys().asSequence().toList().forEach {vault.settings.remove(it)}
  previous.keys().forEach {vault.settings.put(it,previous.get(it))}
  return false
 }
 private fun updateSetting(k:String,value:Any):Boolean=mutateSettings {vault.settings.put(k,value)}
 private fun saveSettings():Boolean {
  try {vault.save()}catch(_:Exception){message("Could not save backup settings; unlock again before retrying");return false}
  changed()
  return true
 }
 fun pairCode(code:String){if(!alive())return;try{
  val p=HomeClient.parsePairing(code)
  dialog=AlertDialog.Builder(activity).setTitle("Pair this home server?").setMessage("${p.getString("url")}\n\nOnly continue if this code came from your home server dashboard. The phone verifies the server identity before pairing.")
   .setPositiveButton("Pair"){_,_->pair(p)}.setNegativeButton("Cancel",null).secureShow()
 }catch(_:Exception){message("Invalid pairing code")}}
 private fun pairDialog(){val input=EditText(activity).apply{hint="Paste pairing code from home dashboard";importantForAutofill=android.view.View.IMPORTANT_FOR_AUTOFILL_NO;inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD}
  dialog=AlertDialog.Builder(activity).setTitle("Pair home server").setMessage("On your home computer, choose Pair a phone. Paste its code here, or scan the dashboard pairing QR with Add account → Scan QR.").setView(input).setPositiveButton("Continue"){_,_->val code=input.text.toString();input.text.clear();pairCode(code)}.setNegativeButton("Cancel",null).secureShow()
 }
 private fun pair(p:JSONObject){runJob(work={HomeClient(p).pair(android.os.Build.MODEL)},done={settings->if(mutateSettings {vault.settings.put("home",settings);vault.settings.put("auto",false)})dialog=AlertDialog.Builder(activity).setTitle("Server paired").setMessage("Back up your accounts to this server now?").setPositiveButton("Back up"){_,_->prepareBackup()}.setNegativeButton("Later",null).secureShow()})}
 private fun prepareBackup(){if(!alive())return;if(!vault.settings.has("home")){pairDialog();return}
  if(vault.needsRecoveryExport||!vault.settings.optBoolean("recoveryConfirmed")){recoveryDialog(true);return};upload()
 }
 private fun recoveryDialog(first:Boolean){
  val builder=AlertDialog.Builder(activity).setTitle("Your recovery kit")
  if(vault.needsRecoveryExport){
   builder.setMessage("Save your recovery kit to safe offline storage before backing up. This file restores accounts if your phone is lost. The phone deletes its recovery private key after the file is saved.")
    .setPositiveButton("Save recovery kit"){_,_->activity.exportRecoveryKit {if(first&&alive())prepareBackup()}}
    .setNegativeButton("Cancel",null)
  }else{
   builder.setMessage("Your recovery kit has been exported. Keep that file offline and separate from your backup server. The phone retains only its public encryption key; it cannot recreate your recovery kit.").setPositiveButton("Done",null)
  }
  dialog=builder.secureShow()
 }
 private fun upload(){if(!alive()||busy)return;if(vault.needsRecoveryExport||!vault.settings.optBoolean("recoveryConfirmed")){message("Save your recovery kit before backing up");return};try{val blob=vault.portable();val config=JSONObject(vault.settings.getJSONObject("home").toString());runJob(work={try{HomeClient(config).upload(blob);true}finally{blob.fill(0)}},done={vault.settings.put("lastBackup",System.currentTimeMillis());saveSettings();message("Encrypted backup saved")})}catch(_:Exception){message("Backup could not be prepared")}}
 fun onAccountsChanged(){if(alive()&&vault.settings.optBoolean("auto")&&vault.settings.optBoolean("recoveryConfirmed")&&vault.settings.has("home")){dirty=true;if(!busy){dirty=false;upload()}}}
 private fun download(){if(!alive())return;val config=JSONObject(vault.settings.getJSONObject("home").toString());runJob(work={HomeClient(config).download()},done={restoreDialog(it)})}
 private fun restoreDialog(blob:ByteArray){
  if(blob.size>=4&&String(blob,0,4,Charsets.US_ASCII)=="LAB2"){
   recoveryBlob?.fill(0);recoveryBlob=blob
   val d=AlertDialog.Builder(activity).setTitle("Recover accounts").setMessage("Choose your offline recovery kit. Accounts merge into your fingerprint-protected vault; existing accounts stay.")
    .setPositiveButton("Choose recovery kit"){_,_->activity.chooseRecoveryKit()}
    .setNegativeButton("Cancel"){_,_->recoveryBlob?.fill(0);recoveryBlob=null}.create()
   d.setOnCancelListener {recoveryBlob?.fill(0);recoveryBlob=null};dialog=d;d.secureShow();return
  }
  val input=EditText(activity).apply{hint="Legacy offline recovery key";inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD;importantForAutofill=android.view.View.IMPORTANT_FOR_AUTOFILL_NO}
  val d=AlertDialog.Builder(activity).setTitle("Recover accounts").setMessage("Enter the recovery key saved with this backup. Accounts will merge into your fingerprint-protected vault; existing accounts stay.").setView(input).setPositiveButton("Restore",null).setNegativeButton("Cancel",null).create();dialog=d;d.secureShow();d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener{if(alive())try{val n=vault.restore(blob,input.text.toString());input.text.clear();d.dismiss();changed();if(n>0)onAccountsChanged();message("Recovered $n accounts")}catch(_:Exception){input.error="Key does not match or backup is damaged"}}
  d.setOnDismissListener{input.text.clear();blob.fill(0)}
 }
 fun receiveRecoveryKit(text:String){
  val blob=recoveryBlob?:return;recoveryBlob=null
  try{if(!alive()){message("Unlock before restoring accounts");return};val n=vault.restore(blob,text);changed();if(n>0)onAccountsChanged();message("Recovered $n accounts")}
  catch(_:Exception){message("Recovery kit does not match or backup is damaged")}
  finally{blob.fill(0)}
 }
 fun cancelRecoveryKit(){recoveryBlob?.fill(0);recoveryBlob=null}
 private fun <T> runJob(work:()->T,done:(T)->Unit){if(busy){message("Backup operation already running");return};busy=true;val ticket=epoch
  worker.execute{try{val result=work();main.post{busy=false;if(alive()&&ticket==epoch){done(result)}else if(result is ByteArray)result.fill(0);if(alive()&&dirty)onAccountsChanged()}}catch(e:Exception){main.post{busy=false;if(alive()&&ticket==epoch)message(e.message?.take(160)?:"Server unavailable")}}}
 }
}
