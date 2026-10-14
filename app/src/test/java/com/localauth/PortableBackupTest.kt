package com.localauth
import org.junit.Assert.*
import org.junit.Test
class PortableBackupTest {
 @Test fun restoreAndRejectTamperingOrWrongKey() {
  val key=PortableBackup.newKey();val plain="private accounts".toByteArray();val a=PortableBackup.encrypt(plain,key);val b=PortableBackup.encrypt(plain,key)
  assertFalse(a.contentEquals(b));assertArrayEquals(plain,PortableBackup.decrypt(a,key))
  try {PortableBackup.decrypt(a,PortableBackup.newKey());fail()}catch(_:javax.crypto.AEADBadTagException){}
  a[a.lastIndex]=(a.last().toInt() xor 1).toByte();try {PortableBackup.decrypt(a,key);fail()}catch(_:javax.crypto.AEADBadTagException){}
  assertArrayEquals(key,PortableBackup.parseKey(PortableBackup.keyText(key)))
 }
 @Test fun handshakeCanonicalFormatAndPayloadHash() {
  assertEquals("LocalAuth request v2\ndevice\nnonce\nPOST\n/v1/backup\n2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",String(PortableBackup.request("device","nonce","POST","/v1/backup","hello".toByteArray())))
 }
 @Test fun plaintextAndOversizedInputsRejected() {
  listOf(byteArrayOf(),ByteArray(32),ByteArray(PortableBackup.MAX+1)).forEach {try{PortableBackup.decrypt(it,PortableBackup.newKey());fail()}catch(_:IllegalArgumentException){}}
 }
}
