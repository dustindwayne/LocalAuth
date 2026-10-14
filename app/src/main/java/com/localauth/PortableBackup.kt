package com.localauth

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

/** Portable encryption is independent from this phone's fingerprint key. */
object PortableBackup {
    const val MAX = 4 * 1024 * 1024
    private val magic = "LAB1".toByteArray(Charsets.US_ASCII)
    private val aad = "LocalAuth portable backup v1".toByteArray(Charsets.UTF_8)
    fun newKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    fun keyText(key: ByteArray): String { require(key.size == 32); return Base64.getUrlEncoder().withoutPadding().encodeToString(key) }
    fun parseKey(text: String): ByteArray = Base64.getUrlDecoder().decode(text.trim()).also { require(it.size == 32) { "Recovery key must be 43 characters" } }
    fun encrypt(plain: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 32 && plain.size <= MAX - 32)
        val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"));cipher.updateAAD(aad)
        return magic+cipher.iv+cipher.doFinal(plain)
    }
    fun decrypt(blob: ByteArray,key: ByteArray): ByteArray {
        require(key.size==32 && blob.size in 33..MAX && blob.copyOfRange(0,4).contentEquals(magic)) { "Invalid backup file" }
        val cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,blob.copyOfRange(4,16)));cipher.updateAAD(aad)
        return cipher.doFinal(blob.copyOfRange(16,blob.size))
    }
    fun hash(body:ByteArray):String=MessageDigest.getInstance("SHA-256").digest(body).joinToString(""){"%02x".format(it.toInt() and 255)}
    fun request(device:String,nonce:String,method:String,path:String,body:ByteArray):ByteArray = "LocalAuth request v2\n$device\n$nonce\n$method\n$path\n${hash(body)}".toByteArray(Charsets.UTF_8)
}
