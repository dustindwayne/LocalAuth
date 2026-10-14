package com.localauth

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

/** Standard RSA-OAEP-SHA256 key transport with AES-256-GCM payload encryption.
 * Only the public recipient key is retained during normal phone operation. */
object PublicBackup {
    private val magic = "LAB2".toByteArray(Charsets.US_ASCII)
    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
    fun generate(): Pair<String,String> {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(3072, SecureRandom()) }.generateKeyPair()
        return Base64.getEncoder().encodeToString(pair.public.encoded) to Base64.getEncoder().encodeToString(pair.private.encoded)
    }
    private fun keyBytes(text:String):ByteArray {
        require(text.length in 100..12000) { "Invalid recovery key" }
        return Base64.getDecoder().decode(text)
    }
    private fun publicKey(text:String) = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes(text))).also {
        require((it as RSAKey).modulus.bitLength()==3072) { "Unsupported recovery key" }
    }
    private fun privateKey(text:String) = keyBytes(text).let { bytes ->
        try { KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(bytes)).also {
            require((it as RSAKey).modulus.bitLength()==3072) { "Unsupported recovery key" }
        } } finally { bytes.fill(0) }
    }
    fun isBackup(blob:ByteArray)=blob.size>=4 && blob.copyOfRange(0,4).contentEquals(magic)
    fun encrypt(plain:ByteArray,publicText:String):ByteArray {
        require(plain.size<=PortableBackup.MAX-418) { "Backup too large" }
        val key=ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            val rsa=Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.ENCRYPT_MODE,publicKey(publicText),oaep) }
            val wrapped=rsa.doFinal(key)
            require(wrapped.size==384)
            val iv=ByteArray(12).also {SecureRandom().nextBytes(it)}
            val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,iv)) }
            val header=magic+ByteBuffer.allocate(2).putShort(wrapped.size.toShort()).array()+wrapped+cipher.iv
            cipher.updateAAD(header)
            return header+cipher.doFinal(plain)
        } finally { key.fill(0) }
    }
    fun decrypt(blob:ByteArray,privateText:String):ByteArray {
        require(blob.size in 418..PortableBackup.MAX && isBackup(blob)) { "Invalid public-key backup" }
        val length=ByteBuffer.wrap(blob,4,2).short.toInt() and 65535
        require(length==384)
        val headerSize=6+length+12
        val rsa=Cipher.getInstance("RSA/ECB/OAEPPadding").apply { init(Cipher.DECRYPT_MODE,privateKey(privateText),oaep) }
        val key=rsa.doFinal(blob.copyOfRange(6,6+length))
        try {
            require(key.size==32)
            val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,blob.copyOfRange(6+length,headerSize)))
                updateAAD(blob.copyOfRange(0,headerSize))
            }
            return cipher.doFinal(blob.copyOfRange(headerSize,blob.size))
        } finally { key.fill(0) }
    }
    fun seal(a:Account,publicText:String):String {
        val plain=JSONObject().put("label",a.label).put("secret",a.secret).put("algorithm",a.algorithm).put("digits",a.digits).put("period",a.period).toString().toByteArray(Charsets.UTF_8)
        return try { Base64.getEncoder().encodeToString(encrypt(plain,publicText)) } finally { plain.fill(0) }
    }
    fun open(capsule:String,privateText:String):Account {
        require(capsule.length<=20000)
        val plain=decrypt(Base64.getDecoder().decode(capsule),privateText)
        try {
            val a=JSONObject(String(plain,Charsets.UTF_8))
            return Otp.validate(Account(java.util.UUID.randomUUID().toString(),a.getString("label"),a.getString("secret"),a.getString("algorithm"),a.getInt("digits"),a.getInt("period")))
        } finally { plain.fill(0) }
    }
    fun recoveryPrivate(kit:String):String {
        require(kit.length<=16000)
        val json=JSONObject(kit)
        require(json.getString("format")=="LocalAuth recovery v2")
        val text=json.getString("private_key")
        privateKey(text)
        return text
    }
}
