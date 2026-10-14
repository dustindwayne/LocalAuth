package com.localauth

import android.os.Build
import android.security.keystore.*
import org.json.JSONObject
import java.net.URI
import java.net.URL
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import javax.net.ssl.*

class HomeClient(private val pairing:JSONObject) {
    private val base=pairing.getString("url").trimEnd('/')
    private val pin=pairing.getString("pin")
    init { validateEndpoint(base,pin) }
    companion object {
        private const val ALIAS="localauth.device.signing.v1"
        fun validateEndpoint(url:String,pin:String) {
            val uri=URI(url);require(uri.scheme=="https"&&uri.host!=null&&uri.userInfo==null&&uri.query==null&&uri.fragment==null&&uri.path.orEmpty() in listOf("","/")) { "Pairing requires a direct HTTPS server address" }
            require(pin.matches(Regex("[a-f0-9]{64}"))) { "Invalid server identity" }
        }
        fun parsePairing(code:String):JSONObject {
            require(code.length<=4096&&code.startsWith("localauth-pair:")) { "Invalid pairing code" }
            val json=JSONObject(String(Base64.getUrlDecoder().decode(code.removePrefix("localauth-pair:")),Charsets.UTF_8))
            require(json.getInt("v")==2) { "Update the home server before pairing" };validateEndpoint(json.getString("url"),json.getString("pin"))
            require(json.getString("ticket").matches(Regex("[A-Za-z0-9_-]{43}")))
            return json
        }
        private fun keys():KeyStore=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        private fun ensureIdentity():KeyStore {
            val ks=keys()
            if(!ks.containsAlias(ALIAS)) {
                fun create(strongBox:Boolean) {
                    val spec=KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_SIGN).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false)
                    if(strongBox) spec.setIsStrongBoxBacked(true)
                    KeyPairGenerator.getInstance("EC","AndroidKeyStore").apply {initialize(spec.build())}.generateKeyPair()
                }
                try {create(true)} catch (_:StrongBoxUnavailableException) {create(false)}
            }
            val private=ks.getKey(ALIAS,null) as PrivateKey
            val info=KeyFactory.getInstance(private.algorithm,"AndroidKeyStore").getKeySpec(private,KeyInfo::class.java)
            @Suppress("DEPRECATION")
            require(info.isInsideSecureHardware) { "Hardware-backed device identity is required on this phone" }
            return ks
        }
        fun publicIdentity():String=Base64.getUrlEncoder().withoutPadding().encodeToString(ensureIdentity().getCertificate(ALIAS).publicKey.encoded)
        private fun sign(body:ByteArray):String {
            val key=ensureIdentity().getKey(ALIAS,null) as PrivateKey
            val signature=Signature.getInstance("SHA256withECDSA");signature.initSign(key);signature.update(body)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign())
        }
    }
    private fun request(method:String,path:String,body:ByteArray=byteArrayOf(),headers:Map<String,String> = emptyMap()):ByteArray {
        val expected=URI(base)
        val connection=URL(base+path).openConnection() as HttpsURLConnection
        val trust=object:X509TrustManager {
            override fun getAcceptedIssuers():Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain:Array<X509Certificate>,auth:String) {throw java.security.cert.CertificateException("Client certificates unsupported")}
            override fun checkServerTrusted(chain:Array<X509Certificate>,auth:String) {
                if(chain.isEmpty()||PortableBackup.hash(chain[0].encoded)!=pin) throw java.security.cert.CertificateException("Server identity changed; re-pair locally")
                chain[0].checkValidity()
            }
        }
        val ssl=SSLContext.getInstance("TLS").apply {init(null,arrayOf(trust),SecureRandom())}
        connection.sslSocketFactory=ssl.socketFactory
        // Pairing authenticates the exact certificate independently of public PKI or DNS names.
        connection.hostnameVerifier=HostnameVerifier {host, session -> host==expected.host && session.peerCertificates.firstOrNull()?.let {PortableBackup.hash(it.encoded)==pin}==true }
        connection.instanceFollowRedirects=false;connection.connectTimeout=8000;connection.readTimeout=12000;connection.requestMethod=method
        connection.setRequestProperty("Content-Type",if(path=="/v1/pair") "application/json" else "application/octet-stream")
        headers.forEach { (k,v)->connection.setRequestProperty(k,v) }
        val started=System.nanoTime()
        try {
            if(method=="POST") {connection.doOutput=true;connection.setFixedLengthStreamingMode(body.size);connection.outputStream.use {it.write(body)}}
            val status=connection.responseCode
            check(status in 200..299) { when(status){401->"Device not authorized; pair again from the home dashboard";404->"No backup available";429->"Server busy; try again shortly";else->"Backup server returned $status"} }
            return connection.inputStream.use { input -> val out=java.io.ByteArrayOutputStream();val buffer=ByteArray(8192);while(true){check(System.nanoTime()-started<=java.util.concurrent.TimeUnit.SECONDS.toNanos(30)){"Backup request timed out"};val n=input.read(buffer);if(n<0)break;require(out.size()+n<=PortableBackup.MAX);out.write(buffer,0,n)};out.toByteArray() }
        } finally {connection.disconnect()}
    }
    fun pair(label:String):JSONObject {
        val publicKey=publicIdentity();val name=label.take(80);val ticket=pairing.getString("ticket")
        val canonical="LocalAuth pair v2\n$pin\n$ticket\n$publicKey\n${PortableBackup.hash(name.toByteArray(Charsets.UTF_8))}".toByteArray(Charsets.UTF_8)
        val body=JSONObject().put("ticket",ticket).put("public_key",publicKey).put("label",name).put("proof",sign(canonical)).toString().toByteArray(Charsets.UTF_8)
        val result=JSONObject(String(request("POST","/v1/pair",body),Charsets.UTF_8))
        val id=result.getString("device");require(id.matches(Regex("[A-Za-z0-9_-]{43}")))
        return JSONObject().put("url",base).put("pin",pin).put("device",id)
    }
    private fun authenticated(method:String,body:ByteArray):ByteArray {
        val id=pairing.getString("device")
        val clientNonce=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also {SecureRandom().nextBytes(it)})
        val clientTime=System.currentTimeMillis().toString()
        val acquisition=sign("LocalAuth challenge v2\n$pin\n$id\n$clientNonce\n$clientTime".toByteArray(Charsets.UTF_8))
        val response=JSONObject(String(request("GET","/v1/challenge/$id",headers=mapOf("X-Client-Nonce" to clientNonce,"X-Client-Time" to clientTime,"X-Signature" to acquisition)),Charsets.UTF_8))
        require(response.getInt("protocol")==2) { "Update the home server before backing up" }
        val challenge=response.getString("challenge")
        require(challenge.matches(Regex("[A-Za-z0-9_-]{43}")))
        val signature=sign(PortableBackup.request(id,challenge,method,"/v1/backup",body))
        return request(method,"/v1/backup",body,mapOf("X-Device" to id,"X-Challenge" to challenge,"X-Signature" to signature))
    }
    fun upload(blob:ByteArray){authenticated("POST",blob)}
    fun download():ByteArray=authenticated("GET",byteArrayOf())
}
