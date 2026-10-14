package com.localauth

import java.net.URI
import java.net.URLDecoder
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class Account(val id: String, val label: String, val secret: String, val algorithm: String = "SHA1", val digits: Int = 6, val period: Int = 30,
    val hardwareAlias: String = "", val seedCapsule: String = "", val seedFingerprint: String = "")
object Otp {
    fun decode(input: String): ByteArray {
        val text = input.uppercase(Locale.ROOT).filterNot { it.isWhitespace() || it == '-' }
        require(text.length <= 4096) { "Secret too long" }
        val raw = text.trimEnd('=')
        require('=' !in raw && raw.length % 8 in setOf(0, 2, 4, 5, 7)) { "Invalid Base32 length" }
        if (text.length != raw.length) require(text.length % 8 == 0 && text.length - raw.length == (8 - raw.length % 8) % 8)
        var bits = 0; var value = 0
        val out = ArrayList<Byte>()
        raw.forEach { ch ->
            val digit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch)
            require(digit >= 0) { "Invalid Base32 character" }
            value = (value shl 5) or digit; bits += 5
            if (bits >= 8) { bits -= 8; out.add((value shr bits).toByte()); value = value and ((1 shl bits) - 1) }
        }
        require(value == 0 && out.isNotEmpty()) { "Invalid Base32 trailing bits" }
        return out.toByteArray()
    }
    fun validate(a: Account): Account {
        require(a.label.isNotBlank() && a.label.length <= 200) { "Enter an account name (up to 200 characters)" }
        require(a.algorithm in setOf("SHA1", "SHA256", "SHA512") && a.digits in setOf(6, 8) && a.period in 1..300) { "Unsupported TOTP parameters" }
        if (a.hardwareAlias.isEmpty()) decode(a.secret).fill(0)
        else require(a.secret.isEmpty() && a.hardwareAlias.matches(Regex("localauth\\.otp\\.v1\\.[a-f0-9-]{36}")) && a.seedCapsule.length in 1..20000 && a.seedFingerprint.matches(Regex("[a-f0-9]{64}"))) { "Invalid hardware account" }
        return a
    }
    fun parse(text: String): Account {
        require(text.length <= 8192) { "QR too large" }
        val uri = URI(text.trim())
        require(uri.scheme == "otpauth" && uri.rawAuthority == "totp" && uri.fragment == null) { "Only otpauth TOTP QR codes are supported" }
        fun decode(s: String) = URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")
        val params = linkedMapOf<String, String>()
        uri.rawQuery.orEmpty().split('&').forEach {
            val p = it.split('=', limit = 2)
            require(p.size == 2) { "Malformed TOTP URI" }
            val k = decode(p[0]); require(!params.containsKey(k)) { "Duplicate URI parameter" }; params[k] = decode(p[1])
        }
        require(params.keys.all { it in setOf("secret", "issuer", "algorithm", "digits", "period") }) { "Unsupported URI parameter" }
        val label = decode(uri.rawPath.orEmpty().removePrefix("/"))
        val issuer = params["issuer"].orEmpty()
        if (':' in label && issuer.isNotBlank()) require(label.substringBefore(':') == issuer) { "Issuer mismatch" }
        return validate(Account(java.util.UUID.randomUUID().toString(), if (':' !in label && issuer.isNotBlank()) "$issuer:$label" else label,
            params["secret"] ?: error("Missing secret"), params["algorithm"]?.uppercase(Locale.ROOT) ?: "SHA1",
            params["digits"]?.toInt() ?: 6, params["period"]?.toInt() ?: 30))
    }
    fun code(a: Account, seconds: Long = System.currentTimeMillis() / 1000): String {
        require(a.hardwareAlias.isEmpty()) { "Hardware accounts require fingerprint-authorized code generation" }
        require(seconds >= 0)
        val secret = decode(a.secret)
        try {
            val mac = Mac.getInstance("Hmac${a.algorithm}"); mac.init(SecretKeySpec(secret, "Hmac${a.algorithm}"))
            return complete(a,mac,seconds)
        } finally { secret.fill(0) }
    }
    fun complete(a:Account,mac:Mac,seconds:Long):String {
        require(seconds>=0)
        val counter=seconds/a.period
        val hash=mac.doFinal(ByteArray(8){(counter ushr ((7-it)*8)).toByte()})
        return try {
            val o=hash.last().toInt() and 15
            val number=((hash[o].toInt() and 127) shl 24) or ((hash[o+1].toInt() and 255) shl 16) or ((hash[o+2].toInt() and 255) shl 8) or (hash[o+3].toInt() and 255)
            (number % if(a.digits==8)100000000 else 1000000).toString().padStart(a.digits,'0')
        }finally{hash.fill(0)}
    }
}
