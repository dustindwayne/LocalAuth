package com.localauth
import org.junit.Assert.*
import org.junit.Test
class OtpTest {
    @Test fun rfc6238Sha1() {
        val secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        val times = listOf(59L,1111111109L,1111111111L,1234567890L,2000000000L,20000000000L)
        val expected = listOf("94287082","07081804","14050471","89005924","69279037","65353130")
        times.zip(expected).forEach { (time, code) -> assertEquals(code, Otp.code(Account("1","test",secret,digits=8),time)) }
    }
    @Test fun rfc6238Sha256AndSha512() {
        fun base32(bytes: ByteArray): String {
            var v=0; var bits=0; val out=StringBuilder(); val alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            for (b in bytes) { v=(v shl 8) or (b.toInt() and 255); bits+=8; while(bits>=5) {bits-=5;out.append(alphabet[(v shr bits) and 31])};v=v and ((1 shl bits)-1) }
            if(bits>0) out.append(alphabet[(v shl (5-bits)) and 31]); return out.toString()
        }
        val times=listOf(59L,1111111109L,1111111111L,1234567890L,2000000000L,20000000000L)
        val expected256=listOf("46119246","68084774","67062674","91819424","90698825","77737706")
        val expected512=listOf("90693936","25091201","99943326","93441116","38618901","47863826")
        listOf(Triple("SHA256",32,expected256),Triple("SHA512",64,expected512)).forEach { (algorithm,length,codes) ->
            val key=ByteArray(length){"1234567890"[it%10].code.toByte()}
            times.zip(codes).forEach { (t,c) -> assertEquals(c,Otp.code(Account("1","test",base32(key),algorithm,8),t)) }
        }
    }
    @Test fun parseParametersAndEscapes() {
        val a=Otp.parse("otpauth://totp/Example%3Aalice%2Btest?secret=MY======&issuer=Example&algorithm=SHA256&digits=8&period=60")
        assertEquals("Example:alice+test",a.label);assertEquals("SHA256",a.algorithm);assertEquals(8,a.digits);assertEquals(60,a.period)
        assertArrayEquals(byteArrayOf(102),Otp.decode("MY======"))
    }
    @Test fun rejectInvalidInputs() {
        listOf("MZ", "A", "MY=AAAAA", "!@#$", "").forEach { try { Otp.decode(it); fail(it) } catch (_: IllegalArgumentException) {} }
        listOf("otpauth://hotp/test?secret=MY", "otpauth://totp/test?secret=MY&secret=MY", "otpauth://totp/A:b?issuer=B&secret=MY", "otpauth://totp/test?secret=MY&digits=7", "otpauth://totp/test?secret=MY&period=0").forEach { try {Otp.parse(it);fail(it)}catch (_:IllegalArgumentException){} }
    }
    @Test fun periodBoundaryAndLeadingZero() {
        val a=Account("1","test","GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",digits=8)
        assertEquals("07081804",Otp.code(a,1111111109));assertNotEquals(Otp.code(a,59),Otp.code(a,60));assertEquals(8,Otp.code(a,0).length)
    }
}
