package com.localauth

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec

/** Runtime TOTP uses a nonexportable, hardware-enforced, biometric-per-operation key. */
object HardwareOtp {
    private fun store()=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
    private fun checked(key:SecretKey,algorithm:String):SecretKey {
        val info=SecretKeyFactory.getInstance("Hmac$algorithm","AndroidKeyStore").getKeySpec(key,KeyInfo::class.java) as KeyInfo
        @Suppress("DEPRECATION")
        val hardware=if(Build.VERSION.SDK_INT>=31) info.securityLevel in setOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,KeyProperties.SECURITY_LEVEL_STRONGBOX) else info.isInsideSecureHardware
        check(hardware && info.isUserAuthenticationRequired && info.isUserAuthenticationRequirementEnforcedBySecureHardware && info.userAuthenticationValidityDurationSeconds<=0){"This device cannot protect this account with hardware biometric TOTP"}
        if(Build.VERSION.SDK_INT>=30)check(info.userAuthenticationType==KeyProperties.AUTH_BIOMETRIC_STRONG){"Strong biometric required for this account"}
        check(key.encoded==null){"Exportable TOTP key rejected"}
        return key
    }
    fun import(seed:ByteArray,algorithm:String):String {
        val alias="localauth.otp.v1.${UUID.randomUUID()}"
        val ks=store()
        fun insert(strong:Boolean){
            val digest=when(algorithm){"SHA1"->KeyProperties.DIGEST_SHA1;"SHA256"->KeyProperties.DIGEST_SHA256;"SHA512"->KeyProperties.DIGEST_SHA512;else->error("Unsupported TOTP algorithm")}
            val protection=KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).setDigests(digest)
                .setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true)
            if(Build.VERSION.SDK_INT>=30)protection.setUserAuthenticationParameters(0,KeyProperties.AUTH_BIOMETRIC_STRONG)
            else @Suppress("DEPRECATION") protection.setUserAuthenticationValidityDurationSeconds(-1)
            if(Build.VERSION.SDK_INT>=31)protection.setIsStrongBoxBacked(strong)
            else check(!strong)
            ks.setEntry(alias,KeyStore.SecretKeyEntry(SecretKeySpec(seed,"Hmac$algorithm")),protection.build())
        }
        try {
            // StrongBox guarantees HMAC-SHA256; SHA1/SHA512 require the device TEE.
            if(algorithm=="SHA256"&&Build.VERSION.SDK_INT>=31)try{insert(true)}catch(_:android.security.keystore.StrongBoxUnavailableException){ks.deleteEntry(alias);insert(false)} else insert(false)
            checked(ks.getKey(alias,null) as SecretKey,algorithm)
            return alias
        }catch(e:Exception){ks.deleteEntry(alias);throw e}
    }
    fun prepare(account:Account):Mac {
        require(account.secret.isEmpty() && account.hardwareAlias.isNotEmpty())
        val key=checked(store().getKey(account.hardwareAlias,null) as? SecretKey ?: error("Account hardware key unavailable; restore your encrypted backup"),account.algorithm)
        return Mac.getInstance("Hmac${account.algorithm}").apply{init(key)}
    }
    fun complete(account:Account,mac:Mac,seconds:Long=System.currentTimeMillis()/1000):String=Otp.complete(account,mac,seconds)
    fun delete(alias:String){if(alias.startsWith("localauth.otp.v1."))store().deleteEntry(alias)}
}
