package com.localauth

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/** Timing is supplementary context, never the source of key strength. */
object VaultKey {
    fun generate(promptNanos: Long, matchNanos: Long, wallMillis: Long): ByteArray {
        require(matchNanos >= promptNanos)
        val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val timing = ByteBuffer.allocate(24).putLong(promptNanos).putLong(matchNanos).putLong(wallMillis).array()
        return try {
            MessageDigest.getInstance("SHA-256").apply {
                update("LocalAuth vault key v1".toByteArray(Charsets.UTF_8))
                update(random); update(timing)
            }.digest()
        } finally { random.fill(0); timing.fill(0) }
    }
}
