package com.localauth

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import java.util.Properties

class PublicBackupTest {
    companion object { private val recipient=PublicBackup.generate() }
    @Test fun encryptsEmptyAndNormalSnapshotsWithRandomness() {
        listOf(byteArrayOf(),"[]".toByteArray(),"test-only account snapshot".toByteArray()).forEach {plain->
            val blob=PublicBackup.encrypt(plain,recipient.first)
            assertArrayEquals(plain,PublicBackup.decrypt(blob,recipient.second))
            assertFalse(blob.contentEquals(PublicBackup.encrypt(plain,recipient.first)))
            assertTrue(PublicBackup.isBackup(blob))
        }
    }
    @Test fun rejectsHeaderWrappedKeyIvPayloadAndTagChanges() {
        val blob=PublicBackup.encrypt("test-only data".toByteArray(),recipient.first)
        listOf(0,4,6,389,390,401,402,blob.lastIndex).forEach {index->
            val changed=blob.clone();changed[index]=(changed[index].toInt() xor 1).toByte()
            try {PublicBackup.decrypt(changed,recipient.second);fail("Accepted altered byte $index")}catch(_:Exception){}
        }
        try {PublicBackup.decrypt(blob,PublicBackup.generate().second);fail("Accepted another recipient")}catch(_:Exception){}
        try {PublicBackup.decrypt(blob.copyOf(417),recipient.second);fail("Accepted truncation")}catch(_:IllegalArgumentException){}
        try {PublicBackup.encrypt(ByteArray(PortableBackup.MAX),recipient.first);fail("Accepted oversize")}catch(_:IllegalArgumentException){}
    }
    @Test fun decryptsIndependentPythonCryptographyFixture() {
        val p=Properties();checkNotNull(javaClass.getResourceAsStream("/public-backup-python.properties")).use {p.load(it)}
        assertArrayEquals(Base64.getDecoder().decode(p.getProperty("plain")),PublicBackup.decrypt(Base64.getDecoder().decode(p.getProperty("blob")),p.getProperty("private")))
        val output=Properties().apply {
            setProperty("private",recipient.second);setProperty("public",recipient.first)
            setProperty("plain",Base64.getEncoder().encodeToString("JCA interop test data".toByteArray()))
            setProperty("blob",Base64.getEncoder().encodeToString(PublicBackup.encrypt("JCA interop test data".toByteArray(),recipient.first)))
        }
        java.io.File("build").mkdirs()
        java.io.File("build/public-backup-jca.properties").outputStream().use {output.store(it,"Synthetic test keys; never use for real accounts")}
    }
}
