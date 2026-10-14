package com.localauth
import org.junit.Assert.*
import org.junit.Test
class VaultKeyTest {
 @Test fun identicalTimingStillProducesDifferentKeys() {
  val keys = List(100) { VaultKey.generate(100, 200, 300) }
  assertTrue(keys.all { it.size == 32 })
  assertEquals(100, keys.map { it.toList() }.toSet().size)
 }
 @Test(expected=IllegalArgumentException::class) fun rejectsReversedTiming() { VaultKey.generate(200,100,300) }
}
