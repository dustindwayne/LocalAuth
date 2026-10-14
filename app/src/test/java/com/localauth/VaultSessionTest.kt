package com.localauth
import org.junit.Assert.*
import org.junit.Test
class VaultSessionTest {
 @Test fun freshInstallPreparesCreation() { val s=VaultSession(); assertEquals(VaultSession.Mode.CREATE,s.begin(false)); assertEquals(VaultSession.Mode.CREATE,s.requireMode()) }
 @Test fun existingVaultPreparesDecryption() { val s=VaultSession(); assertEquals(VaultSession.Mode.OPEN,s.begin(true)); assertEquals(VaultSession.Mode.OPEN,s.requireMode()) }
 @Test fun cancelledSetupCanRetryAsCreation() { val s=VaultSession(); s.begin(false);s.clear();assertEquals(VaultSession.Mode.CREATE,s.begin(false)) }
 @Test(expected=IllegalStateException::class) fun cannotUnlockWithoutPreparation() { VaultSession().requireMode() }
 @Test(expected=IllegalStateException::class) fun cannotSwitchModeMidAuthentication() { val s=VaultSession();s.begin(false);s.begin(true) }
}
