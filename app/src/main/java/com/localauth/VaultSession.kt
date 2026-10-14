package com.localauth

/** A fingerprint operation keeps the mode chosen before authentication. */
class VaultSession {
    enum class Mode { CREATE, OPEN }
    private var pending: Mode? = null
    fun begin(existingVault: Boolean): Mode {
        check(pending == null) { "Authentication already pending" }
        return (if (existingVault) Mode.OPEN else Mode.CREATE).also { pending = it }
    }
    fun requireMode(): Mode = checkNotNull(pending) { "No prepared fingerprint operation" }
    fun clear() { pending = null }
}
