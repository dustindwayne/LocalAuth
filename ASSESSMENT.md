# Comparison and agent security assessment

Assessed October14,2026. LocalAuth4 strengthens its own version3 boundaries but has not earned a claim of being safer overall than established authenticators. Scoped agents and automated tests do not replace device validation or independent review.

## Similar products

| Project | Documented behavior | Comparison |
|---|---|---|
| [Aegis](https://getaegis.app/) | Android encrypted vault, biometric unlock, automatic backup/import/export and actively developed polished UI. | Established alternative. LocalAuth adds integrated account-free Rust home service and experimental per-operation hardware TOTP; this does not prove superior overall safety. |
| [Stratum](https://stratumauth.com/wiki/webdav-backup) | Internet-free app with encrypted automatic WebDAV backups through DAVx5 and configured credentials. | Closest documented home-backup pattern. LocalAuth integrates discovery/pairing/signatures, but intentionally requires Android internet permission for its own server. |
| [Ente offline](https://ente.com/help/auth/features/offline-mode) | Account-free offline use, OS-secure-storage-protected vault and encrypted local exports/backups; app lock protects UI rather than re-encrypting data. | Existing alternative ecosystem. No head-to-head application penetration test was performed. |

Primary project docs describe features, not proof of current complete implementations or absence of bugs. Timing is not a competitive crypto advantage; independent randomness supplies strength.

## Scope

Three agents reviewed Android/server/protocol. Server agents exercised isolated loopback TLS with synthetic keys/accounts, no external targets or real vaults. Android source/SDK behavior was reviewed; physical screenshot and hardware exploitation were not tested. Baseline PoCs apply to version3; current regressions are Rust tests and home-server/tests/https_integration.py.

| Baseline finding | Evidence/impact | Version4 status |
|---|---|---|
| Unsigned challenge exhaustion, medium | Known enrolled ID allocated256 unsigned challenges across sources, blocking another phone temporarily. | Fixed signed bootstrap before allocation, per-device4 cap; live fairness test passes. |
| Revoked capacity exhaustion, medium | Sixteen enrollment/revocation cycles filled original cap. | Revoked excluded from active16; bounded history256 remains a documented lifetime limit without archival UI. |
| Pair lacked possession proof, low | Copied publickey plus fresh trusted ticket returned existing ID; not backup auth bypass. | Signed ticket/pin/publickey/labelhash before offer consumption. |
| Dialog screenshot protection gap | Sensitive dialogs did not inherit activity secure flag; physical capture untested. | Each dialog sets its own secure flag before display. Device check pending. |
| Restore skipped auto-backup trigger | Source path omitted account-change notification. | Fixed source; native network/lifecycle check pending. |
| Settings/save mismatch | Failed pairing/disconnect persistence left changed RAM. | Whole-settings rollback added. Storage-fault device test pending. |
| Unlocked plaintext seeds/symmetric recovery key | Version3 whole-vault decryption exposed all seeds/key to root. | Hardware HMAC + public-recipient capsules; no recovery private key persisted. Import/migration/recovery still transient plaintext. Device check pending. |
| LAB2 minimum422 rejected valid420 empty-array blob | Independent review found envelope overhead418. | Fixed to418, empty tests and Java/Python/live-server interop pass. |

## Material remaining limits

No hardware-attestation/APK-runtime verifier. Deliberately enrolled software identity is copyable; genuine rooted phone can use its non-biometric signing key as an oracle. Signatures do not prove a trustworthy OS/UI.

Root during import/setup/restore can steal seeds/private kits; later it can capture codes/metadata or manipulate authenticated operations. SHA1/SHA512 HMAC availability is device-dependent; fail-closed behavior can prevent accounts/migration. Secure-hardware provenance checks are local and forgeable by a compromised OS.

Backup rollback/deletion, host/provider compromise, heap/flash erasure, durable background retry, orphan-key cleanup, historical archival and internet-scale DoS remain limited or unresolved.

**Decision:** public development preview with explicit limitations, not production-tested/root-proof/certified security. See SECURITY.md and VALIDATION.md.
