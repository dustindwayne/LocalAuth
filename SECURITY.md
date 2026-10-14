# Security model — LocalAuth 4.0 preview

## Intended protection

The design protects application-file copying and normal post-enrollment heap exposure, assuming Android secure hardware and biometric enforcement remain trustworthy. Root is permitted; no root blacklist is used. Rooted runtime malware, hardware exploits and compromise during import/recovery are not universally defeated.

Each account uses a non-exportable hardware HMAC key. KeyInfo must report TEE/StrongBox, hardware-enforced user authentication and a per-operation policy; API30+ must report strong biometric only. FingerprintManager carries the actual Mac, and the returned object must match before code generation. SHA256 StrongBox import is attempted on API31+, with fallback only for explicit StrongBox-unavailable errors to a checked TEE key. SHA1/SHA512 require compatible TEE hardware. Unsupported keys fail closed.

FingerprintManager is used for a fingerprint-only UI. Hardware policy describes strong biometrics, not a universal distinction between fingerprint and other strong modalities. A compromised OS can falsify app-visible checks. No remote Android attestation verifier is implemented. Native behavior remains untested on a phone.

Normal unlocked records contain labels/parameters, hardware aliases, SHA256 seed fingerprints for deduplication, and encrypted capsules. The metadata key cannot decrypt capsules or export hardware keys. Weak/non-random user seeds remain susceptible to guessing via fingerprints. Root can observe labels/codes or manipulate genuine authenticated operations; trusted display is not provided.

## Public-key backups

RSA3072 recovery recipients are generated transiently during setup. Private PKCS8 material is exported as an offline kit JSON and never serialized in the app vault. Locking/canceling setup discards the pending pair; next unlock generates another. File write success is followed by another fingerprint-authorized wrapping operation, metadata-key rotation and transactional persistence of only the public recipient. Accounts/codes/backups are blocked until completion.

Each seed is sealed into a capsule during trusted import. Normal backups encrypt arrays of opaque capsules without decrypting seeds. A replacement-phone restore briefly uses the old kit, imports new hardware keys, and seals accounts under its own new recipient. Neither normal phone operation nor server storage holds the private recovery key.

LAB2: magic4 + big-endian length2 (384) + RSA-wrapped AES key384 + IV12 + GCM ciphertext/tag16. RSA-OAEP uses SHA256 and MGF1-SHA256. AES256-GCM authenticates the entire402-byte header; IV12 and AES key32 are fresh random values. Minimum envelope418; max4MiB. Independent Java/Python interoperability passed. This uses standard primitives but has no independent full construction audit and is not HPKE.

**Saving the kit on this same phone or a compromised provider defeats backup separation.** Android's file picker can select local/cloud storage; the app cannot guarantee an offline destination. Keep the kit off-phone and separate from the server. The phone cannot recreate it after completion. Losing kit and phone can make accounts irrecoverable.

QR/manual import, setup, legacy migration and recovery necessarily handle plaintext/private keys in ordinary memory. Kotlin/Java Strings, JSON, provider RSA objects, QR and keyboard buffers cannot be reliably erased. Mutable buffers are cleared where practical. Root during these operations can capture secrets and undermine later protection. No complete heap-erasure guarantee is made.

## Migration and storage

Old v2/v3 encrypted vaults stay on disk until kit export and all hardware imports succeed. Failed saves restore account/settings/key state and delete newly imported keys. A crash between import and persistence may leave an orphan hardware alias; cleanup is not implemented. Migration decrypts legacy seeds; metadata-key rotation prevents the new normal heap key from directly decrypting old payloads, but physical secure erasure of old flash/ciphertext is not guaranteed. A compromised OS controlling future genuine authentication can manipulate wrapping operations. Prior exposure cannot be undone.

Legacy v1 preferences are refused rather than silently overwritten. Hardware payloads cannot be read by older APKs. Never downgrade/uninstall without tested recovery. LAB1 backups remain importable with their original43-character keys; new backups use LAB2. Legacy symmetric recovery keys are removed from new saved settings.

AtomicFile/redb protect against interrupted writes, not malicious rollback. Authorized malicious phones/servers can return or reupload older valid encrypted snapshots, delete backups or replace metadata. Cryptographic freshness/append-only transparency are not implemented.

## Device/server authentication

The Android P256 signing key is hardware-backed/non-exportable but does not require biometric per network signature. Root on the genuine phone can use it as an oracle. Vault/HMAC biometric access is separate; jobs send ciphertext only.

The server proves possession of the enrolled key, not APK/runtime integrity or hardware provenance. It has no Android/OEM/Google attestation-chain/revocation verifier. A modified client with an administrator-approved offer can intentionally enroll an exportable software key. Copying files/IDs/public keys of a genuine hardware identity does not supply its private key, but absolute anti-cloning and compromised-device detection are not claimed.

TLS pins the exact certificate from the trusted pairing offer. One-use offers expire after5minutes and signed proof binds pin/ticket/publickey/labelhash. Signed bootstrap binds pin/device/clientnonce/canonical timestamp, +/-60s freshness and120s replay retention. Each device gets4 pending challenges and128 accepted bootstrap nonces. Invalid proofs allocate no challenge/replay state. Backup signatures bind exact method/path/device/challenge/body and consume valid challenges. See [wire contract](home-server/PROTOCOL.md).

## Server limits

Backup TLS is LAN-filtered by source address by default; --remote permits public sources. NAT/proxies can defeat LAN interpretation, so firewall/router rules remain the user's responsibility. Admin HTTP stays on IPv4 loopback with a random process capability, privileged-route Host checks, CSP and no third-party scripts/CORS. Never expose the admin port.

120requests/min/source-IP, bounded maps/bodies/timeouts are basic abuse controls, not internet-scale DoS protection. Shared-NAT clients share quota. Host/admin compromise exposes TLS/enrollment metadata and permits data deletion/rollback. Device labels/timestamps/publickeys are plaintext server metadata; account labels remain inside encrypted payloads.

Sixteen active devices; revoked records do not consume active slots. History is capped at256 identities without archival UI. Ten4MiB snapshots each can retain roughly10GiB plus DB overhead. Windows relies on inherited NTFS ACLs; Unix restricts data-directory/TLS-key modes. Allocated DB files can exceed live ciphertext.

No public endpoint, firewall/router/DNS rule or service installation was created. Windowsx64 is locally tested. Linux/macOS/ARM, IPv6, VPNs, reverse-proxy TLS and remote routing remain unverified. TLS-terminating proxies change the pin and need deliberate configuration/re-pairing; never disable verification.

## Validation boundary

No physical phone/emulator tests were possible. Hardware import/authentication, enrollment invalidation, file providers, Android17, screenshots, camera and UI require [device validation](VALIDATION.md). This is a development preview, not a security certification. Dependency lockfiles are included; a full independent vulnerability audit is absent.

[Android Keystore documentation](https://developer.android.com/privacy-and-security/keystore) describes hardware enforcement and its limits. StrongBox guarantees HMAC-SHA256, not universal SHA1/SHA512. Plaintext QR import cannot be hidden from root; protection begins after trusted enrollment.
