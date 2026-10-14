# LocalAuth 4.0 validation — October 14, 2026

## Completed locally

- Debug and unsigned release APK builds successful.19 JVM tests, no errors/failures: RFC6238 algorithm vectors, QR/URI/Base32 rejection, setup state, random timing-supplemented keys, legacy GCM handling, protocol2 canonical messages, LAB2 randomness/roundtrip/size/tamper/wrong-key handling.
- Empty bytes and two-byte empty-array LAB2 roundtrips cover the independently found envelope-length bug. Mutation checks cover magic/length/wrappedkey/IV/payload/tag/truncation.
- Independent interoperability both ways: JCA decrypts Python cryptography fixture, Python decrypts JCA synthetic envelope. Explicit OAEP SHA256/MGF1-SHA256 and complete-header GCM match.
- Android lint0errors/10warnings. StrongBox import API31 guard corrected an initial compatibility error. Remaining target/library/orientation/English-string recommendations and fingerprint deprecation are documented.
- Debug APK v2 signature verified. Manifest inspected: camera, biometric/fingerprint, optional-backup INTERNET/local-network and AndroidX app-local signature permission. Release APK unsigned; production secrets absent.
- Rust13tests, all-target clippy -D warnings, release Windowsx64 build passed. Signed pair/bootstrap, invalid allocation/replay rejection, fair device limits, revocation/history capacity, persistence/retention and LAB1/LAB2 covered.
- Live native loopback TLS regression passed: unsigned/wrong-key/copied proof rejection, protocol2 marker, bootstrap/body/replay binding, per-device fairness, encrypted LAB1/LAB2 upload/download/decrypt (including420-byte empty array), admin Host/capability checks, revocation/retained recovery.
- Three agents reviewed baseline Android/server/protocol; two reviewed revised recovery/server paths. These are scoped reviews/regressions, not third-party security certification. Findings in [ASSESSMENT.md](ASSESSMENT.md).
- The unchanged navy/mint dashboard was visually checked for version3; temporary preview stopped. New Android recovery/hardware flows were not visually tested on a phone.

Toolchain: Windowsx64, SDK35/buildtools35, AGP8.9.2, Kotlin2.1.20, Gradle8.13, Corretto23/Java17bytecode, Rust1.94.1. Cargo.lock included. Private test fixtures are synthetic.

## Required phone checks — not completed

ADB daemon failed to start; no usable device/emulator testing was available. JVM tests do not prove Android Keystore behavior.

1. Fresh setup/unlock/retry/cancel/lockout/background/rotation; actual AES hardware/auth enforcement; confirm user's Android17 setup error is resolved.
2. Offline kit chooser cancel/write failure/background/process death/return/reunlock/final fingerprint. Check kit matches backup and private key is absent from persisted app storage. Keep destination off-phone. Failed migration must preserve original disk vault.
3. Disposable SHA1/SHA256/SHA512 seeds and lengths. Inspect HMAC KeyInfo/non-exportability; reject unsupported hardware. Compare hardware codes against RFC6238. Mac must fail before auth, after cancel and after operation consumption.
4. Period expiration/cached copies/clipboard/locking; no normal post-setup seeds in account records. Screenshot/recording blocked on every dialog's own secure window.
5. Enrollment invalidation/reboot/replacement-phone restore/wrong kit/tamper/duplicates/v2-v3 conversion/failure rollback.
6. Actual camera/gallery bounds, manual keyboards/autofill, permissions/layout/animations. Compromised providers/keyboard can expose import secrets.
7. Real Wi-Fi mDNS/local-network permission; declined pairing/backup; QR expiry/pin mismatch/protocol1 refusal/clock skew/offline/slow network/auto backup after restore/process death. No durable retry claimed.
8. Copied genuine hardware identity must fail without its key; modified intentionally enrolled software identity is not rejected by attestation (absent). Revocation must retain local admin recovery.

## Not claimed

Production readiness, root-proof secrecy, universal compromised-device detection, server-side Android attestation/revocation, cryptographic backup freshness, secure flash/heap erasure, internet-scale DoS resistance, durable background retry or independent full crypto/dependency audit.

Linux/macOS/ARM, remote routers/firewalls/DNS/VPN/IPv6/TLS proxies/services were not tested locally or configured. No real accounts were used.
