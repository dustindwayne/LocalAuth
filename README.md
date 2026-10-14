# LocalAuth

![LocalAuth — home, fingerprint and L emblem](assets/branding/readme-header.png)

A fingerprint-first Android TOTP authenticator with your own Rust home backup server. No service accounts, subscriptions, telemetry or cloud integration. Android and the localhost dashboard share navy surfaces, mint accents, rounded cards and restrained animations.

**Version 4.0 is a development preview. Builds and automated tests pass, but native hardware HMAC, fingerprint and recovery flows have not been tested on a real phone. Use disposable accounts until the device checklist passes. Root-proof security and detection of every compromised device are not claimed.**

## Stronger protection

- Each TOTP seed is imported as a non-exportable Android Keystore HMAC key. Hardware must enforce biometric authorization for every operation. Unsupported hardware/algorithms are rejected; stored accounts never fall back to software TOTP.
- Tap an account and scan your fingerprint to generate/copy its code. A revealed code can be copied during the same period. Expiration hides it; a new code requires another scan. Vault sign-in also requires fingerprint, with no PIN/password fallback.
- Normal unlocked records contain metadata, a hardware alias and an encrypted recovery capsule, not plaintext seeds. QR/manual import, migration and restore briefly handle plaintext; root can still capture these operations or displayed codes.
- Backups use a public recipient key. Its private key is generated transiently during setup, exported to an offline recovery kit and never serialized into the vault. After setup only the public key remains on the phone. Keep the kit off the phone and separate from the server.
- Labels/settings are encrypted locally with AES-256-GCM. The wrapping key must be hardware-backed with hardware-enforced biometric access. Recovery setup rotates the metadata key after a final fingerprint scan.
- Signed pairing proves key possession. Challenge acquisition is signed, fresh and unreplayed before allocating server state. Per-device limits prevent one phone from consuming another's challenge quota.

## Features

Camera/gallery QR import, manual Base32/otpauth entry, offline SHA1/SHA256/SHA512 TOTP where supported by hardware, 6/8 digits, sensitive clipboard marking/clearing, automatic locking, secure dialogs, nearby-server discovery, pinned HTTPS pairing, explicit backup consent and encrypted recovery import.

The Rust server provides native TLS, a matching local dashboard, QR pairing, revocation, durable redb storage and ten snapshots per historical device. Sixteen active devices and 256 historical identities are supported. Remote backup access is opt-in; admin stays on loopback. No firewall/router changes or host-service installation are automatic.

Network permission is intentional for optional backups. TOTP works offline; no third-party runtime endpoints or analytics are implemented. DNS and selected file providers are Android services.

## Documentation

- [SETUP.md](SETUP.md): setup, migration, recovery and remote exposure.
- [SECURITY.md](SECURITY.md): rooted-device threat model and remaining gaps.
- [VALIDATION.md](VALIDATION.md): evidence and required phone tests.
- [ASSESSMENT.md](ASSESSMENT.md): alternatives and scoped agent security-review results.
- [Protocol 2](home-server/PROTOCOL.md): exact wire contract.

## Build

Android: SDK35, AGP8.9.2, Kotlin2.1.20, Gradle8.13, Android9+ minimum. Use JDK17 or a compatible JDK; locally tested with Corretto23 and Java17 bytecode. Configure your SDK in Android Studio or local.properties, then run:

```sh
./gradlew testDebugUnitTest lintDebug assembleDebug assembleRelease
```

Windows: use gradlew.bat. Debug APKs use a development certificate; release APKs are unsigned. Production signing is deliberately not configured. Do not uninstall or change signing identities without verified recovery material.

Rust: stable toolchain meeting Rust1.94 minimum; locally tested with1.94.1 on Windows x64:

```sh
cd home-server
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

Cross-platform source needs a native executable per OS/architecture; Linux/macOS/ARM were not locally tested. The server uses Rust TLS without an OpenSSL installation. Cargo.lock is included.

Optional Python tests need cryptography installed:

```sh
python home-server/tests/public_backup_interop.py
python home-server/tests/https_integration.py home-server/target/release/localauth-home.exe
```

Run the interoperability command after Android JVM tests create its JCA fixture. Adjust the server executable path for your OS. All fixtures/private test keys are synthetic, never real accounts.
