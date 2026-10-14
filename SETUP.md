# Set up LocalAuth 4.0

Use disposable accounts first. Keep service recovery codes. Never clear data, uninstall or downgrade a real vault to troubleshoot.

## Phone and recovery kit

1. Enroll a fingerprint in Android Settings and install the test APK, or sign a release with your own key. Updates require compatible signing identities.
2. Scan fingerprint to create/unlock the vault. Hardware biometric enforcement is mandatory. Android verifies the fingerprint; LocalAuth never sees templates. Randomness supplies key security; invisible scan timing is supplemental, not reproducible key material.
3. Save the recovery kit to trusted offline storage via the file picker. Keep it off this phone and separate from the server; some selectable providers are cloud-backed.
4. Returning from the picker locks the vault. Unlock again to write the current matching kit, then confirm the final fingerprint prompt to rotate the metadata key/finish setup. If canceled, save again; a kit from aborted setup may not match the final recipient.
5. Import a disposable camera/gallery QR or manual Base32/otpauth account. External pickers/camera lock the vault; unlock on return. Hardware support for algorithm/seed length is mandatory. SHA1/SHA512 may be unsupported.
6. Tap account, scan fingerprint and copy the code. Expiration hides it and the next code needs another scan. Check it against the service and test restore before valuable use.

Legacy v2/v3 conversion waits until kit export and every hardware import succeed; failure keeps the original disk vault. Unsupported hardware can block migration. Keep old backups/keys. Do not downgrade after conversion. V1 preference vaults are refused.

## Home server

Windows: extract Home ZIP to a private folder and run start-home.cmd or localauth-home.exe. Keep its data directory, with encrypted snapshots and TLS/enrollment identity. Open the printed localhost dashboard link containing a capability that changes at restart. No account is created. The server stops when its process stops; service installation/auto-start are not included.

Linux/macOS: build home-server with cargo build --release --locked and run your native executable; not locally tested.

Default ports: backup HTTPS7443, dashboard127.0.0.1:7444, mDNS UDP5353. Configure LAN firewall deliberately; no rules are changed automatically. Guest Wi-Fi/VPNs can block discovery. Never forward dashboard7444.

Options: --data, --port, --admin-port, --no-discovery, --bind-address and --remote. Source-address LAN filtering is advisory, especially behind NAT/proxies.

## Pair and back up

1. Use this protocol2 server; unsigned-bootstrap older servers are incompatible.
2. Finish phone kit setup, unlock, then accept nearby discovery or open Home backup.
3. In the dashboard choose a phone-reachable address, normally https://computer-LAN-IP:7443, and Pair a phone.
4. Scan its QR with Add account/Scan QR or paste the trusted dashboard code in Home backup/Pair home server. Offers expire in5minutes, one use. Discovery names are untrusted hints.
5. Confirm address. TLS certificate pin and signed hardware identity proof are checked. No hardware signing support means failure.
6. Confirm first backup separately; pairing alone uploads nothing. Automatic backup is separately opt-in after account changes while unlocked, not unattended periodic sync.

Phone/server clocks must be within1minute. Changed certificates/pins, redirects and HTTP are rejected. Re-pair locally after TLS identity changes.

Ten snapshots per historical identity; the eleventh replaces oldest. Max4MiB,16 active devices,256 historical records; revocation preserves old ciphertext for local recovery. No archival deletion UI exists after the history cap.

Retry failed uploads manually with Back up now. Already-started ciphertext jobs may finish after lock, with phone timestamp stale. No durable retry/background queue is claimed.

## Lost-phone recovery

1. Download the old device's encrypted .lab file from the home dashboard, including revoked-device backups.
2. On a replacement supported phone create a vault and export its own new offline kit.
3. Home backup/Import recovery file: choose old .lab. For LAB2 choose the old matching kit JSON, then unlock after the picker. LAB1 uses its original43-character recovery key.
4. Accounts merge; existing entries remain. Restored seeds get new hardware keys and capsules under the replacement phone's new recipient. Import failure leaves the previous vault unchanged.
5. Pair replacement separately/upload a new backup/revoke old phone. A new phone does not impersonate the old signing identity.

Keep kit/ciphertext separately. Without the kit, neither server nor app can restore LAB2. Test on another disposable device. Copy server data only while its process is stopped, or retain exported ciphertext; live DB copying is unsupported.

## Away from home

Start with --remote and set an external HTTPS address before pairing. DNS/router/firewall are your responsibility. A VPN can reach the existing LAN service without publicly exposing backup TLS.

Direct exposure: forward only backup TLS, never admin. Native TLS or TCP passthrough preserves the pinned certificate. TLS-terminating proxies change it and require deliberate configuration/re-pairing; do not disable verification. Use split DNS/hairpin routing as needed. The app keeps one endpoint, not automatic LAN/public profiles. Re-pairing an active signing key preserves its record/backups.

Read [SECURITY.md](SECURITY.md) first. Remote routing, Linux/macOS, VPNs, IPv6 and production-host hardening were not locally tested. No public deployment was created.
