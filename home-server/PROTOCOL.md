# LocalAuth backup protocol 2

TLS uses the certificate SHA-256 pin distributed in the trusted pairing offer. REST paths remain `/v1/*`; offer field `v` and health field `protocol` are `2`. Protocol 1 unsigned pairing/challenge bootstrap is not accepted. Signatures are P-256 ECDSA with SHA-256, ASN.1 DER encoded and base64url encoded without padding. Hashes are lowercase SHA-256 hexadecimal. Canonical strings use UTF-8 and LF separators, without a final newline.

## Pair

POST `/v1/pair` JSON contains `ticket`, `public_key`, `label`, `proof`. Public key is X.509 SubjectPublicKeyInfo DER base64url without padding. The proof signs:

```
LocalAuth pair v2
<server certificate pin>
<one-time pairing ticket>
<public_key exactly as sent>
<SHA-256 of UTF-8 label>
```

Proof is verified before consuming a pairing ticket. A valid proof for an already paired key returns the same active device identity. Pair tickets expire after five minutes. Sixteen active devices are allowed; revoked history is retained with a separate total limit of 256 records. Administrative archival beyond that lifetime limit is currently not implemented.

## Acquire challenge

GET `/v1/challenge/{device}` requires `X-Client-Nonce`, `X-Client-Time`, and `X-Signature`. Client nonce is 32 random bytes base64url encoded without padding. Client time is canonical decimal Unix milliseconds, without whitespace or leading zeros. Sign:

```
LocalAuth challenge v2
<server certificate pin>
<device>
<client nonce>
<client timestamp>
```

Authentication and a +/-60-second timestamp check precede challenge allocation. Used client nonces remain cached for 120 seconds, covering the full acceptance interval even for future timestamps. Each device can hold four outstanding challenges and 128 accepted bootstrap nonces. Challenges expire after 60 seconds. Invalid signatures never allocate either cache. A capped device cannot consume another device's challenge quota. Replayed accepted bootstrap requests fail. Phones need their system clock synchronized to within one minute of the server.

The successful JSON response includes `protocol: 2`, `challenge`, and `expires_in: 60`. Clients must reject responses with a different or absent protocol marker.

## Backup requests

POST or GET `/v1/backup` requires `X-Device`, `X-Challenge`, and `X-Signature`. Sign:

```
LocalAuth request v2
<device>
<server challenge>
<uppercase HTTP method>
/v1/backup
<SHA-256 of exact request body, empty bytes for GET>
```

A challenge is consumed only after signature verification. Changes to method, path, body, challenge, or device invalidate the signature. Revoked devices cannot acquire challenges or authenticate. The server stores opaque encrypted backup files; it does not possess the portable recovery encryption key.

The server accepts legacy LAB1 envelopes and new LAB2 envelopes up to 4 MiB. LAB2 starts with ASCII `LAB2`, a two-byte big-endian RSA ciphertext length (384), the 384-byte RSA-OAEP-SHA256/MGF1-SHA256 wrapped AES key, and a 12-byte GCM nonce. This 402-byte header is authenticated as AES-256-GCM additional data. A 16-byte tag follows the encrypted payload; minimum envelope size is 418 bytes. The server validates structure, without possessing the key to verify or decrypt the payload.

## Assurance limits

Signed proof establishes possession of the registered private key and rejects software copies containing only public keys, IDs, and old requests. It does not establish hardware key provenance or hardware biometric policy: server-side Android attestation verification is not implemented. Rooted phones are permitted. Root alone does not imply extraction of a hardware-protected key; a compromised phone can nevertheless observe decrypted data after genuine authentication or request signatures using the genuine device. Server operating-system compromise and internet-scale denial of service are outside this protocol's guarantees.
