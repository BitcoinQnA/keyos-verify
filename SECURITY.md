# Security scope

Verify is an internal POC, not an audited security product. Report findings to the Support issue [SUP-1273](https://linear.app/foundation-devices/issue/SUP-1273). Do not attach secrets.

## Trust model

The app independently hashes the selected file on the device. It verifies a detached signature over the exact manifest bytes, then matches and hashes the chosen artifact. A green result additionally requires the primary-key fingerprint to be explicitly trusted on this device. Claimed names inside a public key are not identity evidence.

The versioned trust file contains at most 32 public fingerprints with optional display names, emails, and markers for complete saved certificates. Each reusable public certificate is held separately in durable app-private storage and is bounded to 512 KiB. Legacy newline-separated fingerprint files remain readable; metadata and the complete certificate are populated after successful verification of a signed release. Metadata and certificate availability cannot grant trust or replace fingerprint matching. Names/emails are sanitized, length-limited, and displayed as claims from the key, not verified personal identities. Stores over 64 KiB or invalid versioned stores grant no trust.

Trust and metadata use SDK durable app-private writes; in-memory changes are applied only after the trust record succeeds. A new public-certificate file is written before its availability marker so interruption cannot create reusable trust without key bytes. Selecting a saved publisher rereads the certificate and performs the complete signature, fingerprint, and release-hash verification. Failed reads default to no trusted keys. Failed writes do not grant trust. No secret material is requested or generated, and there is no master-seed API permission.

Per-key removal targets the full fingerprint, never a name, email or list position. Confirmation durably removes its trust marker before best-effort deletion of the corresponding public-certificate file; a failed trust-record write leaves live trust unchanged. Other saved publishers and downloaded files are untouched.

## Limits

- Input bounds: 256 KiB manifests, 128 KiB signatures, 512 KiB public certificates, 1 KiB manually entered expected hashes. Artifact bytes are streamed.
- Untrusted OpenPGP inputs are parsed by rPGP 0.20.0. Limits and malformed-input tests reduce risk but do not constitute fuzzing assurance or a parser security audit.
- Expiry uses the device clock. Revocation checks can only evaluate revocations included in the supplied certificate. An attacker can supply an older certificate or a valid older release. Offline verification does not provide freshness or rollback protection.
- A successful result applies to the bytes read in that operation. Replacing the file afterwards, or executing a different file on a compromised host, is outside the guarantee.
- Cancellation is observed between file reads. It does not interrupt an in-flight OS read or the OpenPGP verification operation.
- Public filenames and certificate user IDs are untrusted display text. The fingerprint is the trust decision, not the displayed name.

## Dependency review, 2026-09-03

`event-listener` was updated to 5.4.2 to resolve [RUSTSEC-2026-0221](https://rustsec.org/advisories/RUSTSEC-2026-0221.html).

`rsa` 0.9.10 has [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), a timing attack against private-key operations. This app only verifies signatures with public keys. It never loads RSA private keys, signs, or decrypts. The audit exception is scoped to this verification-only use. Reassess it before adding any private-key operation; there is no patched version at this review.

The SDK dependency graph also reports unmaintained `bincode` 2.0.1, `paste` 1.0.15, `rustybuzz` 0.18/0.20, and `ttf-parser` 0.24/0.25. These are recorded maintenance risks, not a clean dependency-audit claim. Recheck advisories before every release.
