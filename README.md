# Verify

An internal proof of concept built with the public Foundation SDK, not a native KeyOS app. Verify checks file hashes and detached OpenPGP signatures offline on Passport Prime. It is not independently security-audited.

## Install and try

Use `dist/verify-0.1.9-beta3.app` on KeyOS 1.4.0-beta3 or newer. Copy it to the SD/USB drive or Airlock, then install through Settings > Apps. The device must trust the existing `qna-dev` developer certificate; no Foundation signature is required. Do not unpack the `.app` file.

The `dist/verify-demo` folder contains only public, disposable test data:

1. **Check a File:** choose SHA-256 (the default) or SHA-512, then select `demo-release.txt` to view its hash.
2. From the hash result, choose **Compare with a Checksum**, then select `demo-manifest.txt`. The file is already selected. It should say **Checksum Matches**, not that the publisher is trusted. Alternatively type the hexadecimal hash using **Enter Checksum**. Comparison selects the algorithm from the expected checksum and rereads the file.
3. **Verify a Signed Release:** select `demo-release.txt`, `demo-manifest.txt`, `ed25519-manifest.asc`, and `ed25519-public-key.asc`. It should say **Signature and Hash Match**.
4. For this test key only, compare the fingerprint with `DEMO.md`, then explicitly trust it. Subsequent checks can choose that publisher from the saved-key list and say **Release Verified**.
5. Select `demo-wrong-manifest.txt` for a negative checksum test. It must fail.
6. The top-right three-dot menu contains **Saved Publisher Keys** and **About Verification**. Overview cards show publisher names and emails. Tap a card to see the full fingerprint and the red **Delete Key** button. A confirmation dialog offers **Cancel** or **Delete Key**, with no archive step. This removes only that fingerprint's saved trust and metadata. **Forget All Saved Keys** remains available with confirmation. Neither action changes any files.

Never treat the included demo key as a real publisher identity. For real releases, obtain the publisher fingerprint from an independent trusted source, not just the same download folder or computer.

## Supported checks

- Stream SHA-256/SHA-512 with a 32 KiB file buffer, progress, and cancellation between reads.
- Expected hashes from text entry or a checksum file.
- GNU `sha256sum`/`sha512sum`, BSD `SHA256 (...) = ...`/`SHA512 (...) = ...`, and a single bare hex digest.
- Detached OpenPGP signatures in binary or ASCII armor, with one public certificate and one detached signature per file.
- Modern signing algorithms, including RSA >=2048 bits and Ed25519. The test suite includes a real Sparrow 2.5.4 RSA-4096 release and signing-subkey fixtures.
- Expiration and supplied revocation checks, full primary-key fingerprint display, and explicit per-device trust decisions.
- File selection from Internal, Airlock, or external storage through SDK system pickers.

The checksum must match the selected filename. Duplicate basename matches are rejected. Compressed/clear-signed OpenPGP messages, multi-key bundles, animated UR hashes, URLs, MD5, SHA-1 data signatures, and arbitrary signature formats are not supported.

## Security boundaries

Verify cannot access the master seed or Seed Vault. It declares no `os/security` permission, accepts no seed imports, and performs no signing, decryption, key generation, installation, or software execution. Public keys are imported only for verification. Trusted fingerprints, display names/emails, and the corresponding public certificates are stored in app-private data so a saved publisher can be selected again. User files are opened read-only.

Saved Publisher Keys shows a card for each trusted fingerprint, with the associated name and email when available. The Verify Release publisher-key row opens these saved publishers before offering the file picker. Entries created before public certificates were retained stay trusted but need one successful re-import before reuse. Names and emails are self-asserted display metadata, not identity proof. Metadata and reusable public certificates are saved only after both the signature and release checksum pass and never grant trust to an unknown fingerprint.

A matching hash does not authenticate a publisher. A valid signature proves use of a key, not that the key belongs to the claimed person or that the software is safe. The app cannot discover new revocations, check online for updates, detect an old but valid release, or guarantee the computer will later execute the bytes checked here. Set the device clock correctly. See [SECURITY.md](SECURITY.md).

## Build and test

Install the Foundation SDK using its [official getting-started guide](https://docs.foundation.xyz/developers/get-started/). This app uses the installed SDK bundle through `.foundation-sdk/current`, with no dependency on a KeyOS worktree. Configure your own signing identity in `app-config.toml` if you do not have `qna-dev`.

Inside the SDK development shell:

```sh
foundation doctor
cargo test -p verify-core
cargo clippy -p verify-core --all-targets -- -D warnings
cargo fmt -p keyos-verify -p verify-core --check
python3 -m unittest discover -s tests -p 'test_*.py' -v
foundation sim
```

After code generation, `bash scripts/check-ui.sh` renders all 11 screens at two heights in both themes, plus edge-case states. The `tests/sim-*.json` scripts drive simulator-only demo workflows; coordinates and waits depend on the SDK file picker state. Review the resulting screenshots, not just command exit status.

```sh
mkdir -p dist
foundation pack --release --out target/verify-sdk-0.1.9.app
python3 scripts/pack-beta3.py target/verify-sdk-0.1.9.app dist/verify-0.1.9-beta3.app
```

The packaging wrapper validates signatures, hashes, archive contents, app ID and version, and preserves `minKeyosVersion`, which Beta 3 requires. It refuses to overwrite an output.

Tracking: [SUP-1273](https://linear.app/foundation-devices/issue/SUP-1273). See [TESTING.md](TESTING.md) for the release evidence and device-test limits.
