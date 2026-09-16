# Verify release checks

## Current installer: 0.1.9

The active overflow menu follows the native KeyOS visual hierarchy: a strong dimming backdrop, bright elevated menu surface, rounded border and trailing lock/info icons. It keeps the non-modal implementation and 64x60px touch target introduced in 0.1.8.

- 57 core tests and 116 preview renders pass. The open menu is covered at 760/800px heights in both themes.
- All 25 Python package and UI-style tests pass against `dist/verify-0.1.9-beta3.app`, including cryptographic signature and tamper checks.
- Installer SHA-256: `6e3ca0224d57809e903a3cc459113f4b068fc964b41b1661c774ee0ec1847cbe`.
- App hash: `20d2b0ac0de8038ad0223c71075a714a644e6c74fcc563c96350c746838a56c7`.
- The hardware target builds and signs successfully with the existing `qna-dev` identity. The validated installer is also on the Desktop.

## Previous installer: 0.1.8

The home overflow menu is an in-page overlay instead of a modal popup, avoiding retained modal input capture after dismissal. Its three-dot control keeps the 48x44px visual treatment but has a 64x60px touch target. The menu uses the secondary theme surface, a stronger border, a shadow and a subtle backdrop so it remains distinct in light and dark themes.

- 57 core tests pass, including real Sparrow OpenPGP verification, malformed input, streaming, cancellation and publisher trust persistence.
- 116 base and scenario preview renders pass across 760/800px heights and light/dark themes, including the open overflow menu.
- All 25 Python tests pass against `dist/verify-0.1.8-beta3.app`, including cryptographic signature checks, archive structure, metadata, tamper rejection, standard CTA sizing and menu regression coverage.
- Installer SHA-256: `21a81aea70ac2021573729a45cd13f5dbf4796cf8bb238a711834cd99f68e7dd`.
- App hash: `53128af9d5c1066dac3cb172caa37b9a3b6df753a52fff8021667ddc8959fe33`.
- The hardware target builds and signs successfully with the existing `qna-dev` identity. The validated installer is also on the Desktop; physical repeated-tap behaviour remains the device acceptance check.

## Previous installer: 0.1.7

Verify Release now opens a saved-publisher chooser when trust records exist. Complete verified public certificates are retained in separate bounded, durable app-private files and are selected by their full fingerprint. The fallback file picker remains available. Version 1 and legacy trust records stay trusted but are labelled **Re-import required** until one successful release verification supplies the complete certificate.

- 57 core tests pass, including trust-store version migration, prevention of certificate markers for unknown fingerprints, preservation of exact-fingerprint deletion, real Sparrow OpenPGP verification, malformed input, streaming and cancellation.
- 112 base and scenario preview renders pass across 760/800px heights and light/dark themes, including reusable, legacy and mixed publisher lists on the new chooser screen.
- All 22 Python tests pass against `dist/verify-0.1.7-beta3.app`, including signatures, archive structure, metadata, tamper rejection and standard CTA sizing.
- Installer SHA-256: `e9f1c0e8792aa8e6f59fe3850d5f0e548a67acc44e2793f34cab37f1733d05fb`.
- App hash: `f64d4f9c6787c648084bfce57e84e91b08ef6f9b011a54b7bec0649a0b9b3e25`.
- The hardware target builds and signs successfully with the existing `qna-dev` identity, and the hosted simulator build launches. Physical selection and installation remain device acceptance checks.

## Previous installer: 0.1.6

Signed with the existing `qna-dev` identity for KeyOS 1.4.0-beta3 or newer. Includes checksum QR removal, name/email-only overview cards, full fingerprints on details, and a standard red Delete Key button with confirmation and no archive step.

- Installer: `dist/verify-0.1.6-beta3.app`; matching copies on Desktop and PASSPORT-SD.
- Installer SHA-256: `0f1efbcff4d7635e162304b0f8206df689ea84262e26ef253f29e09e0b153ba0`.
- App hash: `903417b18faece01cf5a24ed12065bf1c57980b4b45dea6f9abb384f1c789974`.
- 55 core tests and 22 Python tests pass. Package signatures, payload hashes, version, signer and beta3 metadata validate. Formatting and app Clippy pass.
- The UI changes passed 96 preview renders and the simulator checks recorded below. Existing saved publisher trust is preserved; demo publisher trust is not packaged. Physical installation remains for device acceptance.

## 0.1.6 UI verification: publisher details and deletion

Overview cards show the publisher name and email without its fingerprint. Publisher cards open a details screen with the full fingerprint and a standard 60px red Delete Key button. A blocking confirmation dialog shows the selected name and full fingerprint, with Cancel and Delete Key. The flow follows the native apps' separate management screen and 2FA confirmation pattern without archiving.

- 55 core tests, CTA sizing, formatting, app Clippy and 96 preview renders pass. Previews include long/legacy identities, multiple cards and deletion error states at both heights/themes.
- Simulator checks confirm card-to-details routing, modal backdrop blocking, cancellation, return to the updated list after deletion, and deletion persistence after close/relaunch.
- Scripts: `tests/sim-open-publisher-details.json`, `tests/sim-remove-publisher.json`, `tests/sim-publisher-persistence.json`. Screenshots: `target/sim-publisher-list-compact.png`, `target/sim-publisher-details.png`, `target/sim-publisher-delete-dialog.png`, and `target/sim-publisher-removed.png`.
- The public demo publisher is restored through normal signed-release verification and explicit test trust for user review. No demo trust is bundled into the app.

## 0.1.6 UI verification: checksum QR removal

Checksum entry offers Choose Checksum File and Enter Checksum. The scanner callback, scanner navigation and QR button are removed.

- 55 core tests, CTA sizing, formatting, app Clippy and 64 preview renders pass.
- Simulator checksum-file comparison and manually entered SHA-256 comparison after SHA-512 hashing both produce Checksum Matches.
- The public Ed25519 demo publisher is added through signed-release verification and explicit test trust for card review; no fixture trust is built into the application.

## Previous installer: 0.1.5

Each publisher card offers Remove Key with Confirm Remove and Cancel. Removal uses the exact fingerprint and commits the updated durable record before updating the live model. Other publishers and downloaded files are untouched.

- Signed with the existing `qna-dev` identity for KeyOS 1.4.0-beta3 or newer. Installer: `dist/verify-0.1.5-beta3.app`; matching copies on Desktop and PASSPORT-SD.
- Installer SHA-256: `d471bbddef99193cdf0ec4bab64f56427ac91a58e44c75d6a4614d6e81787bd4`.
- App hash: `dfac279f684beac49d1ef65420e7fa4aa11ed42052662e2e772568396560971a`.
- All 22 Python tests pass against this package; signatures, payload hashes and beta3 metadata validate.
- 55 core tests pass, including four per-key removal regressions: identical display identities, unknown/partial fingerprints, legacy/last-entry removal, and staged changes leaving live trust untouched.
- Core/app Clippy, formatting and 64 UI preview renders pass. Confirmation, long fields and multiple cards are covered at both heights/themes.
- Simulator: Cancel preserved the saved public demo key; Confirm Remove deleted it; closing/relaunching the app confirmed deletion persisted. Script: `tests/sim-remove-publisher.json`, followed by `tests/sim-publisher-persistence.json`. Evidence: `target/sim-publisher-remove-*.png`, `target/sim-publisher-removed.png`, `target/sim-publisher-persisted.png`.
- Multi-publisher isolation is covered by host tests. Physical installation remains a device acceptance check.

## Previous installer: 0.1.4

Built and signed on 2026-09-04 with the existing `qna-dev` identity for KeyOS 1.4.0-beta3 or newer. Saved publishers appear in wrapping, scrollable cards containing name, email and full fingerprint. One versioned durable record stores metadata and trust together; legacy fingerprint-only records stay trusted and receive metadata after a successful signed-release verification.

- Installer: `dist/verify-0.1.4-beta3.app`; copies on Desktop and PASSPORT-SD.
- Installer SHA-256: `0125fb283805b9bf60e204be332adcfd8afba50ccaf9d2063bec67f0da3b8eef`.
- App hash: `3d8db3ae61e9356b3a640ec9152beb787086a48d09daf3e7d213a6eb71978c38`.
- 51 core tests and 22 Python tests pass. Twelve new trust tests cover real Sparrow name/email extraction, round-trip persistence, legacy migration, metadata-only refresh, unknown-key isolation, malformed/oversized stores, text sanitization, limits and clearing.
- Core and app Clippy pass; formatting and 60 preview renders pass, including legacy records, long fields and multiple cards at both heights/themes.
- Simulator: verified a demo release, explicitly trusted its test fingerprint, checked the populated card, closed/relaunched the app and confirmed metadata persisted. Evidence: `target/sim-publisher-*.png`; scripts: `tests/sim-publisher-cards.json`, `tests/sim-save-publisher-card.json`, `tests/sim-publisher-persistence.json`.
- Legacy migration is covered by host tests; upgrade on physical hardware remains for device acceptance. Existing entries need a successful signed-release verification to supply missing names/emails; fingerprints alone cannot reconstruct them.

## Previous installer: 0.1.3

Built and signed on 2026-09-04 with the existing `qna-dev` identity for KeyOS 1.4.0-beta3 or newer. An app-wide CTA audit found two remaining undersized full-width actions: Scan a Hash QR and Trust This Publisher Key. Both use `ControlSize.md` (60px). Compact inline file-picker controls and algorithm selectors retain their small size.

- Installer: `dist/verify-0.1.3-beta3.app`; Desktop copy: `/Users/admin/Desktop/verify-0.1.3-beta3.app`.
- Installer SHA-256: `2b329d2980b915a66edbf2031d8ed7f9f106846a5cedb7eaca9aee981c1937c6`.
- App hash: `11634c0a49ae250db7bbb34cd43fb5f9084ae4469c807fa7e9b3b8e7affdc3e8`.
- 39 core tests, 22 Python tests, formatting and 48 UI previews pass. The new CTA style check fails on both old undersized actions and passes after the fixes. The updated screens were visually checked at 480x760.
- Hardware installation of this release remains a device acceptance check.

## Previous installer: 0.1.2

Built and signed on 2026-09-04 with the existing `qna-dev` identity for KeyOS 1.4.0-beta3 or newer. Both secondary buttons on Compare Checksum use `ControlSize.md`, matching Compare and the other main CTAs at 60px tall. The 12px action spacing is unchanged.

- Installer: `dist/verify-0.1.2-beta3.app`; identical copy: `/Users/admin/Desktop/verify-0.1.2-beta3.app`.
- Installer SHA-256: `f75b5cc57e19d9d8ebff3d8a0f2d7bc09754055704438fec9c4c24ac5d03677a`.
- App hash: `ea5beee604c59ad4cbd9b3c408627f580c879a29578489916ed337028e122a77`.
- 39 core tests, 21 package tests, formatting and 48 UI previews pass. The Desktop copy matches the validated installer. Comparison simulator tap coordinates were adjusted to the new button centers.
- No SD card was mounted for this release. The updated installer has not been checked on physical hardware.

## Previous installer: 0.1.1

Built and signed on 2026-09-03 with the existing `qna-dev` identity for KeyOS 1.4.0-beta3 or newer. This installer includes all UI review changes below, including the grouped comparison actions and success/failure symbols.

- Installer: `dist/verify-0.1.1-beta3.app`; identical copy: `/Users/admin/Desktop/verify-0.1.1-beta3.app`.
- Installer SHA-256: `e5e58d38dfbf06eba0910be0b47a1d5d07daa2e5983f198e83b0904ac77872d0`.
- App hash: `d6722e4175ee2301e6b5ed3bd18f4f13d0e45e8f3f41f82a7c30fa1807986e13`.
- 39 core tests and 21 package tests pass, including real signature verification and tamper rejection. The Desktop copy's SHA-256 matches the validated installer.
- UI checks: 48 preview renders; latest comparison layout checked in the simulator. Physical installation remains for device acceptance.

The 0.1.0 installer and install-kit ZIP below are retained as historical artifacts, not the current release.

## Historical 0.1.0 checks and subsequent UI review

Date: 2026-09-03. Scope: internal SDK POC, ready for device installation/testing, not an independent security audit.

## UI review changes after the packaged build

The UI review added the two-action home screen, overflow menu, revised copy, and unified Check a File flow. These changes are included in 0.1.1; the historical 0.1.0 installer identified below does not include them.

The unified flow passed the 39 core tests, app Clippy, formatting, and 40 preview renders. Simulator checks confirmed file retention from hashing into comparison, imported-checksum success, and SHA-512 hashing followed by automatic SHA-256 comparison with a typed checksum. Evidence: `target/sim-unified-*.png`; scripts: `tests/sim-unified-check.json` and `tests/sim-unified-compare.json`. Older simulator scripts use the earlier home-screen coordinates.

The comparison form uses natural-height cards and secondary buttons instead of stretching them to fill the viewport. Checksum matches use a green checkmark while retaining the publisher-identity warning; failures use a red X. Status symbols are prerasterized PNGs because the SDK software renderer does not draw runtime Slint Path elements. Their editable SVG sources are in `ui/assets/` and can be rendered with `cairosvg`. UI coverage includes 48 preview renders across both themes and heights, including success and failure states. The mismatch simulator script is `tests/sim-checksum-mismatch.json`.

After a clean simulator restart, imported and typed checksum matches displayed the checkmark, and an all-zero expected digest displayed the failure X. The 39 core tests, app Clippy, formatting, and 48 preview renders passed with these changes. The simulator remains on the home screen for review.

The comparison screen groups both checksum-input buttons and Compare into one fixed bottom action stack with 12px gaps. Only the file details scroll; spare vertical space stays above the actions. All 48 preview renders and formatting checks pass. The simulator is left on Compare Checksum for this layout review.

## Build identity

- SDK: Foundation SDK 1.0.0, aarch64-apple-darwin bundle; `foundation doctor` passes all checks inside its Nix shell.
- Target: `armv7a-unknown-xous-elf`, optimized release.
- App ID: `0x082345924de3d118781cf199b2476ae5`.
- Minimum KeyOS: `1.4.0-beta3`.
- Developer signer: existing `qna-dev` identity. No Foundation signature.
- Installer: `dist/verify-0.1.0-beta3.app` (about 2.1 MiB).
- Installer SHA-256: `73fc061534f1c899d443e4a7e6c2fabee76cf58f207b118e6e30cf2b7afc45c3`.
- Unsigned app payload hash shown in Settings: `032a25753f7df40c9ab4697c0b14eb1de9e03ef4dcdf613430f4fcd68605f6ae`.

## Automated gates: 60 passing tests

`cargo test -p verify-core`: 39 passing tests.

- SHA-256 empty, abc, and million-a vectors; SHA-512 abc vector.
- Streaming chunk boundaries, progress, cancellation, interrupted reads, I/O failure, and hash-engine failure.
- GNU/BSD/bare checksums, CRLF, filename spaces, ambiguous basenames, mismatched filenames, malformed and oversized inputs.
- Typed/QR expected-digest parser rejects URLs, prefixes, weak lengths, non-ASCII hex, and oversized data.
- Armored/binary RSA signatures, a signing subkey with binding, Ed25519, and a genuine Sparrow signed manifest.
- Wrong key, changed manifest, SHA-1 data signature, RSA-1024, revoked key, expired key/signature, future signature, multiple signatures, truncated data, malicious packet lengths.
- 256 deterministic garbage signature inputs without panic. This is bounded malformed-input testing, not an exhaustive fuzzing campaign.

`VERIFY_PACKAGE=dist/verify-0.1.0-beta3.app python3 -m unittest discover -s tests -p 'test_*.py' -v`: 21 passing tests.

- App ID/version/minimum-version and signed hash inventory validation.
- Missing signatures, changed app, icon tampering, extra files, different developer signers, invalid archive order, duplicate entries, symlinks, and unsafe paths rejected.
- Actual manifest and ELF ECDSA signatures verified with `cosign2`.
- Modified signed payloads and a modified ECDSA signature rejected cryptographically.

Both core and app Clippy checks pass with app warnings denied; SDK dependencies still emit their own existing warnings. App/core formatting checks pass.

## Real release interoperability

The host verification harness checked the actual `sparrowserver-2.5.4-aarch64.tar.gz` release, 103,182,519 bytes, against its detached signed manifest. The resulting publisher fingerprint was `D4D0D3202FC06849A257B38DE94618334C674B40`.

Sources: [Sparrow downloads](https://www.sparrowwallet.com/download/), [2.5.4 release](https://github.com/sparrowwallet/sparrow/releases/tag/2.5.4), [publisher public key](https://keybase.io/craigraw/pgp_keys.asc). The large artifact stays under ignored `target/`, not in the repository or install kit.

Reproduce with the `verify-core` example `check_release`, passing artifact, manifest, detached signature, and public certificate paths in that order.

## UI and simulator

- 36 rendered screen/theme/height combinations: nine screens, 480x760 and 480x800, light and dark.
- Visually reviewed home, compare, release, result, trust, saved keys, hash selection, expected hash, and explanatory screens. Results and comparison content scroll independently of the final action button.
- Simulator: SHA-256 and SHA-512 matched the public demo artifact; full SHA-512 remained readable.
- Simulator: file-checksum comparison, typed-hash comparison, signed-release success, explicit fingerprint trust, and wrong-key failure.
- Simulator: trusted fingerprint survived process/simulator restart; two-step Forget All cleared it.
- Manual hash-entry testing caught a keyboard Done action that did not dismiss input; the release handles submission and clears focus.
- Public demo QR was decoded independently with OpenCV and matched the expected SHA-256.

Evidence is in `target/sim-*.png` and `target/previews/`; selected images are copied to `dist/screenshots/`. Simulator captures appear to swap red/blue color channels; semantic text and preview renders were reviewed separately. Earlier debug runs hit the bundled hosted kernel's 32-thread limit after repeated separate debug-client connections. Single-connection action scripts and simulator restarts avoided it; no SDK changes were made.

## Dependency review

`cargo audit` exits successfully with the verification-only RSA timing advisory exception in `.cargo/audit.toml`. The event-listener vulnerability was resolved by updating to 5.4.2. Six SDK maintenance warnings remain. See `SECURITY.md` for the exact advisories and limitations.

## Remaining device acceptance

No physical Passport Prime or external/SD volume was detected at handoff. Hardware installation, actual SD/Airlock reads, physical QR camera scanning, device SHA accelerator/performance, and unplugging real media remain device acceptance tests, not claimed as completed.

Install the supplied `.app`, grant the prompted filesystem/GUI/hash permissions, and follow `dist/verify-demo/DEMO.md`. Test success, mismatch, trusted-key persistence, QR input, cancellation on a large file, and media removal. Never use a real seed or private key for these tests.
