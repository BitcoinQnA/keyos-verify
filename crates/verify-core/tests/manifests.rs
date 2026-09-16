use verify_core::{find_manifest_entry, parse_manifest, HashAlgorithm, MAX_MANIFEST_BYTES};

#[test]
fn bare_digest_matches_any_selected_filename() {
    let entries = parse_manifest(&"A0".repeat(32)).unwrap();
    assert!(find_manifest_entry(&entries, "download.dmg").is_ok());
}

#[test]
fn rejects_ambiguous_duplicate_basenames() {
    let manifest = format!(
        "{}  a/app.bin\n{}  b/app.bin",
        "ab".repeat(32),
        "cd".repeat(32)
    );
    let entries = parse_manifest(&manifest).unwrap();
    assert!(find_manifest_entry(&entries, "app.bin")
        .unwrap_err()
        .contains("More than one"));
}

#[test]
fn refuses_single_named_entry_for_a_different_file() {
    let entries = parse_manifest(&format!("{}  good.bin", "ab".repeat(32))).unwrap();
    assert!(find_manifest_entry(&entries, "bad.bin").is_err());
}

#[test]
fn handles_crlf_comments_binary_markers_and_spaces() {
    let entries = parse_manifest(&format!(
        "# comment\r\n{} *my  release.bin\r\n",
        "AB".repeat(32)
    ))
    .unwrap();
    assert_eq!(entries[0].filename.as_deref(), Some("my  release.bin"));
    assert!(find_manifest_entry(&entries, "my  release.bin").is_ok());
}

#[test]
fn supports_sha512_bsd_format() {
    let entries = parse_manifest(&format!("SHA512 (app.bin) = {}", "12".repeat(64))).unwrap();
    assert_eq!(entries[0].algorithm, HashAlgorithm::Sha512);
}

#[test]
fn rejects_malformed_bsd_and_oversized_manifests() {
    assert!(parse_manifest("SHA256 (file) = 1234").is_err());
    assert!(parse_manifest("SHA256 (file 1234").is_err());
    assert!(parse_manifest(&"x".repeat(MAX_MANIFEST_BYTES + 1)).is_err());
}

#[test]
fn never_confuses_hash_prefixes_with_complete_hashes() {
    for length in [0, 1, 31, 33, 63, 65, 128] {
        assert!(parse_manifest(&"ab".repeat(length)).is_err());
    }
}
