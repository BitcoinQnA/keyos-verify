use verify_core::parse_expected_digest;

#[test]
fn accepts_sha256_and_sha512_with_spacing() {
    assert_eq!(
        parse_expected_digest(&"ab ".repeat(32)).unwrap(),
        vec![0xab; 32]
    );
    assert_eq!(
        parse_expected_digest(&"CD".repeat(64)).unwrap(),
        vec![0xcd; 64]
    );
}

#[test]
fn rejects_urls_labels_legacy_and_wrong_lengths() {
    for input in [
        "https://example.com",
        "sha256:abcd",
        "",
        "1234",
        &"ab".repeat(20),
        &"ab".repeat(33),
    ] {
        assert!(parse_expected_digest(input).is_err());
    }
}

#[test]
fn rejects_non_ascii_and_oversized_input() {
    assert!(parse_expected_digest(&"ＡＢ".repeat(32)).is_err());
    assert!(parse_expected_digest(&" ".repeat(1025)).is_err());
}
