use verify_core::{
    trust::{PublisherDetails, TrustStore},
    verify_detached_signature, SignatureIdentity,
};

const FINGERPRINT: &str = "D4D0D3202FC06849A257B38DE94618334C674B40";

fn identity(user_id: Option<&str>) -> SignatureIdentity {
    SignatureIdentity {
        fingerprint: FINGERPRINT.into(),
        user_id: user_id.map(str::to_owned),
        signing_key: FINGERPRINT.into(),
    }
}

#[test]
fn parses_name_and_email() {
    assert_eq!(
        PublisherDetails::from_user_id(Some("Craig Raw <craig@sparrowwallet.com>")),
        PublisherDetails {
            name: "Craig Raw".into(),
            email: "craig@sparrowwallet.com".into()
        }
    );
}

#[test]
fn handles_missing_or_partial_user_ids() {
    assert_eq!(
        PublisherDetails::from_user_id(None),
        PublisherDetails::default()
    );
    assert_eq!(PublisherDetails::from_user_id(Some("Craig Raw")).email, "");
    assert_eq!(
        PublisherDetails::from_user_id(Some("craig@example.com")).name,
        ""
    );
    assert_eq!(
        PublisherDetails::from_user_id(Some("<craig@example.com>")).email,
        "craig@example.com"
    );
    assert_eq!(
        PublisherDetails::from_user_id(Some("Broken <address")).name,
        "Broken <address"
    );
}

#[test]
fn sanitizes_control_and_bidi_characters_and_bounds_text() {
    let details =
        PublisherDetails::from_user_id(Some("Cr\n\u{202e}aig <cr\t\u{2066}aig@example.com>"));
    assert_eq!(details.name, "Craig");
    assert_eq!(details.email, "craig@example.com");
    let long = format!("{} <{}>", "名".repeat(300), "é".repeat(300));
    let details = PublisherDetails::from_user_id(Some(&long));
    assert_eq!(details.name.chars().count(), 128);
    assert_eq!(details.email.chars().count(), 254);
}

#[test]
fn preserves_legacy_trust_without_inventing_metadata() {
    let text = format!(
        "{}\r\ninvalid\n{}\n",
        FINGERPRINT.to_lowercase(),
        "A".repeat(64)
    );
    let store = TrustStore::from_bytes(text.as_bytes());
    assert!(store.contains(FINGERPRINT));
    assert_eq!(store.entries().count(), 2);
    assert!(store.entries().all(|(_, details)| details.is_none()));
    assert_eq!(TrustStore::from_bytes(&store.to_bytes().unwrap()), store);
}

#[test]
fn real_sparrow_identity_round_trips() {
    let identity = verify_detached_signature(
        include_bytes!("fixtures/sparrow-manifest.txt"),
        include_bytes!("fixtures/sparrow-manifest.asc"),
        include_bytes!("fixtures/sparrow-public-key.asc"),
    )
    .unwrap();
    let mut store = TrustStore::default();
    store.remember(&identity).unwrap();
    assert!(!store.key_available(&identity.fingerprint));
    assert!(store.remember_key(&identity.fingerprint));
    let loaded = TrustStore::from_bytes(&store.to_bytes().unwrap());
    assert_eq!(loaded, store);
    assert!(loaded.key_available(&identity.fingerprint));
    let details = loaded.entries().next().unwrap().1.as_ref().unwrap();
    assert_eq!(details.name, "Craig Raw");
    assert_eq!(details.email, "craig@sparrowwallet.com");
}

#[test]
fn enriches_a_legacy_record_without_an_additional_trust_decision() {
    let mut store = TrustStore::from_bytes(FINGERPRINT.as_bytes());
    assert!(store.refresh_details(&identity(Some("Craig <craig@example.com>"))));
    assert!(store.contains(FINGERPRINT));
    assert!(!store.refresh_details(&identity(Some("Craig <craig@example.com>"))));
    assert_eq!(TrustStore::from_bytes(&store.to_bytes().unwrap()), store);
}

#[test]
fn metadata_cannot_grant_trust_to_an_unknown_fingerprint() {
    let mut store = TrustStore::default();
    assert!(!store.refresh_details(&identity(Some("Craig <craig@example.com>"))));
    assert!(!store.contains(FINGERPRINT));
    store
        .remember(&identity(Some("Craig <craig@example.com>")))
        .unwrap();
    let mut impostor = identity(Some("Craig <craig@example.com>"));
    impostor.fingerprint = "B".repeat(40);
    assert!(!store.refresh_details(&impostor));
    assert!(!store.remember_key(&impostor.fingerprint));
    assert!(!store.contains(&impostor.fingerprint));
}

#[test]
fn refreshes_changed_details_but_does_not_erase_with_an_absent_user_id() {
    let mut store = TrustStore::default();
    store
        .remember(&identity(Some("Craig <old@example.com>")))
        .unwrap();
    assert!(store.refresh_details(&identity(Some("Craig <new@example.com>"))));
    assert!(!store.refresh_details(&identity(None)));
    assert_eq!(
        store.entries().next().unwrap().1.as_ref().unwrap().email,
        "new@example.com"
    );
}

#[test]
fn rejects_corrupt_unsupported_and_oversized_stores() {
    for bytes in [
        b"{broken".to_vec(),
        b"{\"version\":3,\"publishers\":{}}".to_vec(),
        b"{\"version\":1,\"publishers\":{\"bad-fingerprint\":null}}".to_vec(),
        vec![b' '; 65537],
        vec![255],
    ] {
        assert_eq!(TrustStore::from_bytes(&bytes).entries().count(), 0);
    }
}

#[test]
fn normalizes_and_sanitizes_persisted_metadata() {
    let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"publishers":{
        FINGERPRINT.to_lowercase(): {"name":"Craig\u{202e}","email":"a\nb@example.com"}
    }}))
    .unwrap();
    let store = TrustStore::from_bytes(&bytes);
    let (fingerprint, details) = store.entries().next().unwrap();
    assert_eq!(fingerprint, FINGERPRINT);
    assert_eq!(details.as_ref().unwrap().name, "Craig");
    assert_eq!(details.as_ref().unwrap().email, "ab@example.com");
}

#[test]
fn enforces_limit_and_rejects_invalid_fingerprints() {
    let mut store = TrustStore::default();
    let mut item = identity(Some("Publisher <public@example.com>"));
    item.fingerprint = "invalid".into();
    assert!(store.remember(&item).is_err());
    for i in 0..32 {
        item.fingerprint = format!("{i:040X}");
        store.remember(&item).unwrap();
    }
    store.remember(&item).unwrap();
    item.fingerprint = format!("{:040X}", 32);
    assert!(store.remember(&item).is_err());
    assert_eq!(TrustStore::from_bytes(&store.to_bytes().unwrap()), store);
}

#[test]
fn clearing_removes_metadata_and_trust() {
    let mut store = TrustStore::default();
    store
        .remember(&identity(Some("Craig <craig@example.com>")))
        .unwrap();
    store.clear();
    assert!(!store.contains(FINGERPRINT));
    assert_eq!(
        TrustStore::from_bytes(&store.to_bytes().unwrap()),
        TrustStore::default()
    );
    assert_eq!(TrustStore::from_bytes(b""), TrustStore::default());
}

#[test]
fn removing_one_of_two_identically_named_publishers_preserves_the_other() {
    let mut store = TrustStore::default();
    let first = identity(Some("Publisher <public@example.com>"));
    let mut second = first.clone();
    second.fingerprint = "B".repeat(40);
    store.remember(&first).unwrap();
    store.remember(&second).unwrap();
    assert!(store.remember_key(&first.fingerprint));
    assert!(store.remember_key(&second.fingerprint));
    assert!(store.forget(&first.fingerprint.to_lowercase()));
    let reloaded = TrustStore::from_bytes(&store.to_bytes().unwrap());
    assert!(!reloaded.contains(&first.fingerprint));
    assert!(reloaded.contains(&second.fingerprint));
    assert!(!reloaded.key_available(&first.fingerprint));
    assert!(reloaded.key_available(&second.fingerprint));
    assert_eq!(reloaded.entries().count(), 1);
    assert_eq!(
        reloaded.entries().next().unwrap().1.as_ref().unwrap().email,
        "public@example.com"
    );
    assert!(!store.refresh_details(&first));
}

#[test]
fn unknown_or_partial_fingerprints_cannot_remove_a_key() {
    let mut store = TrustStore::default();
    store
        .remember(&identity(Some("Publisher <public@example.com>")))
        .unwrap();
    let original = store.clone();
    for fingerprint in [
        "",
        "Publisher",
        "public@example.com",
        &FINGERPRINT[..8],
        &"B".repeat(40),
    ] {
        assert!(!store.forget(fingerprint));
        assert_eq!(store, original);
    }
}

#[test]
fn removes_legacy_and_last_entries_without_erasing_other_legacy_trust() {
    let second = "B".repeat(64);
    let mut store = TrustStore::from_bytes(format!("{FINGERPRINT}\n{second}").as_bytes());
    assert!(store.forget(FINGERPRINT));
    assert!(store.contains(&second));
    assert!(store.forget(&second));
    assert_eq!(
        TrustStore::from_bytes(&store.to_bytes().unwrap()),
        TrustStore::default()
    );
}

#[test]
fn staging_removal_leaves_live_trust_unchanged_until_committed() {
    let mut live = TrustStore::default();
    live.remember(&identity(Some("Publisher <public@example.com>")))
        .unwrap();
    let mut staged = live.clone();
    assert!(staged.forget(FINGERPRINT));
    assert!(live.contains(FINGERPRINT));
    assert!(!staged.contains(FINGERPRINT));
}

#[test]
fn ignores_saved_key_markers_without_matching_trust() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 2,
        "publishers": {FINGERPRINT: null},
        "saved_keys": ["B".repeat(40)]
    }))
    .unwrap();
    let store = TrustStore::from_bytes(&bytes);
    assert!(store.contains(FINGERPRINT));
    assert!(!store.key_available(FINGERPRINT));
    assert!(!store.key_available(&"B".repeat(40)));
}

#[test]
fn version_one_records_migrate_without_claiming_a_saved_certificate() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "publishers": {FINGERPRINT: null},
        "saved_keys": [FINGERPRINT]
    }))
    .unwrap();
    let store = TrustStore::from_bytes(&bytes);
    assert!(store.contains(FINGERPRINT));
    assert!(!store.key_available(FINGERPRINT));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&store.to_bytes().unwrap()).unwrap()["version"],
        2
    );
}
