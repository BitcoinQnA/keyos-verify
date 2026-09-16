use verify_core::{verify_detached_signature, MAX_MANIFEST_BYTES};

const MANIFEST: &[u8] = include_bytes!("fixtures/demo-manifest.txt");
const KEY: &[u8] = include_bytes!("fixtures/test-public-key.asc");
const SIGNATURE: &[u8] = include_bytes!("fixtures/demo-manifest.asc");

#[test]
fn accepts_armored_rsa_signing_subkey() {
    let identity = verify_detached_signature(MANIFEST, SIGNATURE, KEY).unwrap();
    assert_eq!(identity.fingerprint.len(), 40);
    assert_ne!(identity.fingerprint, identity.signing_key);
    assert!(identity.user_id.unwrap().contains("Verify RSA Fixture"));
}

#[test]
fn accepts_binary_rsa_signature() {
    verify_detached_signature(MANIFEST, include_bytes!("fixtures/demo-manifest.sig"), KEY).unwrap();
}

#[test]
fn accepts_ed25519_signature() {
    verify_detached_signature(
        MANIFEST,
        include_bytes!("fixtures/ed25519-manifest.asc"),
        include_bytes!("fixtures/ed25519-public-key.asc"),
    )
    .unwrap();
}

#[test]
fn accepts_real_sparrow_release_manifest() {
    let identity = verify_detached_signature(
        include_bytes!("fixtures/sparrow-manifest.txt"),
        include_bytes!("fixtures/sparrow-manifest.asc"),
        include_bytes!("fixtures/sparrow-public-key.asc"),
    )
    .unwrap();
    assert_eq!(
        identity.fingerprint,
        "D4D0D3202FC06849A257B38DE94618334C674B40"
    );
}

#[test]
fn rejects_modified_manifest() {
    let mut modified = MANIFEST.to_vec();
    modified[0] ^= 1;
    assert!(verify_detached_signature(&modified, SIGNATURE, KEY).is_err());
}

#[test]
fn rejects_wrong_public_key() {
    assert!(verify_detached_signature(
        MANIFEST,
        SIGNATURE,
        include_bytes!("fixtures/ed25519-public-key.asc")
    )
    .is_err());
}

#[test]
fn rejects_weak_sha1_signature() {
    assert!(
        verify_detached_signature(MANIFEST, include_bytes!("fixtures/weak-sha1.asc"), KEY)
            .unwrap_err()
            .contains("weak hash")
    );
}

#[test]
fn rejects_signatures_in_the_future() {
    assert!(
        verify_core::verify_detached_signature_at(MANIFEST, SIGNATURE, KEY, 1_600_000_000)
            .unwrap_err()
            .contains("future")
    );
}

#[test]
fn rejects_expired_sparrow_certificate() {
    assert!(verify_core::verify_detached_signature_at(
        include_bytes!("fixtures/sparrow-manifest.txt"),
        include_bytes!("fixtures/sparrow-manifest.asc"),
        include_bytes!("fixtures/sparrow-public-key.asc"),
        2_100_000_000
    )
    .unwrap_err()
    .contains("expired"));
}

#[test]
fn checks_key_expiry_at_a_fixed_time() {
    let key = include_bytes!("fixtures/expiring-public-key.asc");
    let signature = include_bytes!("fixtures/expiring-key-manifest.asc");
    assert!(
        verify_core::verify_detached_signature_at(MANIFEST, signature, key, 1_767_225_600).is_ok()
    );
    assert!(
        verify_core::verify_detached_signature_at(MANIFEST, signature, key, 1_767_400_000)
            .unwrap_err()
            .contains("expired")
    );
}

#[test]
fn rejects_expired_signature() {
    assert!(verify_core::verify_detached_signature_at(
        MANIFEST,
        include_bytes!("fixtures/expiring-signature.asc"),
        include_bytes!("fixtures/expiring-public-key.asc"),
        1_767_400_000
    )
    .unwrap_err()
    .contains("signature has expired"));
}

#[test]
fn rejects_revoked_publisher() {
    assert!(verify_core::verify_detached_signature_at(
        MANIFEST,
        include_bytes!("fixtures/expiring-key-manifest.asc"),
        include_bytes!("fixtures/revoked-public-key.asc"),
        1_767_225_600
    )
    .unwrap_err()
    .contains("revoked"));
}

#[test]
fn rejects_1024_bit_rsa() {
    assert!(verify_detached_signature(
        MANIFEST,
        include_bytes!("fixtures/weak-rsa-manifest.asc"),
        include_bytes!("fixtures/weak-rsa-public-key.asc")
    )
    .unwrap_err()
    .contains("weak signing"));
}

#[test]
fn rejects_multiple_binary_signatures() {
    let single = include_bytes!("fixtures/demo-manifest.sig");
    let mut signatures = single.to_vec();
    signatures.extend_from_slice(single);
    assert!(verify_detached_signature(MANIFEST, &signatures, KEY)
        .unwrap_err()
        .contains("exactly one"));
}

#[test]
fn rejects_malicious_packet_lengths() {
    for packet in [
        &[0xc2, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        &[0x99, 0xff, 0xff][..],
        &[0xc6, 0xe0][..],
    ] {
        assert!(verify_detached_signature(MANIFEST, packet, KEY).is_err());
        assert!(verify_detached_signature(MANIFEST, SIGNATURE, packet).is_err());
    }
}

#[test]
fn rejects_truncated_and_empty_inputs() {
    for length in [0, 1, 8, SIGNATURE.len() / 2] {
        assert!(verify_detached_signature(MANIFEST, &SIGNATURE[..length], KEY).is_err());
    }
    for length in [0, 1, 8, KEY.len() / 2] {
        assert!(verify_detached_signature(MANIFEST, SIGNATURE, &KEY[..length]).is_err());
    }
}

#[test]
fn rejects_oversized_manifest_before_parsing() {
    let oversized = vec![0u8; MAX_MANIFEST_BYTES + 1];
    assert!(verify_detached_signature(&oversized, SIGNATURE, KEY)
        .unwrap_err()
        .contains("safety limit"));
}

#[test]
fn random_garbage_never_panics() {
    let mut state = 0x1234_5678u32;
    for length in 0..256 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        assert!(verify_detached_signature(MANIFEST, &bytes, KEY).is_err());
    }
}
