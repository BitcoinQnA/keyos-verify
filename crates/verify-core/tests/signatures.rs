use std::io::Cursor;

use pgp::{
    composed::{CleartextSignedMessage, KeyType, SecretKeyParamsBuilder},
    crypto::{hash::HashAlgorithm as PgpHashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::Password,
};
use rand::thread_rng;
use smallvec::smallvec;
use verify_core::{
    verify_cleartext_signature, verify_detached_signature, verify_detached_signature_reader,
    MAX_MANIFEST_BYTES,
};

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
fn accepts_a_direct_signature_over_a_streamed_file() {
    let identity =
        verify_detached_signature_reader(SIGNATURE, KEY, || Ok(Cursor::new(MANIFEST))).unwrap();
    assert!(identity.user_id.unwrap().contains("Verify RSA Fixture"));
}

#[test]
fn accepts_a_clear_signed_checksum_manifest() {
    let (message, public_key) = clear_signed_manifest();
    let (identity, signed_text) =
        verify_cleartext_signature(message.as_bytes(), public_key.as_bytes()).unwrap();
    assert!(identity.user_id.unwrap().contains("Cleartext Fixture"));
    assert_eq!(
        verify_core::parse_manifest(&signed_text).unwrap()[0]
            .filename
            .as_deref(),
        Some("demo-release.txt")
    );
}

#[test]
fn rejects_a_modified_clear_signed_manifest() {
    let (message, public_key) = clear_signed_manifest();
    let modified = message.replacen("demo-release.txt", "other-release.txt", 1);
    assert!(verify_cleartext_signature(modified.as_bytes(), public_key.as_bytes()).is_err());
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
    let error = verify_core::verify_detached_signature_at(MANIFEST, SIGNATURE, KEY, 1_600_000_000)
        .unwrap_err();
    assert!(error.contains("future"), "{error}");
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
    let error = verify_core::verify_detached_signature_at(
        MANIFEST,
        include_bytes!("fixtures/expiring-signature.asc"),
        include_bytes!("fixtures/expiring-public-key.asc"),
        1_767_400_000,
    )
    .unwrap_err();
    assert!(error.contains("signature has expired"), "{error}");
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
fn accepts_multiple_binary_signatures() {
    let single = include_bytes!("fixtures/demo-manifest.sig");
    let mut signatures = single.to_vec();
    signatures.extend_from_slice(single);
    verify_detached_signature(MANIFEST, &signatures, KEY).unwrap();
}

#[test]
fn accepts_multiple_armored_signature_blocks() {
    let single = include_bytes!("fixtures/demo-manifest.asc");
    let mut signatures = single.to_vec();
    signatures.extend_from_slice(b"\n");
    signatures.extend_from_slice(single);
    verify_detached_signature(MANIFEST, &signatures, KEY).unwrap();
}

#[test]
fn finds_the_selected_key_later_in_a_signature_bundle() {
    let mut signatures = include_bytes!("fixtures/ed25519-manifest.asc").to_vec();
    signatures.extend_from_slice(b"\n");
    signatures.extend_from_slice(SIGNATURE);
    let identity = verify_detached_signature(MANIFEST, &signatures, KEY).unwrap();
    assert!(identity.user_id.unwrap().contains("Verify RSA Fixture"));
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

fn clear_signed_manifest() -> (String, String) {
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Cleartext Fixture <cleartext@example.invalid>".into())
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![PgpHashAlgorithm::Sha256])
        .preferred_compression_algorithms(smallvec![]);
    let secret = params.build().unwrap().generate(thread_rng()).unwrap();
    let public = secret.to_public_key();
    let message = CleartextSignedMessage::sign(
        thread_rng(),
        std::str::from_utf8(MANIFEST).unwrap(),
        &secret.primary_key,
        &Password::empty(),
    )
    .unwrap();
    (
        message.to_armored_string(None.into()).unwrap(),
        public.to_armored_string(None.into()).unwrap(),
    )
}
