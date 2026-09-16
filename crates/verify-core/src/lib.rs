use std::{
    io::{Cursor, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use pgp::{
    composed::{CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey},
    crypto::hash::HashAlgorithm as PgpHashAlgorithm,
    packet::{Signature, SignatureType},
    types::{KeyDetails, KeyVersion, PublicParams},
};
use rsa::traits::PublicKeyParts;

pub mod trust;

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 128 * 1024;
pub const MAX_PUBLIC_KEY_BYTES: usize = 512 * 1024;
pub const MAX_SIGNATURES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    pub fn digest_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub algorithm: HashAlgorithm,
    pub digest: Vec<u8>,
    pub filename: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureIdentity {
    pub fingerprint: String,
    pub user_id: Option<String>,
    pub signing_key: String,
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        // TODO: localize
        return Err("Expected an even-length hexadecimal digest.".into());
    }
    if !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        // TODO: localize
        return Err("Digest contains non-hexadecimal characters.".into());
    }

    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex is ASCII");
            // TODO: localize
            u8::from_str_radix(text, 16).map_err(|_| "Invalid hexadecimal digest.".to_string())
        })
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_expected_digest(text: &str) -> Result<Vec<u8>, String> {
    if text.len() > 1024 {
        // TODO: localize
        return Err("Expected hash exceeds the 1 KiB input limit.".into());
    }
    let digest = decode_hex(text)?;
    algorithm_for_digest(&digest)?;
    Ok(digest)
}

pub fn parse_manifest(text: &str) -> Result<Vec<ManifestEntry>, String> {
    if text.len() > MAX_MANIFEST_BYTES {
        // TODO: localize
        return Err("Checksum manifest exceeds the 256 KiB safety limit.".into());
    }

    let mut entries = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(entry) = parse_bsd_line(line)? {
            entries.push(entry);
            continue;
        }

        let split = line.find(char::is_whitespace).unwrap_or(line.len());
        let candidate = &line[..split];
        let digest = match decode_hex(candidate) {
            Ok(digest) if matches!(digest.len(), 32 | 64) => digest,
            _ => continue,
        };
        let filename = line[split..].trim_start();
        let filename = (!filename.is_empty())
            .then(|| filename.strip_prefix('*').unwrap_or(filename).to_string());
        entries.push(ManifestEntry {
            algorithm: algorithm_for_digest(&digest)?,
            digest,
            filename,
        });
    }

    if entries.is_empty() {
        // TODO: localize
        Err("No SHA-256 or SHA-512 checksums were found.".into())
    } else {
        Ok(entries)
    }
}

fn parse_bsd_line(line: &str) -> Result<Option<ManifestEntry>, String> {
    let (algorithm, rest) = if let Some(rest) = line.strip_prefix("SHA256 (") {
        (HashAlgorithm::Sha256, rest)
    } else if let Some(rest) = line.strip_prefix("SHA512 (") {
        (HashAlgorithm::Sha512, rest)
    } else {
        return Ok(None);
    };
    let Some((filename, digest_text)) = rest.split_once(") = ") else {
        // TODO: localize
        return Err("Malformed BSD checksum line.".into());
    };
    let digest = decode_hex(digest_text)?;
    if digest.len() != algorithm.digest_bytes() {
        // TODO: localize
        return Err("Checksum length does not match its algorithm.".into());
    }
    Ok(Some(ManifestEntry {
        algorithm,
        digest,
        filename: Some(filename.to_string()),
    }))
}

fn algorithm_for_digest(digest: &[u8]) -> Result<HashAlgorithm, String> {
    match digest.len() {
        32 => Ok(HashAlgorithm::Sha256),
        64 => Ok(HashAlgorithm::Sha512),
        // TODO: localize
        _ => Err("Only SHA-256 and SHA-512 are supported.".into()),
    }
}

pub fn find_manifest_entry<'a>(
    entries: &'a [ManifestEntry],
    artifact_name: &str,
) -> Result<&'a ManifestEntry, String> {
    let basename = artifact_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(artifact_name);
    let named: Vec<_> = entries
        .iter()
        .filter(|entry| {
            entry.filename.as_deref().is_some_and(|name| {
                name == artifact_name || name.rsplit(['/', '\\']).next() == Some(basename)
            })
        })
        .collect();
    match named.as_slice() {
        [entry] => Ok(entry),
        [] if entries.len() == 1 && entries[0].filename.is_none() => Ok(&entries[0]),
        // TODO: localize
        [] => Err(format!("No checksum entry matches {basename}.")),
        // TODO: localize
        _ => Err(format!("More than one checksum entry matches {basename}.")),
    }
}

pub fn digest_matches(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected
        .iter()
        .zip(actual)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

pub fn stream_bytes(
    reader: &mut impl Read,
    cancelled: impl Fn() -> bool,
    mut consume: impl FnMut(&[u8]) -> Result<(), String>,
    mut progress: impl FnMut(u64),
) -> Result<u64, String> {
    let mut buffer = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        if cancelled() {
            // TODO: localize
            return Err("Verification cancelled.".into());
        }
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            // TODO: localize
            Err(error) => {
                return Err(format!(
                    "Reading stopped. Reconnect the drive and try again: {error}"
                ))
            }
        };
        if count == 0 {
            break;
        }
        consume(&buffer[..count])?;
        total = total
            .checked_add(count as u64)
            // TODO: localize
            .ok_or_else(|| "The file size exceeds the supported range.".to_string())?;
        progress(total);
    }
    Ok(total)
}

pub fn verify_detached_signature(
    data: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<SignatureIdentity, String> {
    verify_detached_signature_at(data, signature_bytes, public_key_bytes, current_time()?)
}

pub fn verify_detached_signature_at(
    data: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
    now: u64,
) -> Result<SignatureIdentity, String> {
    if data.len() > MAX_MANIFEST_BYTES {
        // TODO: localize
        return Err("Checksum manifest exceeds the 256 KiB safety limit.".into());
    }
    verify_detached_signature_reader_at(signature_bytes, public_key_bytes, now, || {
        Ok(Cursor::new(data))
    })
}

pub fn verify_detached_signature_reader<R: Read>(
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
    open_data: impl FnMut() -> Result<R, String>,
) -> Result<SignatureIdentity, String> {
    verify_detached_signature_reader_at(
        signature_bytes,
        public_key_bytes,
        current_time()?,
        open_data,
    )
}

pub fn verify_cleartext_signature(
    message_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<(SignatureIdentity, String), String> {
    verify_cleartext_signature_at(message_bytes, public_key_bytes, current_time()?)
}

pub fn verify_cleartext_signature_at(
    message_bytes: &[u8],
    public_key_bytes: &[u8],
    now: u64,
) -> Result<(SignatureIdentity, String), String> {
    if message_bytes.len() > MAX_MANIFEST_BYTES {
        // TODO: localize
        return Err("Signed checksum file exceeds the 256 KiB safety limit.".into());
    }
    if public_key_bytes.len() > MAX_PUBLIC_KEY_BYTES {
        // TODO: localize
        return Err("Public key exceeds the 512 KiB safety limit.".into());
    }
    let text = std::str::from_utf8(message_bytes)
        // TODO: localize
        .map_err(|_| "The signed checksum file is not UTF-8 text.".to_string())?;
    let (message, _) = CleartextSignedMessage::from_string(text)
        // TODO: localize
        .map_err(|error| format!("Could not parse the signed checksum file: {error}"))?;
    if message.signatures().len() > MAX_SIGNATURES {
        // TODO: localize
        return Err(format!(
            "The signed checksum file contains more than {MAX_SIGNATURES} signatures."
        ));
    }
    let signed_text = message.signed_text();
    let key = parse_public_key(public_key_bytes)?;
    precheck_signatures(message.signatures().iter(), &key, now)?;
    let key = prepare_public_key(key, now)?;
    let identity = verify_signatures(message.signatures().iter(), &key, now, || {
        Ok(Cursor::new(signed_text.as_bytes()))
    })?;
    Ok((identity, signed_text))
}

fn current_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // TODO: localize
        .map_err(|_| "Set the device clock before verifying signatures.".to_string())
        .map(|duration| duration.as_secs())
}

fn verify_detached_signature_reader_at<R: Read>(
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
    now: u64,
    open_data: impl FnMut() -> Result<R, String>,
) -> Result<SignatureIdentity, String> {
    if signature_bytes.len() > MAX_SIGNATURE_BYTES {
        // TODO: localize
        return Err("Signature exceeds the 128 KiB safety limit.".into());
    }
    if public_key_bytes.len() > MAX_PUBLIC_KEY_BYTES {
        // TODO: localize
        return Err("Public key exceeds the 512 KiB safety limit.".into());
    }

    let signatures = parse_signatures(signature_bytes)?;
    let key = parse_public_key(public_key_bytes)?;
    precheck_signatures(
        signatures.iter().map(|signature| &signature.signature),
        &key,
        now,
    )?;
    let key = prepare_public_key(key, now)?;
    verify_signatures(
        signatures.iter().map(|signature| &signature.signature),
        &key,
        now,
        open_data,
    )
}

struct PreparedPublicKey {
    key: SignedPublicKey,
    fingerprint: String,
    user_id: Option<String>,
    primary_can_sign: bool,
}

fn prepare_public_key(key: SignedPublicKey, now: u64) -> Result<PreparedPublicKey, String> {
    check_key_strength(&key.primary_key)?;
    key.verify_bindings()
        // TODO: localize
        .map_err(|error| format!("Public key certificate is invalid: {error}"))?;
    if !key.details.revocation_signatures.is_empty() {
        // TODO: localize
        return Err("This publisher key has been revoked.".into());
    }
    let primary_policy = key
        .details
        .direct_signatures
        .iter()
        .chain(
            key.details
                .users
                .iter()
                .flat_map(|user| user.signatures.iter()),
        )
        .filter(|signature| {
            matches!(
                signature.typ(),
                Some(
                    SignatureType::Key
                        | SignatureType::CertGeneric
                        | SignatureType::CertPersona
                        | SignatureType::CertCasual
                        | SignatureType::CertPositive
                )
            )
        })
        .filter(|signature| {
            signature
                .created()
                .is_some_and(|created| u64::from(created.as_secs()) <= now)
        })
        .max_by_key(|signature| signature.created());
    let Some(primary_policy) = primary_policy else {
        // TODO: localize
        return Err(
            "The publisher key has no current self-certification. Check the device clock.".into(),
        );
    };
    check_key_expiration(&key.primary_key, primary_policy, now)?;

    let fingerprint = format!("{:X}", key.fingerprint());
    let user_id = key
        .details
        .users
        .iter()
        .find(|user| {
            user.signatures
                .iter()
                .max_by_key(|signature| signature.created())
                .is_some_and(|signature| signature.typ() != Some(SignatureType::CertRevocation))
        })
        .and_then(|user| std::str::from_utf8(user.id.id()).ok().map(str::to_string));

    let primary_can_sign = primary_policy.key_flags().sign();
    Ok(PreparedPublicKey {
        key,
        fingerprint,
        user_id,
        primary_can_sign,
    })
}

fn precheck_signatures<'a>(
    signatures: impl IntoIterator<Item = &'a Signature>,
    key: &SignedPublicKey,
    now: u64,
) -> Result<(), String> {
    let mut matching = false;
    let mut error = None;
    for signature in signatures {
        let matches = signature_matches_key(signature, &key.primary_key)
            || key
                .public_subkeys
                .iter()
                .any(|subkey| signature_matches_key(signature, &subkey.key));
        if !matches {
            continue;
        }
        matching = true;
        match check_data_signature(signature, now) {
            Ok(()) => return Ok(()),
            Err(candidate_error) => error = Some(candidate_error),
        }
    }
    if let Some(error) = error {
        return Err(error);
    }
    if matching {
        Ok(())
    } else {
        // TODO: localize
        Err("No signature from this publisher key was found.".into())
    }
}

fn verify_signatures<'a, R: Read>(
    signatures: impl IntoIterator<Item = &'a Signature>,
    prepared: &PreparedPublicKey,
    now: u64,
    mut open_data: impl FnMut() -> Result<R, String>,
) -> Result<SignatureIdentity, String> {
    let signatures = signatures.into_iter().collect::<Vec<_>>();
    if signatures.is_empty() {
        // TODO: localize
        return Err("No signature found.".into());
    }

    let mut policy_error = None;
    for signature in signatures {
        let primary_matches = signature_matches_key(signature, &prepared.key.primary_key);
        let matching_subkeys = prepared
            .key
            .public_subkeys
            .iter()
            .filter(|subkey| signature_matches_key(signature, &subkey.key))
            .collect::<Vec<_>>();
        if !primary_matches && matching_subkeys.is_empty() {
            continue;
        }

        if let Err(error) = check_data_signature(signature, now) {
            policy_error = Some(error);
            continue;
        }

        if primary_matches
            && signature
                .verify(&prepared.key.primary_key, open_data()?)
                .is_ok()
        {
            if !prepared.primary_can_sign {
                // TODO: localize
                return Err("The primary key is not authorized for signing.".into());
            }
            return Ok(SignatureIdentity {
                fingerprint: prepared.fingerprint.clone(),
                user_id: prepared.user_id.clone(),
                signing_key: prepared.fingerprint.clone(),
            });
        }

        for subkey in matching_subkeys {
            if subkey
                .signatures
                .iter()
                .any(|signature| signature.typ() == Some(SignatureType::SubkeyRevocation))
            {
                continue;
            }
            if signature.verify(&subkey.key, open_data()?).is_err() {
                continue;
            }
            check_key_strength(&subkey.key)?;
            let policy = subkey
                .signatures
                .iter()
                .filter(|signature| signature.typ() == Some(SignatureType::SubkeyBinding))
                .filter(|signature| {
                    signature
                        .created()
                        .is_some_and(|created| u64::from(created.as_secs()) <= now)
                })
                .max_by_key(|signature| signature.created())
                // TODO: localize
                .ok_or_else(|| "The signing subkey has no current binding.".to_string())?;
            if !policy.key_flags().sign() {
                // TODO: localize
                return Err("This subkey is not authorized for signing.".into());
            }
            check_key_expiration(&subkey.key, policy, now)?;
            return Ok(SignatureIdentity {
                fingerprint: prepared.fingerprint.clone(),
                user_id: prepared.user_id.clone(),
                signing_key: format!("{:X}", subkey.fingerprint()),
            });
        }
    }

    if let Some(error) = policy_error {
        return Err(error);
    }
    // TODO: localize
    Err("No valid signature from this publisher key was found.".into())
}

fn check_data_signature(signature: &Signature, now: u64) -> Result<(), String> {
    if !matches!(
        signature.hash_alg(),
        Some(
            PgpHashAlgorithm::Sha256
                | PgpHashAlgorithm::Sha384
                | PgpHashAlgorithm::Sha512
                | PgpHashAlgorithm::Sha3_256
                | PgpHashAlgorithm::Sha3_512
        )
    ) {
        // TODO: localize
        return Err("The signature uses an unsupported or weak hash algorithm.".into());
    }
    if !matches!(
        signature.typ(),
        Some(SignatureType::Binary | SignatureType::Text)
    ) {
        // TODO: localize
        return Err("Expected a detached data signature.".into());
    }
    check_signature_time(signature, now)
}

fn signature_matches_key(signature: &Signature, key: &impl KeyDetails) -> bool {
    let issuer_ids = signature.issuer_key_id();
    let issuer_fingerprints = signature.issuer_fingerprint();
    (issuer_ids.is_empty() && issuer_fingerprints.is_empty())
        || issuer_ids
            .iter()
            .any(|issuer| *issuer == &key.legacy_key_id())
        || issuer_fingerprints
            .iter()
            .any(|issuer| *issuer == &key.fingerprint())
}

fn check_signature_time(signature: &Signature, now: u64) -> Result<(), String> {
    let created = signature
        .created()
        // TODO: localize
        .ok_or_else(|| "The signature has no authenticated creation time.".to_string())?;
    let created = u64::from(created.as_secs());
    if created > now.saturating_add(300) {
        // TODO: localize
        return Err("The signature is dated in the future. Check the device clock.".into());
    }
    if signature
        .signature_expiration_time()
        .is_some_and(|duration| {
            duration.as_secs() > 0 && created.saturating_add(u64::from(duration.as_secs())) <= now
        })
    {
        // TODO: localize
        return Err("The signature has expired.".into());
    }
    Ok(())
}

fn check_key_expiration(key: &impl KeyDetails, policy: &Signature, now: u64) -> Result<(), String> {
    if u64::from(key.created_at().as_secs()) > now.saturating_add(300) {
        // TODO: localize
        return Err("The publisher key is dated in the future. Check the device clock.".into());
    }
    check_signature_time(policy, now)?;
    if policy.key_expiration_time().is_some_and(|duration| {
        duration.as_secs() > 0
            && u64::from(key.created_at().as_secs()).saturating_add(u64::from(duration.as_secs()))
                <= now
    }) {
        // TODO: localize
        return Err(
            "The publisher key or signing subkey has expired. Import an updated public key.".into(),
        );
    }
    Ok(())
}

fn check_key_strength(key: &impl KeyDetails) -> Result<(), String> {
    if !matches!(key.version(), KeyVersion::V4 | KeyVersion::V6) {
        // TODO: localize
        return Err("Only modern OpenPGP v4 and v6 keys are supported.".into());
    }
    match key.public_params() {
        PublicParams::RSA(params) if params.key.n().bits() >= 2048 => Ok(()),
        PublicParams::ECDSA(_)
        | PublicParams::EdDSALegacy(_)
        | PublicParams::Ed25519(_)
        | PublicParams::Ed448(_) => Ok(()),
        // TODO: localize
        _ => Err("The publisher key uses an unsupported or weak signing algorithm.".into()),
    }
}

fn parse_signatures(bytes: &[u8]) -> Result<Vec<DetachedSignature>, String> {
    const BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
    const END: &str = "-----END PGP SIGNATURE-----";

    let mut signatures = Vec::new();
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'-')
    {
        let text = std::str::from_utf8(bytes)
            // TODO: localize
            .map_err(|_| "The armored signature is not UTF-8 text.".to_string())?;
        let mut remaining = text;
        while !remaining.trim().is_empty() {
            let start = remaining
                .find(BEGIN)
                // TODO: localize
                .ok_or_else(|| "Could not find an OpenPGP signature block.".to_string())?;
            if !remaining[..start].trim().is_empty() {
                // TODO: localize
                return Err("Unexpected text appears before an OpenPGP signature.".into());
            }
            let after_start = &remaining[start + BEGIN.len()..];
            let end = after_start
                .find(END)
                // TODO: localize
                .ok_or_else(|| "The OpenPGP signature block is incomplete.".to_string())?
                + start
                + BEGIN.len()
                + END.len();
            let block = &remaining[start..end];
            let (objects, _) = DetachedSignature::from_armor_many(Cursor::new(block.as_bytes()))
                // TODO: localize
                .map_err(|error| format!("Could not parse signature: {error}"))?;
            collect_signatures(objects, &mut signatures)?;
            remaining = &remaining[end..];
        }
    } else {
        let objects = DetachedSignature::from_bytes_many(Cursor::new(bytes))
            // TODO: localize
            .map_err(|error| format!("Could not parse signature: {error}"))?;
        collect_signatures(objects, &mut signatures)?;
    }

    if signatures.is_empty() {
        // TODO: localize
        return Err("No signature found.".into());
    }
    Ok(signatures)
}

fn collect_signatures<'a>(
    objects: impl Iterator<Item = pgp::errors::Result<DetachedSignature>> + 'a,
    signatures: &mut Vec<DetachedSignature>,
) -> Result<(), String> {
    for object in objects {
        if signatures.len() >= MAX_SIGNATURES {
            // TODO: localize
            return Err(format!(
                "Choose a file containing no more than {MAX_SIGNATURES} signatures."
            ));
        }
        signatures.push(
            object
                // TODO: localize
                .map_err(|error| format!("Could not parse signature: {error}"))?,
        );
    }
    Ok(())
}

fn parse_public_key(bytes: &[u8]) -> Result<SignedPublicKey, String> {
    parse_one(bytes, "public key")
}

fn parse_one<T: Deserializable>(bytes: &[u8], kind: &str) -> Result<T, String> {
    let (mut objects, _) = T::from_reader_many(Cursor::new(bytes))
        // TODO: localize
        .map_err(|error| format!("Could not parse {kind}: {error}"))?;
    let object = objects
        .next()
        // TODO: localize
        .ok_or_else(|| format!("No {kind} found."))?
        // TODO: localize
        .map_err(|error| format!("Could not parse {kind}: {error}"))?;
    if objects.next().is_some() {
        // TODO: localize
        return Err(format!("Choose a file containing exactly one {kind}."));
    }
    Ok(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gnu_and_bsd_manifests() {
        let sha256 = "00".repeat(32);
        let sha512 = "11".repeat(64);
        let manifest = format!("{sha256}  release.app\nSHA512 (firmware.bin) = {sha512}\n");
        let entries = parse_manifest(&manifest).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename.as_deref(), Some("release.app"));
        assert_eq!(entries[1].algorithm, HashAlgorithm::Sha512);
    }

    #[test]
    fn ignores_comments_and_unrelated_lines() {
        let sha256 = "ab".repeat(32);
        let entries =
            parse_manifest(&format!("# release checksums\nnotes\n{sha256} *app.bin\n")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename.as_deref(), Some("app.bin"));
    }

    #[test]
    fn matches_a_manifest_entry_by_basename() {
        let entries = parse_manifest(&format!("{}  dist/release.app", "10".repeat(32))).unwrap();
        assert!(find_manifest_entry(&entries, "/usb/release.app").is_ok());
        assert!(find_manifest_entry(&entries, "/usb/other.app").is_err());
    }

    #[test]
    fn compares_digests_without_an_early_exit() {
        assert!(digest_matches(&[1, 2, 3], &[1, 2, 3]));
        assert!(!digest_matches(&[1, 2, 3], &[1, 2, 4]));
        assert!(!digest_matches(&[1], &[1, 2]));
    }

    #[test]
    fn rejects_legacy_and_malformed_digests() {
        assert!(parse_manifest(&format!("{}  old.bin", "ab".repeat(20))).is_err());
        assert!(decode_hex("not-a-hash").is_err());
    }
}
