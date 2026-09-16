use std::{
    io::{Cursor, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use pgp::{
    composed::{Deserializable, DetachedSignature, SignedPublicKey},
    crypto::hash::HashAlgorithm as PgpHashAlgorithm,
    packet::{Signature, SignatureType},
    types::{KeyDetails, KeyVersion, PublicParams},
};
use rsa::traits::PublicKeyParts;

pub mod trust;

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 128 * 1024;
pub const MAX_PUBLIC_KEY_BYTES: usize = 512 * 1024;

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
    manifest: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<SignatureIdentity, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        // TODO: localize
        .map_err(|_| "Set the device clock before verifying signatures.".to_string())?
        .as_secs();
    verify_detached_signature_at(manifest, signature_bytes, public_key_bytes, now)
}

pub fn verify_detached_signature_at(
    manifest: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
    now: u64,
) -> Result<SignatureIdentity, String> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        // TODO: localize
        return Err("Checksum manifest exceeds the 256 KiB safety limit.".into());
    }
    if signature_bytes.len() > MAX_SIGNATURE_BYTES {
        // TODO: localize
        return Err("Signature exceeds the 128 KiB safety limit.".into());
    }
    if public_key_bytes.len() > MAX_PUBLIC_KEY_BYTES {
        // TODO: localize
        return Err("Public key exceeds the 512 KiB safety limit.".into());
    }

    let signature = parse_signature(signature_bytes)?;
    let key = parse_public_key(public_key_bytes)?;
    if !matches!(
        signature.signature.hash_alg(),
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
        signature.signature.typ(),
        Some(SignatureType::Binary | SignatureType::Text)
    ) {
        // TODO: localize
        return Err("Expected a detached data signature.".into());
    }
    check_key_strength(&key.primary_key)?;
    check_signature_time(&signature.signature, now)?;
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

    let primary_fingerprint = format!("{:X}", key.fingerprint());
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

    if signature.verify(&key.primary_key, manifest).is_ok() {
        if !primary_policy.key_flags().sign() {
            // TODO: localize
            return Err("The primary key is not authorized for signing.".into());
        }
        return Ok(SignatureIdentity {
            fingerprint: primary_fingerprint.clone(),
            user_id,
            signing_key: primary_fingerprint,
        });
    }
    for subkey in &key.public_subkeys {
        if subkey
            .signatures
            .iter()
            .any(|signature| signature.typ() == Some(SignatureType::SubkeyRevocation))
        {
            continue;
        }
        if signature.verify(&subkey.key, manifest).is_ok() {
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
                fingerprint: primary_fingerprint,
                user_id,
                signing_key: format!("{:X}", subkey.fingerprint()),
            });
        }
    }
    // TODO: localize
    Err("The detached signature is not valid for this manifest and key.".into())
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

fn parse_signature(bytes: &[u8]) -> Result<DetachedSignature, String> {
    parse_one(bytes, "signature")
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
