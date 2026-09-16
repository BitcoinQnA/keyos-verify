use sha2::{Digest, Sha256, Sha512};
use std::{fs::File, path::Path};
use verify_core::{
    digest_matches, find_manifest_entry, parse_manifest, stream_bytes, verify_detached_signature,
};

fn main() {
    let paths = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(paths.len(), 4, "artifact manifest signature public-key");
    let manifest = std::fs::read(&paths[1]).unwrap();
    let identity = verify_detached_signature(
        &manifest,
        &std::fs::read(&paths[2]).unwrap(),
        &std::fs::read(&paths[3]).unwrap(),
    )
    .unwrap();
    let entries = parse_manifest(std::str::from_utf8(&manifest).unwrap()).unwrap();
    let entry = find_manifest_entry(
        &entries,
        Path::new(&paths[0]).file_name().unwrap().to_str().unwrap(),
    )
    .unwrap();
    let mut file = File::open(&paths[0]).unwrap();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let bytes = stream_bytes(
        &mut file,
        || false,
        |chunk| {
            sha256.update(chunk);
            sha512.update(chunk);
            Ok(())
        },
        |_| {},
    )
    .unwrap();
    let actual = match entry.algorithm {
        verify_core::HashAlgorithm::Sha256 => sha256.finalize().to_vec(),
        verify_core::HashAlgorithm::Sha512 => sha512.finalize().to_vec(),
    };
    assert!(
        digest_matches(&entry.digest, &actual),
        "artifact checksum mismatch"
    );
    println!(
        "Verified {bytes} bytes against signed manifest; publisher fingerprint {}",
        identity.fingerprint
    );
}
