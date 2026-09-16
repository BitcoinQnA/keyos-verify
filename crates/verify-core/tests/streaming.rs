use sha2::{Digest, Sha256, Sha512};
use std::{
    cell::Cell,
    io::{self, Cursor, Read},
};
use verify_core::{encode_hex, stream_bytes};

fn hash256(bytes: &[u8]) -> (String, u64) {
    let mut hash = Sha256::new();
    let total = stream_bytes(
        &mut Cursor::new(bytes),
        || false,
        |chunk| {
            hash.update(chunk);
            Ok(())
        },
        |_| {},
    )
    .unwrap();
    (encode_hex(&hash.finalize()), total)
}

#[test]
fn known_sha256_vectors() {
    assert_eq!(
        hash256(b"").0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hash256(b"abc").0,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hash256(&vec![b'a'; 1_000_000]).0,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn known_sha512_vector() {
    let mut hash = Sha512::new();
    stream_bytes(
        &mut Cursor::new(b"abc"),
        || false,
        |chunk| {
            hash.update(chunk);
            Ok(())
        },
        |_| {},
    )
    .unwrap();
    assert_eq!(encode_hex(&hash.finalize()), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

#[test]
fn chunk_boundaries_match_one_shot_hashes() {
    for length in [
        1, 63, 64, 65, 127, 128, 129, 32767, 32768, 32769, 65536, 1_048_577,
    ] {
        let data: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
        let (digest, total) = hash256(&data);
        assert_eq!(total, length as u64);
        assert_eq!(digest, encode_hex(&Sha256::digest(&data)));
    }
}

#[test]
fn reports_progress_and_cancels_before_next_read() {
    let processed = Cell::new(0u64);
    let result = stream_bytes(
        &mut Cursor::new(vec![0u8; 100_000]),
        || processed.get() > 0,
        |_| Ok(()),
        |total| processed.set(total),
    );
    assert!(result.unwrap_err().contains("cancelled"));
    assert_eq!(processed.get(), 32 * 1024);
}

struct FaultyReader {
    reads: usize,
}
impl Read for FaultyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        match self.reads {
            1 => Err(io::ErrorKind::Interrupted.into()),
            2 => {
                buffer[0] = 42;
                Ok(1)
            }
            _ => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }
}

#[test]
fn retries_interrupted_reads_but_propagates_io_failure() {
    let mut read = FaultyReader { reads: 0 };
    let mut consumed = Vec::new();
    let result = stream_bytes(
        &mut read,
        || false,
        |chunk| {
            consumed.extend_from_slice(chunk);
            Ok(())
        },
        |_| {},
    );
    assert!(result.unwrap_err().contains("Reading stopped"));
    assert_eq!(consumed, vec![42]);
}

#[test]
fn propagates_hash_engine_failure() {
    let result = stream_bytes(
        &mut Cursor::new(b"abc"),
        || false,
        |_| Err("engine failed".into()),
        |_| {},
    );
    assert_eq!(result.unwrap_err(), "engine failed");
}
