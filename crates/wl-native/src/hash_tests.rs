use super::*;

const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn hash_of(bytes: &[u8]) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("f.bin");
    std::fs::write(&path, bytes).expect("write");
    sha256_hex(&path).expect("hash")
}

#[test]
fn empty_file() {
    assert_eq!(hash_of(b""), EMPTY);
}

#[test]
fn known_vector() {
    assert_eq!(hash_of(b"abc"), ABC);
}

#[test]
fn output_is_lowercase_hex_of_64_chars() {
    let h = hash_of(b"anything");
    assert_eq!(h.len(), 64);
    assert!(
        h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

#[test]
fn file_larger_than_one_chunk_matches_one_shot_digest() {
    let bytes: Vec<u8> = (0..(CHUNK * 3 + 17)).map(|i| (i % 251) as u8).collect();
    let expected: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hash_of(&bytes), expected);
}

#[test]
fn chunk_boundary_sizes() {
    for len in [CHUNK - 1, CHUNK, CHUNK + 1] {
        let bytes = vec![0x5a; len];
        let expected: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hash_of(&bytes), expected, "len {len}");
    }
}

#[test]
fn missing_file_is_an_error_naming_the_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("absent.pcap");
    let err = sha256_hex(&path).expect_err("missing");
    assert!(matches!(err, CaptureError::Other(ref m) if m.contains("absent.pcap")));
}

#[test]
fn directory_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(sha256_hex(dir.path()).is_err());
}
