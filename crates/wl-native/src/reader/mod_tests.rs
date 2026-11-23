use std::io::{Cursor, Read};

use crate::test_util::{Frame, PcapStyle, pcap_bytes, pcapng_bytes, sample_frames, write_pcap};

use super::*;

/// Everything a source yields: the packets, and the error that ended it if any.
pub struct Drained {
    pub packets: Vec<(PacketMeta, Vec<u8>)>,
    pub error: Option<ReadError>,
}

const MAX_PACKETS: usize = 5_000_000;

pub fn drain(source: &mut dyn PacketSource) -> Drained {
    let mut packets = Vec::new();
    let mut data = vec![0xee; 7];
    loop {
        match source.next_packet(&mut data) {
            Ok(Some(meta)) => packets.push((meta, data.clone())),
            Ok(None) => {
                return Drained {
                    packets,
                    error: None,
                };
            }
            Err(e) => {
                let again = source.next_packet(&mut data);
                assert!(matches!(again, Ok(None)), "source not fused after {e}");
                return Drained {
                    packets,
                    error: Some(e),
                };
            }
        }
        assert!(packets.len() < MAX_PACKETS, "source does not terminate");
    }
}

pub fn drain_bytes(bytes: Vec<u8>) -> Result<Drained, ReadError> {
    let mut source = from_reader(Cursor::new(bytes))?;
    Ok(drain(source.as_mut()))
}

#[test]
fn open_detects_pcap_and_pcapng_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let frames = sample_frames();
    let a = dir.path().join("a.pcap");
    write_pcap(&a, &frames, PcapStyle::default());
    let b = dir.path().join("b.pcapng");
    std::fs::write(&b, pcapng_bytes(&frames)).expect("write");
    for path in [a, b] {
        let mut source = open(&path).expect("open");
        let got = drain(source.as_mut());
        assert!(got.error.is_none());
        assert_eq!(got.packets.len(), frames.len());
        for (i, (meta, data)) in got.packets.iter().enumerate() {
            assert_eq!(meta.no, i as u64 + 1);
            assert_eq!(*data, frames[i].data);
            assert!((meta.epoch - frames[i].epoch).abs() < 1e-6);
        }
    }
}

#[test]
fn missing_file_is_an_io_error_naming_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = open(&dir.path().join("nope.pcap")).err().expect("error");
    assert!(matches!(err, ReadError::Io(ref m) if m.contains("nope.pcap")));
}

#[test]
fn files_that_are_not_captures_are_unknown() {
    let cases: [&[u8]; 6] = [
        b"",
        b"\xd4",
        b"\xd4\xc3\xb2",
        b"GET / HTTP/1.1\r\n",
        &[0; 64],
        b"\x7fELF\x02\x01\x01\x00",
    ];
    for bytes in cases {
        let err = drain_bytes(bytes.to_vec()).err().expect("error");
        assert_eq!(err, ReadError::UnknownFormat, "{bytes:?}");
    }
}

#[test]
fn a_magic_number_alone_is_a_damaged_file() {
    for magic in [[0xd4, 0xc3, 0xb2, 0xa1], [0x0a, 0x0d, 0x0d, 0x0a]] {
        let err = drain_bytes(magic.to_vec()).err().expect("error");
        assert!(matches!(err, ReadError::Truncated(_)), "{err:?}");
    }
}

#[test]
fn one_byte_reads_give_the_same_packets() {
    struct Dribble(Cursor<Vec<u8>>);
    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(1);
            self.0.read(&mut buf[..n])
        }
    }
    for bytes in [
        pcap_bytes(&sample_frames(), PcapStyle::default()),
        pcapng_bytes(&sample_frames()),
    ] {
        let whole = drain_bytes(bytes.clone()).expect("whole");
        let mut source = from_reader(Dribble(Cursor::new(bytes))).expect("dribble");
        let slow = drain(source.as_mut());
        assert!(slow.error.is_none());
        assert_eq!(slow.packets, whole.packets);
        assert_eq!(slow.packets.len(), 8);
    }
}

#[test]
fn an_io_error_midway_returns_earlier_packets_then_io() {
    struct Fails {
        good: Cursor<Vec<u8>>,
    }
    impl Read for Fails {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.good.read(buf)? {
                0 => Err(std::io::Error::other("disk gone")),
                n => Ok(n),
            }
        }
    }
    let frames: Vec<Frame> = sample_frames();
    let bytes = pcap_bytes(&frames, PcapStyle::default());
    let mut source = from_reader(Fails {
        good: Cursor::new(bytes),
    })
    .expect("open");
    let got = drain(source.as_mut());
    assert_eq!(got.packets.len(), 8);
    assert!(matches!(got.error, Some(ReadError::Io(ref m)) if m.contains("disk gone")));
}

#[test]
fn directory_is_not_a_capture() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(open(dir.path()).is_err());
}

#[test]
fn link_codes_map_to_the_named_types() {
    use super::convert::link_type;
    let table = [
        (1, LinkType::Ethernet),
        (0, LinkType::Null),
        (101, LinkType::RawIp),
        (12, LinkType::RawIp),
        (14, LinkType::RawIp),
        (113, LinkType::LinuxSll),
        (276, LinkType::LinuxSll2),
        (127, LinkType::Other(127)),
        (228, LinkType::Other(228)),
    ];
    for (code, want) in table {
        assert_eq!(link_type(code), want, "code {code}");
    }
}

#[test]
fn epoch_splits_integer_ticks_before_converting() {
    use super::convert::epoch_from_ticks;
    assert_eq!(epoch_from_ticks(1_500_000, 1_000_000), 1.5);
    assert_eq!(epoch_from_ticks(u64::MAX, 1), u64::MAX as f64);
    let ns = epoch_from_ticks(1_700_000_000_123_456_789, 1_000_000_000);
    assert!((ns - 1_700_000_000.123_456_8).abs() < 5e-7);
}
