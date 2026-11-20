//! Parser for `tshark -x` text dumps (first block only: the frame bytes).

pub fn parse(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut started = false;
    for line in text.lines() {
        let Some((off, rest)) = line.split_once("  ") else {
            if started {
                break;
            }
            continue;
        };
        if off.len() < 4 || !off.chars().all(|c| c.is_ascii_hexdigit()) {
            if started {
                break;
            }
            continue;
        }
        started = true;
        // hex area is 16 * 3 chars (+1 extra gap), the ASCII column follows after two spaces
        let hex = rest.split("  ").next().unwrap_or("");
        bytes.extend(
            hex.split_whitespace()
                .filter(|b| b.len() == 2)
                .filter_map(|b| u8::from_str_radix(b, 16).ok()),
        );
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_first_block_only() {
        let t = "0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   ................\n\
                 0010  10 11                                             ..\n\
                 \n\
                 Reassembled (2 bytes):\n\
                 0000  ff ff   ..\n";
        let b = parse(t);
        assert_eq!(b.len(), 18);
        assert_eq!(b[17], 0x11);
    }

    #[test]
    fn handles_large_offsets_spaces_in_ascii_and_noise() {
        let t = "Frame header noise\n\
                 10000  de ad be ef   a  b  c\n\
                 10010  ca fe         ..\n";
        assert_eq!(parse(t), vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
    }

    #[test]
    fn empty_input() {
        assert!(parse("").is_empty());
    }
}
