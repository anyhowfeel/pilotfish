//! Allocation-free case-insensitive substring search shared by every filter box.

use memchr::memchr2;

/// True when `hay` contains `needle`, ignoring case. `needle` must already be lowercase.
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.is_ascii() {
        contains_ascii(hay.as_bytes(), needle.as_bytes())
    } else {
        hay.to_lowercase().contains(needle)
    }
}

fn contains_ascii(hay: &[u8], needle: &[u8]) -> bool {
    let (first, rest) = (needle[0], &needle[1..]);
    let upper = first.to_ascii_uppercase();
    let mut from = 0;
    while hay.len() - from > rest.len() {
        let Some(at) = memchr2(first, upper, &hay[from..hay.len() - rest.len()]) else {
            return false;
        };
        let tail = from + at + 1;
        if hay[tail..tail + rest.len()].eq_ignore_ascii_case(rest) {
            return true;
        }
        from = tail;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::contains_ci;

    #[test]
    fn matches_any_case_and_position() {
        assert!(contains_ci("Example.COM", "example"));
        assert!(contains_ci("Example.COM", "com"));
        assert!(contains_ci("Example.COM", "e.c"));
        assert!(contains_ci("abc", "abc"));
        assert!(contains_ci("anything", ""));
    }

    #[test]
    fn rejects_misses_and_short_haystacks() {
        assert!(!contains_ci("abc", "abcd"));
        assert!(!contains_ci("", "a"));
        assert!(!contains_ci("aaaa", "aab"));
        assert!(!contains_ci("Example", "xyz"));
    }

    #[test]
    fn finds_match_after_false_first_byte_hits() {
        assert!(contains_ci("aaab", "aab"));
        assert!(contains_ci("xAaAb", "aab"));
    }

    #[test]
    fn non_ascii_needle_uses_unicode_folding() {
        assert!(contains_ci("Crème Brûlée", "brûlée"));
        assert!(!contains_ci("Creme", "crème"));
    }
}
