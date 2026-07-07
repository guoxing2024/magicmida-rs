//! Byte-pattern matching engine used by the unpacker to locate Themida stubs.
//!
//! Corresponds to `Utils.pas` `FindDynamic` / `FindStatic`.

use crate::error::DisasmError;

/// A byte pattern that supports wildcards (`??`).
///
/// Parsed from strings like `"8B 44 24 04 ?? ?? ?? ?? 50 E8"`,
/// where `??` means "any byte".
///
/// # Examples
///
/// ```
/// use mida_disasm::BytePattern;
///
/// let pat = BytePattern::parse("8B 44 ?? ?? 24 04").unwrap();
/// let data = [0x8B, 0x44, 0xAA, 0xBB, 0x24, 0x04];
/// assert_eq!(pat.find(&data), Some(0));
/// ```
#[derive(Debug, Clone)]
pub struct BytePattern {
    /// The pattern bytes. `None` represents a wildcard (`??`).
    bytes: Vec<Option<u8>>,
}

impl BytePattern {
    /// Parse a pattern string like `"8B 44 24 04 ?? ?? ?? ?? 50 E8"`.
    ///
    /// - Bytes are separated by whitespace.
    /// - `??` is a wildcard that matches any byte.
    /// - Each non-wildcard entry must be exactly two hex digits.
    pub fn parse(s: &str) -> Result<Self, DisasmError> {
        let mut bytes = Vec::new();

        for token in s.split_whitespace() {
            if token.eq_ignore_ascii_case("??") || token.eq_ignore_ascii_case("?") {
                bytes.push(None);
            } else if token.len() == 2 {
                let byte =
                    u8::from_str_radix(token, 16).map_err(|_| DisasmError::InvalidHex(token.to_string()))?;
                bytes.push(Some(byte));
            } else {
                return Err(DisasmError::InvalidPattern(format!(
                    "token '{}' is not a valid byte or wildcard",
                    token
                )));
            }
        }

        if bytes.is_empty() {
            return Err(DisasmError::InvalidPattern(
                "pattern must contain at least one token".to_string(),
            ));
        }

        Ok(Self { bytes })
    }

    /// Returns the number of bytes in the pattern (including wildcards).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the pattern contains no bytes (including wildcards).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Find the first occurrence of the pattern in `data`.
    ///
    /// Returns the byte offset of the match, or `None` if not found.
    /// This corresponds to `Utils.pas` `FindDynamic`.
    pub fn find(&self, data: &[u8]) -> Option<usize> {
        self.find_from(data, 0)
    }

    /// Find all occurrences of the pattern in `data`.
    ///
    /// Returns a vector of byte offsets for every match found.
    /// Non-overlapping; after a match the search resumes one byte past the match start.
    pub fn find_all(&self, data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let mut cursor = 0;

        while let Some(offset) = self.find_from(data, cursor) {
            results.push(offset);
            // Advance one byte past the current match to find overlapping / subsequent matches.
            cursor = offset + 1;
        }

        results
    }

    /// Find the first occurrence starting at or after `start`.
    ///
    /// Returns the byte offset of the match, or `None` if not found.
    pub fn find_from(&self, data: &[u8], start: usize) -> Option<usize> {
        let plen = self.bytes.len();
        if plen == 0 || data.len() < plen {
            return None;
        }

        let end = data.len().saturating_sub(plen);
        let mut i = start;

        while i <= end {
            if self.matches_at(data, i) {
                return Some(i);
            }
            i += 1;
        }

        None
    }

    /// Check whether the pattern matches `data` at position `offset`.
    fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        for (j, pat_byte) in self.bytes.iter().enumerate() {
            if let Some(expected) = pat_byte {
                if data[offset + j] != *expected {
                    return false;
                }
            }
            // None (wildcard) always matches.
        }
        true
    }
}

/// Convenience: find the first dynamic (wildcard-capable) pattern match in `data`.
///
/// Corresponds to `Utils.pas` `FindDynamic`.
///
/// # Examples
///
/// ```
/// use mida_disasm::find_dynamic;
///
/// let data = [0x8B, 0x44, 0xAA, 0xBB, 0x24, 0x04];
/// assert_eq!(find_dynamic(&data, "8B 44 ?? ?? 24 04"), Some(0));
/// ```
pub fn find_dynamic(data: &[u8], pattern: &str) -> Option<usize> {
    BytePattern::parse(pattern).ok()?.find(data)
}

/// Convenience: find the first fixed (no wildcard) pattern match in `data`.
///
/// Corresponds to `Utils.pas` `FindStatic`.
///
/// # Examples
///
/// ```
/// use mida_disasm::find_static;
///
/// let data = [0x8B, 0x44, 0x24, 0x04];
/// assert_eq!(find_static(&data, "8B 44 24 04"), Some(0));
/// ```
pub fn find_static(data: &[u8], pattern: &str) -> Option<usize> {
    let bytes: Vec<u8> = pattern
        .split_whitespace()
        .map(|t| u8::from_str_radix(t, 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    if bytes.is_empty() || data.len() < bytes.len() {
        return None;
    }

    let end = data.len() - bytes.len();
    for i in 0..=end {
        if data[i..i + bytes.len()] == bytes[..] {
            return Some(i);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_pattern() {
        let pat = BytePattern::parse("8B 44 24 04").unwrap();
        assert_eq!(pat.len(), 4);
    }

    #[test]
    fn parse_pattern_with_wildcards() {
        let pat = BytePattern::parse("8B ?? 24 ?? ?? 50").unwrap();
        assert_eq!(pat.len(), 6);
    }

    #[test]
    fn parse_single_question_mark_wildcard() {
        // Also accept single `?` as wildcard
        let pat = BytePattern::parse("8B ? 24").unwrap();
        assert_eq!(pat.len(), 3);
    }

    #[test]
    fn parse_empty_pattern() {
        assert!(BytePattern::parse("").is_err());
    }

    #[test]
    fn parse_invalid_hex() {
        assert!(BytePattern::parse("8B GG").is_err());
    }

    #[test]
    fn exact_match() {
        let data = [0x8B, 0x44, 0x24, 0x04];
        let pat = BytePattern::parse("8B 44 24 04").unwrap();
        assert_eq!(pat.find(&data), Some(0));
    }

    #[test]
    fn wildcard_match() {
        let data = [0x8B, 0x44, 0xAA, 0xBB, 0x24, 0x04];
        let pat = BytePattern::parse("8B 44 ?? ?? 24 04").unwrap();
        assert_eq!(pat.find(&data), Some(0));
    }

    #[test]
    fn wildcard_match_middle() {
        let data = [0xAA, 0xBB, 0x8B, 0x44, 0xCC, 0xDD, 0x24, 0x04, 0xEE];
        let pat = BytePattern::parse("8B 44 ?? ?? 24 04").unwrap();
        assert_eq!(pat.find(&data), Some(2));
    }

    #[test]
    fn multiple_matches() {
        let data = [0x8B, 0x44, 0x24, 0x8B, 0x44, 0x24];
        let pat = BytePattern::parse("8B 44 24").unwrap();
        assert_eq!(pat.find_all(&data), vec![0, 3]);
    }

    #[test]
    fn not_found() {
        let data = [0x8B, 0x44, 0x24, 0x05];
        let pat = BytePattern::parse("8B 44 24 04").unwrap();
        assert_eq!(pat.find(&data), None);
    }

    #[test]
    fn pattern_longer_than_data() {
        let data = [0x8B, 0x44];
        let pat = BytePattern::parse("8B 44 24 04").unwrap();
        assert_eq!(pat.find(&data), None);
    }

    #[test]
    fn find_from_offset() {
        let data = [0x8B, 0x44, 0x24, 0x04, 0x8B, 0x44, 0x24, 0x04];
        let pat = BytePattern::parse("8B 44 24 04").unwrap();
        // First match at offset 0, second at offset 4
        assert_eq!(pat.find_from(&data, 0), Some(0));
        assert_eq!(pat.find_from(&data, 1), Some(4));
        assert_eq!(pat.find_from(&data, 5), None);
    }

    #[test]
    fn find_from_with_wildcards() {
        let data = [0x8B, 0x44, 0xAA, 0xBB, 0x24, 0x8B, 0x44, 0xCC, 0xDD, 0x24];
        let pat = BytePattern::parse("8B 44 ?? ?? 24").unwrap();
        assert_eq!(pat.find_from(&data, 0), Some(0));
        assert_eq!(pat.find_from(&data, 1), Some(5));
    }

    #[test]
    fn all_wildcards_matches_everywhere() {
        let data = [0x01, 0x02, 0x03];
        let pat = BytePattern::parse("?? ??").unwrap();
        // Should match at offsets 0 and 1 (length-2 pattern in length-3 data)
        assert_eq!(pat.find_all(&data), vec![0, 1]);
    }

    #[test]
    fn find_dynamic_convenience() {
        let data = [0x8B, 0x44, 0xAA, 0xBB, 0x24, 0x04];
        assert_eq!(find_dynamic(&data, "8B 44 ?? ?? 24 04"), Some(0));
        assert_eq!(find_dynamic(&data, "8B 44 24 04"), None);
    }

    #[test]
    fn find_static_convenience() {
        let data = [0x8B, 0x44, 0x24, 0x04];
        assert_eq!(find_static(&data, "8B 44 24 04"), Some(0));
        assert_eq!(find_static(&data, "8B 44 24 05"), None);
    }

    #[test]
    fn find_static_not_found() {
        let data = [0x8B, 0x44, 0x24, 0x04];
        assert_eq!(find_static(&data, "DE AD BE EF"), None);
    }

    #[test]
    fn find_static_data_too_short() {
        let data = [0x8B];
        assert_eq!(find_static(&data, "8B 44"), None);
    }

    #[test]
    fn zero_length_pattern() {
        let _data = [0x8B, 0x44, 0x24, 0x04];
        let pat = BytePattern::parse("").unwrap_err();
        // Verify the error is for empty pattern
        assert!(matches!(pat, DisasmError::InvalidPattern(_)));
    }
}
