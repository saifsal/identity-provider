//! Strict, unpadded base64url (RFC 4648 section 5), as used by JOSE (RFC 7515
//! section 2).
//!
//! The decoder is deliberately stricter than most libraries:
//!
//! * only the URL-safe alphabet is accepted, so `+`, `/`, `=` and whitespace are errors;
//! * a length of 1 modulo 4 is impossible and is an error;
//! * the encoding must be canonical: the unused trailing bits of the last
//!   character must be zero. Without this check, several different strings decode
//!   to the same bytes, which makes tokens malleable (see ADR 0003).
//!
//! The decoder is not constant time. It is meant for public data such as token
//! segments, not for secret key material.

use std::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A byte outside the base64url alphabet, at this byte offset.
    InvalidCharacter { index: usize },
    /// The length is 1 modulo 4, which no byte sequence encodes to.
    InvalidLength,
    /// The unused trailing bits of the last character are not zero.
    NonCanonical,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidCharacter { index } => {
                write!(f, "invalid base64url character at byte {index}")
            }
            DecodeError::InvalidLength => write!(f, "invalid base64url length"),
            DecodeError::NonCanonical => write!(f, "non-canonical base64url encoding"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Length of the unpadded base64url encoding of `n` bytes.
pub fn encoded_len(n: usize) -> usize {
    (n / 3) * 4
        + match n % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

fn sextet(n: u32, shift: u32) -> char {
    ALPHABET[((n >> shift) & 0x3f) as usize] as char
}

/// Encodes `input` as unpadded base64url.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(input.len()));
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(sextet(n, 18));
        out.push(sextet(n, 12));
        out.push(sextet(n, 6));
        out.push(sextet(n, 0));
    }
    match chunks.remainder() {
        [a] => {
            let n = (*a as u32) << 16;
            out.push(sextet(n, 18));
            out.push(sextet(n, 12));
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(sextet(n, 18));
            out.push(sextet(n, 12));
            out.push(sextet(n, 6));
        }
        _ => {}
    }
    out
}

fn value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes strict, canonical, unpadded base64url.
///
/// The empty string decodes to an empty vector. Callers that require a non-empty
/// segment (the JWS verifier does) check that themselves.
pub fn decode(input: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = input.as_bytes();

    let mut vals = Vec::with_capacity(bytes.len());
    for (index, &b) in bytes.iter().enumerate() {
        vals.push(value(b).ok_or(DecodeError::InvalidCharacter { index })?);
    }
    if vals.len() % 4 == 1 {
        return Err(DecodeError::InvalidLength);
    }

    let mut out = Vec::with_capacity(vals.len() / 4 * 3 + 2);
    let mut chunks = vals.chunks_exact(4);
    for c in &mut chunks {
        let n =
            ((c[0] as u32) << 18) | ((c[1] as u32) << 12) | ((c[2] as u32) << 6) | (c[3] as u32);
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    match chunks.remainder() {
        [a, b] => {
            if b & 0x0f != 0 {
                return Err(DecodeError::NonCanonical);
            }
            out.push((a << 2) | (b >> 4));
        }
        [a, b, c] => {
            if c & 0x03 != 0 {
                return Err(DecodeError::NonCanonical);
            }
            let n = ((*a as u32) << 10) | ((*b as u32) << 4) | ((*c as u32) >> 2);
            out.extend_from_slice(&[(n >> 8) as u8, n as u8]);
        }
        _ => {}
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10 test vectors. The RFC lists padded forms; JOSE strips
    /// the padding, so the expected strings below have none.
    const RFC4648: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_encode() {
        for (plain, encoded) in RFC4648 {
            assert_eq!(encode(plain.as_bytes()), *encoded, "encoding {plain:?}");
        }
    }

    #[test]
    fn rfc4648_decode() {
        for (plain, encoded) in RFC4648 {
            assert_eq!(
                decode(encoded).unwrap(),
                plain.as_bytes(),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn url_safe_alphabet_is_used() {
        // 0xfb 0xff is "+/8=" in standard base64.
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn rejects_standard_alphabet_padding_and_whitespace() {
        assert_eq!(
            decode("+_8"),
            Err(DecodeError::InvalidCharacter { index: 0 })
        );
        assert_eq!(
            decode("-/8"),
            Err(DecodeError::InvalidCharacter { index: 1 })
        );
        assert_eq!(
            decode("Zg=="),
            Err(DecodeError::InvalidCharacter { index: 2 })
        );
        assert_eq!(
            decode("Zm9v\n"),
            Err(DecodeError::InvalidCharacter { index: 4 })
        );
        assert_eq!(
            decode("Zm 9v"),
            Err(DecodeError::InvalidCharacter { index: 2 })
        );
    }

    #[test]
    fn rejects_non_ascii_bytes() {
        assert_eq!(
            decode("Zm9\u{e9}"),
            Err(DecodeError::InvalidCharacter { index: 3 })
        );
    }

    #[test]
    fn rejects_length_one_mod_four() {
        for s in ["A", "Zm9vY", "Zm9vYmFyA"] {
            assert_eq!(decode(s), Err(DecodeError::InvalidLength), "{s:?}");
        }
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // "Zg" is the canonical encoding of "f". "Zh", "Zi" and "Zj" carry the
        // same first byte but have non-zero trailing bits.
        assert_eq!(decode("Zg").unwrap(), b"f");
        for s in ["Zh", "Zi", "Zj"] {
            assert_eq!(decode(s), Err(DecodeError::NonCanonical), "{s:?}");
        }
        // "Zm8" is canonical for "fo". "Zm9" has non-zero trailing bits.
        assert_eq!(decode("Zm8").unwrap(), b"fo");
        assert_eq!(decode("Zm9"), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn round_trips_every_one_and_two_byte_input() {
        for a in 0..=255u8 {
            let one = [a];
            assert_eq!(decode(&encode(&one)).unwrap(), one);
            for b in 0..=255u8 {
                let two = [a, b];
                assert_eq!(decode(&encode(&two)).unwrap(), two);
            }
        }
    }

    #[test]
    fn round_trips_all_lengths_with_pseudo_random_bytes() {
        // Small LCG so the test needs no dependency and is reproducible.
        let mut state: u32 = 0x1234_5678;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        };
        for len in 0..=300 {
            let data: Vec<u8> = (0..len).map(|_| next()).collect();
            let encoded = encode(&data);
            assert_eq!(encoded.len(), encoded_len(len));
            assert_eq!(decode(&encoded).unwrap(), data, "length {len}");
        }
    }

    #[test]
    fn encoding_is_injective_for_two_byte_inputs() {
        // Canonical decoding means no two distinct strings decode to the same
        // bytes. Check the converse on a small space: every canonical string
        // re-encodes to itself.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let s = encode(&[a, b]);
                assert_eq!(encode(&decode(&s).unwrap()), s);
            }
        }
    }
}
