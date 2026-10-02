//! Public keys and JWK thumbprints (RFC 7638).
//!
//! Only Ed25519 (`OKP`, RFC 8037) and P-256 (`EC`, RFC 7518 section 6.2) are modelled.
//!
//! RSA is out of scope, so the RSA example in
//! RFC 7638 section 3.1 is not covered by a test here.

use std::fmt;

use ring::digest;

use crate::b64url;

const ED25519_LEN: usize = 32;
const P256_COORD_LEN: usize = 32;

/// SEC 1 uncompressed point format: `0x04 || X || Y`.
const P256_UNCOMPRESSED_LEN: usize = 1 + 2 * P256_COORD_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    BadLength { expected: usize, actual: usize },
    NotUncompressedPoint,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::BadLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            KeyError::NotUncompressedPoint => write!(f, "not an uncompressed SEC 1 point"),
        }
    }
}

impl std::error::Error for KeyError {}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], KeyError> {
    bytes.try_into().map_err(|_| KeyError::BadLength {
        expected: N,
        actual: bytes.len(),
    })
}

/// A public verification key.
///
/// Construction checks lengths only. It does not check that a P-256 point is
/// on the curve. The signature verifier rejects invalid points when it is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519 {
        x: [u8; ED25519_LEN],
    },
    P256 {
        x: [u8; P256_COORD_LEN],
        y: [u8; P256_COORD_LEN],
    },
}

impl PublicKey {
    pub fn ed25519_from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        Ok(PublicKey::Ed25519 { x: fixed(bytes)? })
    }

    pub fn p256_from_coordinates(x: &[u8], y: &[u8]) -> Result<Self, KeyError> {
        Ok(PublicKey::P256 {
            x: fixed(x)?,
            y: fixed(y)?,
        })
    }

    pub fn p256_from_uncompressed(point: &[u8]) -> Result<Self, KeyError> {
        if point.len() != P256_UNCOMPRESSED_LEN {
            return Err(KeyError::BadLength {
                expected: P256_UNCOMPRESSED_LEN,
                actual: point.len(),
            });
        }
        if point[0] != 0x04 {
            return Err(KeyError::NotUncompressedPoint);
        }
        Self::p256_from_coordinates(&point[1..1 + P256_COORD_LEN], &point[1 + P256_COORD_LEN..])
    }

    /// The canonical JSON of RFC 7638 section 3:
    ///
    /// only the required members, in
    /// lexicographic order, no whitespace.
    ///
    /// Every value is a fixed string or base64url text, so none needs JSON
    /// escaping.
    pub fn canonical_json(&self) -> String {
        match self {
            PublicKey::Ed25519 { x } => format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                b64url::encode(x)
            ),
            PublicKey::P256 { x, y } => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                b64url::encode(x),
                b64url::encode(y)
            ),
        }
    }

    /// The RFC 7638 thumbprint with SHA-256, base64url encoded. Used as the `kid`.
    pub fn thumbprint(&self) -> String {
        let hash = digest::digest(&digest::SHA256, self.canonical_json().as_bytes());
        b64url::encode(hash.as_ref())
    }
}
