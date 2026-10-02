use jose::b64url;
use jose::jwk::{KeyError, PublicKey};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 8037 Appendix A.1 / A.2: Ed25519 public key.
const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
// RFC 8037 Appendix A.1: hexadecimal dump of the public key.
const RFC8037_X_HEX: &str = "d7 5a 98 01 82 b1 0a b7 d5 4b fe d3 c9 64 07 3a
                             0e e1 72 f3 da a6 23 25 af 02 1a 68 f7 07 51 1a";
// RFC 8037 Appendix A.3: canonical JSON and thumbprint.
const RFC8037_CANONICAL: &str =
    r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

#[test]
fn rfc8037_a1_base64url_matches_hex_dump() {
    assert_eq!(b64url::decode(RFC8037_X).unwrap(), hex(RFC8037_X_HEX));
}

#[test]
fn rfc8037_a3_canonical_json() {
    let key = PublicKey::ed25519_from_bytes(&hex(RFC8037_X_HEX)).unwrap();
    assert_eq!(key.canonical_json(), RFC8037_CANONICAL);
}

#[test]
fn rfc8037_a3_thumbprint() {
    let key = PublicKey::ed25519_from_bytes(&b64url::decode(RFC8037_X).unwrap()).unwrap();
    assert_eq!(key.thumbprint(), RFC8037_THUMBPRINT);
}

// P-256 key from the DPoP specification (RFC 9449) examples, with the `jkt`
// value given there. The RFC section was not checked when this test was written;
// the pair was confirmed by hashing the canonical JSON independently.
const P256_X: &str = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
const P256_Y: &str = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";
const P256_THUMBPRINT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

#[test]
fn p256_thumbprint() {
    let key = PublicKey::p256_from_coordinates(
        &b64url::decode(P256_X).unwrap(),
        &b64url::decode(P256_Y).unwrap(),
    )
    .unwrap();
    assert_eq!(
        key.canonical_json(),
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{P256_X}","y":"{P256_Y}"}}"#)
    );
    assert_eq!(key.thumbprint(), P256_THUMBPRINT);
}

#[test]
fn p256_from_uncompressed_point_matches_coordinates() {
    let x = b64url::decode(P256_X).unwrap();
    let y = b64url::decode(P256_Y).unwrap();
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    assert_eq!(
        PublicKey::p256_from_uncompressed(&point).unwrap(),
        PublicKey::p256_from_coordinates(&x, &y).unwrap()
    );
}

#[test]
fn rejects_wrong_lengths_and_tags() {
    assert_eq!(
        PublicKey::ed25519_from_bytes(&[0; 31]),
        Err(KeyError::BadLength { expected: 32, actual: 31 })
    );
    assert_eq!(
        PublicKey::p256_from_coordinates(&[0; 32], &[0; 33]),
        Err(KeyError::BadLength { expected: 32, actual: 33 })
    );
    assert_eq!(
        PublicKey::p256_from_uncompressed(&[0x04; 64]),
        Err(KeyError::BadLength { expected: 65, actual: 64 })
    );
    let mut compressed_tag = vec![0x02];
    compressed_tag.extend_from_slice(&[0; 64]);
    assert_eq!(
        PublicKey::p256_from_uncompressed(&compressed_tag),
        Err(KeyError::NotUncompressedPoint)
    );
}

#[test]
fn thumbprint_is_43_url_safe_characters() {
    // SHA-256 is 32 bytes, which encodes to 43 unpadded base64url characters.
    let key = PublicKey::ed25519_from_bytes(&[7; 32]).unwrap();
    let t = key.thumbprint();
    assert_eq!(t.len(), 43);
    assert!(t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}

#[test]
fn different_keys_have_different_thumbprints() {
    let a = PublicKey::ed25519_from_bytes(&[1; 32]).unwrap();
    let b = PublicKey::ed25519_from_bytes(&[2; 32]).unwrap();
    assert_ne!(a.thumbprint(), b.thumbprint());
}
