//! JWS signing for algorithms enabled by the project policy.

use std::fmt;

use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair};

use crate::alg::Alg;
use crate::b64url;
use crate::json::{self, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    UnsupportedAlgorithm,
    InvalidKey,
    SigningFailed,
    InvalidProtectedHeader,
    AlgorithmMismatch,
    UnsupportedCriticalHeader,
    InvalidPayload,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::UnsupportedAlgorithm => {
                f.write_str("the algorithm is not available for signing")
            }
            SigningError::InvalidKey => f.write_str("invalid PKCS#8 signing key"),
            SigningError::SigningFailed => f.write_str("signature generation failed"),
            SigningError::InvalidProtectedHeader => {
                f.write_str("protected header must be a valid JSON object with a string kid")
            }
            SigningError::AlgorithmMismatch => {
                f.write_str("protected header alg does not match signing algorithm")
            }
            SigningError::UnsupportedCriticalHeader => {
                f.write_str("critical protected-header parameters are unsupported")
            }
            SigningError::InvalidPayload => f.write_str("payload must be a valid JSON object"),
        }
    }
}

impl std::error::Error for SigningError {}

/// Signs the JWS signing input with a PKCS#8 private key.
///
/// The caller supplies the ASCII bytes of `BASE64URL(protected).BASE64URL(payload)`.
/// EdDSA uses an Ed25519 PKCS#8 key; ES256 uses a P-256 PKCS#8 key. The returned
/// ES256 signature is the fixed-width 64-byte JOSE representation, not DER.
/// HS256 is intentionally verification-only.
pub fn sign(alg: Alg, pkcs8: &[u8], signing_input: &[u8]) -> Result<Vec<u8>, SigningError> {
    match alg {
        Alg::EdDSA => {
            let key = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| SigningError::InvalidKey)?;
            Ok(key.sign(signing_input).as_ref().to_vec())
        }
        Alg::ES256 => {
            let rng = ring::rand::SystemRandom::new();
            let key =
                EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
                    .map_err(|_| SigningError::InvalidKey)?;
            key.sign(&rng, signing_input)
                .map(|sig| sig.as_ref().to_vec())
                .map_err(|_| SigningError::SigningFailed)
        }
        Alg::HS256 => Err(SigningError::UnsupportedAlgorithm),
    }
}

/// Creates a compact JWS carrying a JSON object payload.
///
/// The protected header is preserved byte-for-byte and must be a strict JSON
/// object containing string `alg` and non-empty string `kid` members. Its
/// algorithm must match `alg`. The payload must be a strict JSON object. This
/// lets the caller choose header fields while ensuring the result matches the
/// project's compact JWT verifier profile.
pub fn sign_compact(
    alg: Alg,
    pkcs8: &[u8],
    protected_header_json: &[u8],
    payload_json: &[u8],
) -> Result<String, SigningError> {
    let header =
        json::parse(protected_header_json).map_err(|_| SigningError::InvalidProtectedHeader)?;
    if header.as_object().is_none()
        || header.get("alg").and_then(Value::as_str).is_none()
        || header
            .get("kid")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(SigningError::InvalidProtectedHeader);
    }
    if header.get("alg").and_then(Value::as_str) != Some(alg.name()) {
        return Err(SigningError::AlgorithmMismatch);
    }
    if header.get("crit").is_some() {
        return Err(SigningError::UnsupportedCriticalHeader);
    }

    let payload = json::parse(payload_json).map_err(|_| SigningError::InvalidPayload)?;
    if payload.as_object().is_none() {
        return Err(SigningError::InvalidPayload);
    }

    let encoded_header = b64url::encode(protected_header_json);
    let encoded_payload = b64url::encode(payload_json);
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    let signature = sign(alg, pkcs8, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", b64url::encode(&signature)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::PublicKey;
    use crate::jwks::Jwks;
    use crate::jwks::KeyMaterial;
    use crate::signature as jws_signature;
    use crate::verify::{self, Policy};
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    const INPUT: &[u8] = b"eyJhbGciOiJFZERTQSJ9.e30";

    #[test]
    fn signs_ed25519_deterministically_and_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse Ed25519 key");
        let public = PublicKey::ed25519_from_bytes(pair.public_key().as_ref())
            .expect("valid Ed25519 public key");

        let first = sign(Alg::EdDSA, pkcs8.as_ref(), INPUT).expect("sign input");
        let second = sign(Alg::EdDSA, pkcs8.as_ref(), INPUT).expect("sign input again");
        assert_eq!(first, second);
        jws_signature::verify(Alg::EdDSA, &KeyMaterial::Public(public), INPUT, &first)
            .expect("signature verifies");
    }

    #[test]
    fn signs_es256_with_fixed_width_jose_signature() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate P-256 key");
        let pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .expect("parse P-256 key");
        let public = PublicKey::p256_from_uncompressed(pair.public_key().as_ref())
            .expect("valid P-256 public key");

        let sig = sign(Alg::ES256, pkcs8.as_ref(), INPUT).expect("sign input");
        assert_eq!(sig.len(), 64);
        jws_signature::verify(Alg::ES256, &KeyMaterial::Public(public), INPUT, &sig)
            .expect("signature verifies");
    }

    #[test]
    fn rejects_hs256_and_invalid_private_keys() {
        assert_eq!(
            sign(Alg::HS256, b"not a key", INPUT),
            Err(SigningError::UnsupportedAlgorithm)
        );
        assert_eq!(
            sign(Alg::EdDSA, b"not a key", INPUT),
            Err(SigningError::InvalidKey)
        );
    }

    #[test]
    fn creates_compact_jwt_that_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse Ed25519 key");
        let public = PublicKey::ed25519_from_bytes(pair.public_key().as_ref())
            .expect("valid Ed25519 public key");
        let kid = public.thumbprint();
        let jwks = Jwks::parse(
            format!(
                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{}"}}]}}"#,
                crate::b64url::encode(pair.public_key().as_ref()),
                kid,
            )
            .as_bytes(),
        )
        .expect("valid JWKS");
        let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"at+jwt"}}"#);
        let payload = r#"{"iss":"issuer","aud":"api","exp":101}"#;
        let token = sign_compact(
            Alg::EdDSA,
            pkcs8.as_ref(),
            header.as_bytes(),
            payload.as_bytes(),
        )
        .expect("sign compact JWT");

        let verified = verify::verify(
            token.as_bytes(),
            &jwks,
            &Policy {
                algorithms: vec![Alg::EdDSA],
                issuer: Some("issuer".into()),
                audience: Some("api".into()),
                now: 100,
                leeway: 0,
                typ: Some("at+jwt".into()),
                max_token_bytes: 8192,
            },
        )
        .expect("newly signed JWT verifies");
        assert_eq!(verified.kid, kid);
        assert_eq!(verified.alg, Alg::EdDSA);
    }

    #[test]
    fn compact_signing_rejects_invalid_header_algorithm_and_payload() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
        assert_eq!(
            sign_compact(
                Alg::EdDSA,
                pkcs8.as_ref(),
                br#"{"alg":"ES256","kid":"key"}"#,
                br#"{"exp":101}"#,
            ),
            Err(SigningError::AlgorithmMismatch)
        );
        assert_eq!(
            sign_compact(
                Alg::EdDSA,
                pkcs8.as_ref(),
                br#"{"alg":"EdDSA"}"#,
                br#"{"exp":101}"#,
            ),
            Err(SigningError::InvalidProtectedHeader)
        );
        assert_eq!(
            sign_compact(
                Alg::EdDSA,
                pkcs8.as_ref(),
                br#"{"alg":"EdDSA","kid":"key"}"#,
                b"[]",
            ),
            Err(SigningError::InvalidPayload)
        );
        assert_eq!(
            sign_compact(
                Alg::EdDSA,
                pkcs8.as_ref(),
                br#"{"alg":"EdDSA","kid":"key","crit":["exp"]}"#,
                br#"{"exp":101}"#,
            ),
            Err(SigningError::UnsupportedCriticalHeader)
        );
    }
}
