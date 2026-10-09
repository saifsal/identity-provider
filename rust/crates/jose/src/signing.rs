//! JWS signing for algorithms enabled by the project policy.

use std::fmt;

use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair};

use crate::alg::Alg;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    UnsupportedAlgorithm,
    InvalidKey,
    SigningFailed,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigningError::UnsupportedAlgorithm => {
                f.write_str("the algorithm is not available for signing")
            }
            SigningError::InvalidKey => f.write_str("invalid PKCS#8 signing key"),
            SigningError::SigningFailed => f.write_str("signature generation failed"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::PublicKey;
    use crate::jwks::KeyMaterial;
    use crate::signature as jws_signature;
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
}
