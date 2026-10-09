//! JWS signature verification for the algorithms supported by this crate.
//!
//! This module verifies the signature over an already-formed JWS signing input.
//! Compact serialization, header policy, key selection and claims validation
//! are handled by higher layers.

use ring::{hmac, signature};
use std::fmt;

use crate::alg::{Alg, HS256_MIN_KEY_LEN};
use crate::jwk::PublicKey;
use crate::jwks::KeyMaterial;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureError;

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl std::error::Error for SignatureError {}

/// Verifies a JWS signature over the ASCII bytes of `header.payload`.
///
/// The caller must check the algorithm policy and select a compatible key
/// before calling this function. ES256 signatures use the fixed-width JOSE
/// `R || S` format, not ASN.1 DER.
pub fn verify(
    alg: Alg,
    key: &KeyMaterial,
    signing_input: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SignatureError> {
    match (alg, key) {
        (Alg::EdDSA, KeyMaterial::Public(PublicKey::Ed25519 { x })) => {
            signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(signing_input, signature_bytes)
                .map_err(|_| SignatureError)
        }
        (Alg::ES256, KeyMaterial::Public(PublicKey::P256 { x, y })) => {
            let mut point = [0u8; 65];
            point[0] = 0x04;
            point[1..33].copy_from_slice(x);
            point[33..].copy_from_slice(y);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point)
                .verify(signing_input, signature_bytes)
                .map_err(|_| SignatureError)
        }
        (Alg::HS256, KeyMaterial::Secret(secret)) if secret.len() >= HS256_MIN_KEY_LEN => {
            hmac::verify(
                &hmac::Key::new(hmac::HMAC_SHA256, secret),
                signing_input,
                signature_bytes,
            )
            .map_err(|_| SignatureError)
        }
        _ => Err(SignatureError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    const INPUT: &[u8] = b"eyJhbGciOiJFZERTQSJ9.e30";

    #[test]
    fn verifies_ed25519_signature() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse Ed25519 key");
        let public = PublicKey::ed25519_from_bytes(pair.public_key().as_ref())
            .expect("Ed25519 public key length");
        let key = KeyMaterial::Public(public);
        let sig = pair.sign(INPUT);

        verify(Alg::EdDSA, &key, INPUT, sig.as_ref()).expect("valid Ed25519 signature");
        assert_eq!(
            verify(Alg::EdDSA, &key, INPUT, &sig.as_ref()[..63]),
            Err(SignatureError)
        );
    }

    #[test]
    fn verifies_es256_fixed_width_signature() {
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
            .expect("P-256 public key format");
        let key = KeyMaterial::Public(public);
        let sig = pair.sign(&rng, INPUT).expect("sign input");

        verify(Alg::ES256, &key, INPUT, sig.as_ref()).expect("valid ES256 signature");
        assert_eq!(sig.as_ref().len(), 64);
        assert_eq!(
            verify(Alg::ES256, &key, INPUT, &sig.as_ref()[..63]),
            Err(SignatureError)
        );
    }

    #[test]
    fn verifies_hs256_signature() {
        let secret = [0x42; HS256_MIN_KEY_LEN];
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let sig = hmac::sign(&key, b"what do ya want for nothing?");

        verify(
            Alg::HS256,
            &KeyMaterial::Secret(secret.to_vec()),
            b"what do ya want for nothing?",
            sig.as_ref(),
        )
        .expect("valid HS256 signature");
    }

    #[test]
    fn rejects_tampered_input_and_wrong_key_type() {
        let secret = [0x42; HS256_MIN_KEY_LEN];
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let sig = hmac::sign(&key, INPUT);

        assert_eq!(
            verify(
                Alg::HS256,
                &KeyMaterial::Secret(secret.to_vec()),
                b"tampered",
                sig.as_ref(),
            ),
            Err(SignatureError)
        );
        assert_eq!(
            verify(
                Alg::EdDSA,
                &KeyMaterial::Secret(secret.to_vec()),
                INPUT,
                sig.as_ref(),
            ),
            Err(SignatureError)
        );
    }

    #[test]
    fn rejects_hs256_keys_shorter_than_256_bits() {
        let secret = [0x42; HS256_MIN_KEY_LEN - 1];
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let sig = hmac::sign(&key, INPUT);
        assert_eq!(
            verify(
                Alg::HS256,
                &KeyMaterial::Secret(secret.to_vec()),
                INPUT,
                sig.as_ref(),
            ),
            Err(SignatureError)
        );
    }
}
