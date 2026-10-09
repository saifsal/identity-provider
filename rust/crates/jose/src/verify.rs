//! Compact JWS verification and JWT claim validation following ADR 0003.

use std::fmt;

use crate::alg::Alg;
use crate::b64url;
use crate::json::{self, Value};
use crate::jwks::Jwks;
use crate::signature;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub algorithms: Vec<Alg>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub now: i64,
    pub leeway: u64,
    pub typ: Option<String>,
    pub max_token_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    TooLarge,
    Malformed,
    CritUnsupported,
    AlgNotAllowed,
    TypMismatch,
    KeyNotFound,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    Expired,
    NotYetValid,
}

impl VerifyError {
    pub fn code(self) -> &'static str {
        match self {
            VerifyError::TooLarge => "too_large",
            VerifyError::Malformed => "malformed",
            VerifyError::CritUnsupported => "crit_unsupported",
            VerifyError::AlgNotAllowed => "alg_not_allowed",
            VerifyError::TypMismatch => "typ_mismatch",
            VerifyError::KeyNotFound => "key_not_found",
            VerifyError::BadSignature => "bad_signature",
            VerifyError::WrongIssuer => "wrong_issuer",
            VerifyError::WrongAudience => "wrong_audience",
            VerifyError::Expired => "expired",
            VerifyError::NotYetValid => "not_yet_valid",
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    pub kid: String,
    pub alg: Alg,
    pub claims: Value,
}

/// Verifies one compact JWS and validates its JWT claims according to ADR 0003.
pub fn verify(token: &[u8], jwks: &Jwks, policy: &Policy) -> Result<VerifiedToken, VerifyError> {
    if token.len() > policy.max_token_bytes {
        return Err(VerifyError::TooLarge);
    }

    let token = std::str::from_utf8(token).map_err(|_| VerifyError::Malformed)?;
    let mut segments = token.split('.');
    let header_segment = segments.next().ok_or(VerifyError::Malformed)?;
    let payload_segment = segments.next().ok_or(VerifyError::Malformed)?;
    let signature_segment = segments.next().ok_or(VerifyError::Malformed)?;
    if segments.next().is_some()
        || header_segment.is_empty()
        || payload_segment.is_empty()
        || signature_segment.is_empty()
        || ![header_segment, payload_segment, signature_segment]
            .iter()
            .all(|segment| segment.bytes().all(is_base64url))
    {
        return Err(VerifyError::Malformed);
    }

    let header_bytes = b64url::decode(header_segment).map_err(|_| VerifyError::Malformed)?;
    let header = json::parse(&header_bytes).map_err(|_| VerifyError::Malformed)?;
    if header.as_object().is_none() {
        return Err(VerifyError::Malformed);
    }

    if let Some(crit) = header.get("crit") {
        let entries = crit
            .as_array()
            .filter(|entries| !entries.is_empty())
            .ok_or(VerifyError::Malformed)?;
        if entries.iter().any(|entry| entry.as_str().is_none()) {
            return Err(VerifyError::Malformed);
        }
        return Err(VerifyError::CritUnsupported);
    }

    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(VerifyError::AlgNotAllowed)?;
    let alg = Alg::from_name(alg_name)
        .filter(|alg| policy.algorithms.contains(alg))
        .ok_or(VerifyError::AlgNotAllowed)?;

    if let Some(expected_typ) = &policy.typ {
        let actual_typ = header
            .get("typ")
            .and_then(Value::as_str)
            .ok_or(VerifyError::TypMismatch)?;
        if !typ_matches(actual_typ, expected_typ) {
            return Err(VerifyError::TypMismatch);
        }
    }

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(VerifyError::KeyNotFound)?;
    let key = jwks.find(kid, alg).ok_or(VerifyError::KeyNotFound)?;
    let signature_bytes =
        b64url::decode(signature_segment).map_err(|_| VerifyError::BadSignature)?;
    let expected_len = match alg {
        Alg::EdDSA | Alg::ES256 => 64,
        Alg::HS256 => 32,
    };
    if signature_bytes.len() != expected_len {
        return Err(VerifyError::BadSignature);
    }
    let signing_input = format!("{header_segment}.{payload_segment}");
    signature::verify(
        alg,
        key.material().ok_or(VerifyError::KeyNotFound)?,
        signing_input.as_bytes(),
        &signature_bytes,
    )
    .map_err(|_| VerifyError::BadSignature)?;

    let payload_bytes = b64url::decode(payload_segment).map_err(|_| VerifyError::Malformed)?;
    let claims = json::parse(&payload_bytes).map_err(|_| VerifyError::Malformed)?;
    if claims.as_object().is_none() {
        return Err(VerifyError::Malformed);
    }
    validate_claims(&claims, policy)?;

    Ok(VerifiedToken {
        kid: kid.to_owned(),
        alg,
        claims,
    })
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fn typ_matches(actual: &str, expected: &str) -> bool {
    fn normalize(value: &str) -> &str {
        if value
            .get(..12)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/"))
        {
            &value[12..]
        } else {
            value
        }
    }
    normalize(actual).eq_ignore_ascii_case(normalize(expected))
}

fn validate_claims(claims: &Value, policy: &Policy) -> Result<(), VerifyError> {
    if let Some(expected) = &policy.issuer {
        if claims.get("iss").and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(VerifyError::WrongIssuer);
        }
    }

    if let Some(expected) = &policy.audience {
        let audience = claims.get("aud").ok_or(VerifyError::WrongAudience)?;
        let matches = match audience {
            Value::String(value) => value == expected,
            Value::Array(values) => {
                let mut found = false;
                for value in values {
                    let value = value.as_str().ok_or(VerifyError::Malformed)?;
                    found |= value == expected;
                }
                found
            }
            _ => false,
        };
        if !matches {
            return Err(VerifyError::WrongAudience);
        }
    }

    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(VerifyError::Malformed)?;
    let nbf = match claims.get("nbf") {
        None => None,
        Some(value) => Some(value.as_i64().ok_or(VerifyError::Malformed)?),
    };
    let now = i128::from(policy.now);
    let leeway = i128::from(policy.leeway);
    if now >= i128::from(exp) + leeway {
        return Err(VerifyError::Expired);
    }
    if nbf.is_some_and(|nbf| now + leeway < i128::from(nbf)) {
        return Err(VerifyError::NotYetValid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::hmac;

    use crate::alg::HS256_MIN_KEY_LEN;

    fn policy() -> Policy {
        Policy {
            algorithms: vec![Alg::HS256],
            issuer: Some("https://issuer.example".into()),
            audience: Some("api".into()),
            now: 100,
            leeway: 0,
            typ: Some("at+jwt".into()),
            max_token_bytes: 8192,
        }
    }

    fn signed_token(header: &str, payload: &str) -> String {
        let header = b64url::encode(header.as_bytes());
        let payload = b64url::encode(payload.as_bytes());
        let input = format!("{header}.{payload}");
        let secret = [0x42; HS256_MIN_KEY_LEN];
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let signature = b64url::encode(hmac::sign(&key, input.as_bytes()).as_ref());
        format!("{input}.{signature}")
    }

    fn jwks() -> Jwks {
        let secret = b64url::encode(&[0x42; HS256_MIN_KEY_LEN]);
        Jwks::parse(format!(r#"{{"keys":[{{"kty":"oct","kid":"h","k":"{secret}"}}]}}"#).as_bytes())
            .expect("valid JWKS")
    }

    fn valid_payload() -> &'static str {
        r#"{"iss":"https://issuer.example","aud":["other","api"],"exp":101,"nbf":100}"#
    }

    fn valid_header() -> &'static str {
        r#"{"alg":"HS256","kid":"h","typ":"application/at+jwt"}"#
    }

    #[test]
    fn verifies_compact_token_and_claims() {
        let token = signed_token(valid_header(), valid_payload());
        let verified = verify(token.as_bytes(), &jwks(), &policy()).expect("valid JWT");
        assert_eq!(verified.kid, "h");
        assert_eq!(verified.alg, Alg::HS256);
    }

    #[test]
    fn applies_size_shape_algorithm_and_critical_header_checks() {
        let keys = jwks();
        let mut limited = policy();
        limited.max_token_bytes = 2;
        assert_eq!(verify(b"abc", &keys, &limited), Err(VerifyError::TooLarge));
        assert_eq!(
            verify(b"a.b.c.d", &keys, &policy()),
            Err(VerifyError::Malformed)
        );
        assert_eq!(
            verify(
                signed_token(r#"{"alg":"none","kid":"h"}"#, valid_payload()).as_bytes(),
                &keys,
                &policy()
            ),
            Err(VerifyError::AlgNotAllowed)
        );
        assert_eq!(
            verify(
                signed_token(
                    r#"{"alg":"HS256","kid":"h","crit":["exp"]}"#,
                    valid_payload()
                )
                .as_bytes(),
                &keys,
                &policy()
            ),
            Err(VerifyError::CritUnsupported)
        );
    }

    #[test]
    fn verifies_signature_before_parsing_payload() {
        let token = signed_token(valid_header(), "not-json");
        let parts: Vec<&str> = token.split('.').collect();
        let altered = format!(
            "{}.{}.{}",
            parts[0],
            b64url::encode(b"still-not-json"),
            parts[2]
        );
        assert_eq!(
            verify(altered.as_bytes(), &jwks(), &policy()),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn validates_claim_errors_and_expiry_precedence() {
        let keys = jwks();
        let mut p = policy();
        p.now = 101;
        assert_eq!(
            verify(
                signed_token(valid_header(), valid_payload()).as_bytes(),
                &keys,
                &p
            ),
            Err(VerifyError::Expired)
        );
        let payload = r#"{"iss":"bad","aud":"api","exp":101}"#;
        assert_eq!(
            verify(
                signed_token(valid_header(), payload).as_bytes(),
                &keys,
                &policy()
            ),
            Err(VerifyError::WrongIssuer)
        );
        let payload = r#"{"iss":"https://issuer.example","aud":["api",1],"exp":101}"#;
        assert_eq!(
            verify(
                signed_token(valid_header(), payload).as_bytes(),
                &keys,
                &policy()
            ),
            Err(VerifyError::Malformed)
        );
    }
}
