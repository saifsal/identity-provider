//! JWKS parsing and the key lookup rules of ADR 0003, step 8.
//!
//! A [`Jwks`] is built from configuration, never from the network, and never from
//! anything in a token header (`jku`, `jwk`, `x5u`, `x5c` and `x5t` are ignored by
//! the verifier).
//!
//! Two kinds of problem are kept apart on purpose:
//!
//! * A JWKS that is structurally wrong is a configuration error and fails
//!   [`Jwks::parse`]: bad JSON, a missing or non-array `keys`, an entry that is
//!   not an object, a `kid` that is not a string, or two entries with the same
//!   `kid`. The CLI reports these with exit code 2 and no verdict.
//! * A key whose contents cannot be used (unsupported `kty` or `crv`, bad
//!   base64url, wrong lengths, an `alg` or `use` that is not a string) stays in
//!   the set but can never be selected. A token that names it gets
//!   `key_not_found`. This lets a negative vector carry a deliberately broken
//!   key without making the whole JWKS unusable.
//!
//! Members this module does not model, including private members such as `d`,
//! are ignored.

use std::collections::HashSet;
use std::fmt;

use crate::alg::Alg;
use crate::b64url;
use crate::json::{self, JsonError, Value};
use crate::jwk::PublicKey;

/// Key bytes a verifier can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// An `OKP`/`Ed25519` or `EC`/`P-256` public key.
    Public(PublicKey),
    /// The shared secret of an `oct` key. Only `HS256` uses it.
    Secret(Vec<u8>),
}

impl KeyMaterial {
    /// The one algorithm this kind of key can be used with.
    fn natural_alg(&self) -> Alg {
        match self {
            KeyMaterial::Public(PublicKey::Ed25519 { .. }) => Alg::EdDSA,
            KeyMaterial::Public(PublicKey::P256 { .. }) => Alg::ES256,
            KeyMaterial::Secret(_) => Alg::HS256,
        }
    }
}

/// One entry of a JWKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    kid: Option<String>,
    alg: Option<String>,
    use_: Option<String>,
    /// `None` when the entry could not be turned into usable key bytes.
    material: Option<KeyMaterial>,
}

impl Key {
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The key's own `alg` member, if it has one.
    pub fn alg_member(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// The key's own `use` member, if it has one.
    pub fn use_member(&self) -> Option<&str> {
        self.use_.as_deref()
    }

    /// The key bytes, or `None` for an entry that cannot be used.
    pub fn material(&self) -> Option<&KeyMaterial> {
        self.material.as_ref()
    }

    /// Whether this key may verify a token whose header says `alg`.
    ///
    /// * the entry must be usable;
    /// * the key type must fit the algorithm: Ed25519 for `EdDSA`, P-256 for
    ///   `ES256`, `oct` for `HS256`, whatever the `alg` member says;
    /// * if the key has an `alg` member it must equal the header algorithm, and
    ///   if it has none the key type alone decides;
    /// * if the key has a `use` member it must be `sig`.
    fn usable_for(&self, alg: Alg) -> bool {
        let Some(material) = &self.material else {
            return false;
        };
        if material.natural_alg() != alg {
            return false;
        }
        if let Some(declared) = &self.alg {
            if declared != alg.name() {
                return false;
            }
        }
        if let Some(usage) = &self.use_ {
            if usage != "sig" {
                return false;
            }
        }
        true
    }
}

/// A configuration error in a JWKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksError {
    Json(JsonError),
    NotAnObject,
    MissingKeys,
    KeysNotArray,
    KeyNotObject { index: usize },
    KidNotString { index: usize },
    DuplicateKid { kid: String },
}

impl fmt::Display for JwksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwksError::Json(e) => write!(f, "JWKS is not valid JSON: {e}"),
            JwksError::NotAnObject => write!(f, "JWKS is not a JSON object"),
            JwksError::MissingKeys => write!(f, "JWKS has no \"keys\" member"),
            JwksError::KeysNotArray => write!(f, "JWKS \"keys\" is not an array"),
            JwksError::KeyNotObject { index } => write!(f, "key {index} is not a JSON object"),
            JwksError::KidNotString { index } => write!(f, "key {index} has a non-string kid"),
            JwksError::DuplicateKid { kid } => write!(f, "duplicate kid {kid:?}"),
        }
    }
}

impl std::error::Error for JwksError {}

/// A set of verification keys, looked up by `kid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwks {
    keys: Vec<Key>,
}

impl Jwks {
    /// Parses a JWKS document. See the module documentation for what is an
    /// error and what is merely an unusable key.
    pub fn parse(input: &[u8]) -> Result<Jwks, JwksError> {
        let root = json::parse(input).map_err(JwksError::Json)?;
        if root.as_object().is_none() {
            return Err(JwksError::NotAnObject);
        }
        let entries = root
            .get("keys")
            .ok_or(JwksError::MissingKeys)?
            .as_array()
            .ok_or(JwksError::KeysNotArray)?;

        let mut keys = Vec::with_capacity(entries.len());
        let mut seen: HashSet<String> = HashSet::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry.as_object().is_none() {
                return Err(JwksError::KeyNotObject { index });
            }
            let kid = match entry.get("kid") {
                None => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => return Err(JwksError::KidNotString { index }),
            };
            if let Some(kid) = &kid {
                if !seen.insert(kid.clone()) {
                    return Err(JwksError::DuplicateKid { kid: kid.clone() });
                }
            }
            keys.push(Key::from_json(kid, entry));
        }
        Ok(Jwks { keys })
    }

    /// The key a token with this `kid` and `alg` must be verified with.
    ///
    /// The `kid` must match exactly. There is no fallback to another key, so a
    /// key that exists but does not fit (wrong type, `alg` member disagreeing,
    /// `use` other than `sig`, unusable contents) gives `None`, which the
    /// verifier reports as `key_not_found`.
    pub fn find(&self, kid: &str, alg: Alg) -> Option<&Key> {
        // Kids are unique (checked in `parse`), so at most one key matches.
        let key = self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))?;
        key.usable_for(alg).then_some(key)
    }

    /// All entries, in document order.
    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Key {
    fn from_json(kid: Option<String>, entry: &Value) -> Key {
        let alg = optional_string(entry, "alg");
        let use_ = optional_string(entry, "use");
        // A non-string `alg` or `use` makes the entry unusable.
        let material = match (&alg, &use_) {
            (Some(_), Some(_)) => load_material(entry),
            _ => None,
        };
        Key {
            kid,
            alg: alg.flatten(),
            use_: use_.flatten(),
            material,
        }
    }
}

/// `Some(None)` when the member is absent, `Some(Some(s))` when it is a string,
/// and `None` when it is present but not a string.
fn optional_string(entry: &Value, name: &str) -> Option<Option<String>> {
    match entry.get(name) {
        None => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        Some(_) => None,
    }
}

fn member_str<'a>(entry: &'a Value, name: &str) -> Option<&'a str> {
    entry.get(name)?.as_str()
}

fn member_bytes(entry: &Value, name: &str) -> Option<Vec<u8>> {
    b64url::decode(member_str(entry, name)?).ok()
}

fn load_material(entry: &Value) -> Option<KeyMaterial> {
    match member_str(entry, "kty")? {
        "OKP" => {
            if member_str(entry, "crv")? != "Ed25519" {
                return None;
            }
            let x = member_bytes(entry, "x")?;
            PublicKey::ed25519_from_bytes(&x)
                .ok()
                .map(KeyMaterial::Public)
        }
        "EC" => {
            if member_str(entry, "crv")? != "P-256" {
                return None;
            }
            let x = member_bytes(entry, "x")?;
            let y = member_bytes(entry, "y")?;
            PublicKey::p256_from_coordinates(&x, &y)
                .ok()
                .map(KeyMaterial::Public)
        }
        "oct" => {
            let k = member_bytes(entry, "k")?;
            if k.is_empty() {
                None
            } else {
                Some(KeyMaterial::Secret(k))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Ed25519 key of RFC 8037 Appendix A.2 and the P-256 key used in
    // tests/thumbprint.rs.
    const ED_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const P_X: &str = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs";
    const P_Y: &str = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA";

    fn ed(extra: &str) -> String {
        format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}"{extra}}}"#)
    }

    fn ec(extra: &str) -> String {
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{P_X}","y":"{P_Y}"{extra}}}"#)
    }

    fn oct(extra: &str) -> String {
        let k = b64url::encode(&[0x42; 32]);
        format!(r#"{{"kty":"oct","k":"{k}"{extra}}}"#)
    }

    fn set(keys: &[String]) -> String {
        format!(r#"{{"keys":[{}]}}"#, keys.join(","))
    }

    fn parse(keys: &[String]) -> Jwks {
        Jwks::parse(set(keys).as_bytes()).expect("JWKS should parse")
    }

    #[test]
    fn parses_all_three_key_types() {
        let jwks = parse(&[
            ed(r#","kid":"e""#),
            ec(r#","kid":"p""#),
            oct(r#","kid":"h""#),
        ]);
        assert_eq!(jwks.len(), 3);
        assert!(matches!(
            jwks.find("e", Alg::EdDSA).unwrap().material(),
            Some(KeyMaterial::Public(PublicKey::Ed25519 { .. }))
        ));
        assert!(matches!(
            jwks.find("p", Alg::ES256).unwrap().material(),
            Some(KeyMaterial::Public(PublicKey::P256 { .. }))
        ));
        assert_eq!(
            jwks.find("h", Alg::HS256).unwrap().material(),
            Some(&KeyMaterial::Secret(vec![0x42; 32]))
        );
    }

    #[test]
    fn decodes_the_expected_key_bytes() {
        let jwks = parse(&[ed(r#","kid":"e""#)]);
        let expected = PublicKey::ed25519_from_bytes(&b64url::decode(ED_X).unwrap()).unwrap();
        assert_eq!(
            jwks.find("e", Alg::EdDSA).unwrap().material(),
            Some(&KeyMaterial::Public(expected))
        );
    }

    #[test]
    fn empty_key_set_is_valid_and_finds_nothing() {
        let jwks = Jwks::parse(br#"{"keys":[]}"#).unwrap();
        assert!(jwks.is_empty());
        assert!(jwks.find("any", Alg::EdDSA).is_none());
    }

    #[test]
    fn kid_must_match_exactly() {
        let jwks = parse(&[ed(r#","kid":"Key-1""#)]);
        assert!(jwks.find("Key-1", Alg::EdDSA).is_some());
        for wrong in ["key-1", "Key-1 ", " Key-1", "Key-", "Key-12", ""] {
            assert!(jwks.find(wrong, Alg::EdDSA).is_none(), "{wrong:?}");
        }
    }

    #[test]
    fn there_is_no_fallback_to_another_key() {
        let jwks = parse(&[ed(r#","kid":"a""#), ed(r#","kid":"b""#)]);
        assert!(jwks.find("c", Alg::EdDSA).is_none());
    }

    #[test]
    fn keys_without_kid_can_never_be_selected() {
        let jwks = parse(&[ed(""), ed("")]);
        assert_eq!(jwks.len(), 2);
        assert!(jwks.find("", Alg::EdDSA).is_none());
        assert!(jwks.keys().iter().all(|k| k.kid().is_none()));
    }

    #[test]
    fn key_type_decides_the_algorithm_when_alg_member_is_absent() {
        let jwks = parse(&[ed(r#","kid":"e""#), ec(r#","kid":"p""#), oct(r#","kid":"h""#)]);
        for (kid, ok) in [("e", Alg::EdDSA), ("p", Alg::ES256), ("h", Alg::HS256)] {
            for alg in [Alg::EdDSA, Alg::ES256, Alg::HS256] {
                assert_eq!(jwks.find(kid, alg).is_some(), alg == ok, "{kid} with {alg}");
            }
        }
    }

    #[test]
    fn alg_member_must_equal_the_header_algorithm() {
        let jwks = parse(&[ed(r#","kid":"e","alg":"EdDSA""#), ec(r#","kid":"p","alg":"EdDSA""#)]);
        assert!(jwks.find("e", Alg::EdDSA).is_some());
        // Declared alg disagrees with the algorithm the token asks for.
        let jwks = parse(&[ec(r#","kid":"p","alg":"ES384""#)]);
        assert!(jwks.find("p", Alg::ES256).is_none());
        let jwks = parse(&[ed(r#","kid":"e","alg":"eddsa""#)]);
        assert!(jwks.find("e", Alg::EdDSA).is_none());
    }

    #[test]
    fn alg_member_cannot_make_a_key_fit_the_wrong_type() {
        // An Ed25519 key that claims ES256 must not verify an ES256 token.
        let jwks = parse(&[ed(r#","kid":"e","alg":"ES256""#)]);
        assert!(jwks.find("e", Alg::ES256).is_none());
        assert!(jwks.find("e", Alg::EdDSA).is_none());
        // Same for an oct key claiming EdDSA.
        let jwks = parse(&[oct(r#","kid":"h","alg":"EdDSA""#)]);
        assert!(jwks.find("h", Alg::EdDSA).is_none());
    }

    #[test]
    fn use_member_must_be_sig() {
        let jwks = parse(&[
            ed(r#","kid":"sig","use":"sig""#),
            ed(r#","kid":"enc","use":"enc""#),
            ed(r#","kid":"none""#),
            ed(r#","kid":"caps","use":"SIG""#),
        ]);
        assert!(jwks.find("sig", Alg::EdDSA).is_some());
        assert!(jwks.find("none", Alg::EdDSA).is_some());
        assert!(jwks.find("enc", Alg::EdDSA).is_none());
        assert!(jwks.find("caps", Alg::EdDSA).is_none());
    }

    #[test]
    fn non_string_alg_or_use_makes_the_key_unusable() {
        let jwks = parse(&[
            ed(r#","kid":"a","alg":1"#),
            ed(r#","kid":"b","use":null"#),
            ed(r#","kid":"c","alg":["EdDSA"]"#),
        ]);
        assert_eq!(jwks.len(), 3);
        for kid in ["a", "b", "c"] {
            assert!(jwks.find(kid, Alg::EdDSA).is_none(), "{kid}");
        }
    }

    #[test]
    fn unusable_keys_stay_in_the_set_without_failing_the_parse() {
        let bad = [
            // Unsupported key type.
            r#"{"kid":"rsa","kty":"RSA","n":"AQAB","e":"AQAB"}"#.to_string(),
            // Wrong curve for the key type.
            format!(r#"{{"kid":"crv","kty":"OKP","crv":"Ed448","x":"{ED_X}"}}"#),
            format!(r#"{{"kid":"crv2","kty":"EC","crv":"P-384","x":"{P_X}","y":"{P_Y}"}}"#),
            // Wrong length.
            r#"{"kid":"short","kty":"OKP","crv":"Ed25519","x":"AAAA"}"#.to_string(),
            // Not base64url, or not canonical.
            r#"{"kid":"b64","kty":"OKP","crv":"Ed25519","x":"not base64url!"}"#.to_string(),
            r#"{"kid":"pad","kty":"oct","k":"Zg=="}"#.to_string(),
            r#"{"kid":"noncanon","kty":"oct","k":"Zh"}"#.to_string(),
            // Missing members.
            r#"{"kid":"nox","kty":"OKP","crv":"Ed25519"}"#.to_string(),
            format!(r#"{{"kid":"noy","kty":"EC","crv":"P-256","x":"{P_X}"}}"#),
            r#"{"kid":"nok","kty":"oct"}"#.to_string(),
            r#"{"kid":"nokty"}"#.to_string(),
            // Empty secret.
            r#"{"kid":"empty","kty":"oct","k":""}"#.to_string(),
            // Members of the wrong JSON type.
            r#"{"kid":"num","kty":"oct","k":5}"#.to_string(),
            r#"{"kid":"ktynum","kty":1}"#.to_string(),
        ];
        let jwks = parse(&bad);
        assert_eq!(jwks.len(), bad.len());
        for key in jwks.keys() {
            assert!(key.material().is_none(), "{:?}", key.kid());
            for alg in [Alg::EdDSA, Alg::ES256, Alg::HS256] {
                assert!(jwks.find(key.kid().unwrap(), alg).is_none());
            }
        }
    }

    #[test]
    fn an_unusable_key_does_not_hide_a_good_one() {
        let jwks = parse(&[
            r#"{"kid":"rsa","kty":"RSA"}"#.to_string(),
            ed(r#","kid":"e""#),
        ]);
        assert!(jwks.find("e", Alg::EdDSA).is_some());
    }

    #[test]
    fn duplicate_kid_is_a_configuration_error() {
        let doc = set(&[ed(r#","kid":"k""#), ec(r#","kid":"k""#)]);
        assert_eq!(
            Jwks::parse(doc.as_bytes()),
            Err(JwksError::DuplicateKid { kid: "k".into() })
        );
    }

    #[test]
    fn duplicate_kid_is_detected_even_among_unusable_keys() {
        let doc = set(&[
            r#"{"kid":"k","kty":"RSA"}"#.to_string(),
            r#"{"kid":"k","kty":"RSA"}"#.to_string(),
        ]);
        assert_eq!(
            Jwks::parse(doc.as_bytes()),
            Err(JwksError::DuplicateKid { kid: "k".into() })
        );
    }

    #[test]
    fn kids_differing_only_in_case_are_distinct() {
        let jwks = parse(&[ed(r#","kid":"k""#), ed(r#","kid":"K""#)]);
        assert_eq!(jwks.len(), 2);
    }

    #[test]
    fn structural_errors() {
        let cases: [(&str, JwksError); 6] = [
            ("[]", JwksError::NotAnObject),
            (r#""keys""#, JwksError::NotAnObject),
            (r#"{}"#, JwksError::MissingKeys),
            (r#"{"keys":{}}"#, JwksError::KeysNotArray),
            (r#"{"keys":[1]}"#, JwksError::KeyNotObject { index: 0 }),
            (
                r#"{"keys":[{"kty":"oct","k":"AA","kid":"a"},{"kid":7}]}"#,
                JwksError::KidNotString { index: 1 },
            ),
        ];
        for (doc, expected) in cases {
            assert_eq!(Jwks::parse(doc.as_bytes()), Err(expected), "{doc}");
        }
    }

    #[test]
    fn invalid_json_and_duplicate_json_members_are_errors() {
        assert!(matches!(Jwks::parse(b""), Err(JwksError::Json(_))));
        assert!(matches!(Jwks::parse(b"{\"keys\":["), Err(JwksError::Json(_))));
        // Duplicate member names inside a key are rejected by the JSON layer.
        let doc = format!(r#"{{"keys":[{{"kid":"a","kid":"b","kty":"OKP","crv":"Ed25519","x":"{ED_X}"}}]}}"#);
        assert!(matches!(
            Jwks::parse(doc.as_bytes()),
            Err(JwksError::Json(JsonError::DuplicateKey { .. }))
        ));
        // And so are duplicate top-level members, so a second "keys" cannot win.
        let doc = r#"{"keys":[],"keys":[]}"#;
        assert!(matches!(
            Jwks::parse(doc.as_bytes()),
            Err(JwksError::Json(JsonError::DuplicateKey { .. }))
        ));
    }

    #[test]
    fn unknown_and_private_members_are_ignored() {
        let jwks = parse(&[ed(r#","kid":"e","d":"AAAA","key_ops":["verify"],"x5u":"https://evil.invalid/""#)]);
        assert!(jwks.find("e", Alg::EdDSA).is_some());
        let doc = format!(r#"{{"note":"extra","keys":[{}]}}"#, ed(r#","kid":"e""#));
        assert!(Jwks::parse(doc.as_bytes()).is_ok());
    }

    #[test]
    fn key_accessors_report_members_as_written() {
        let jwks = parse(&[ed(r#","kid":"e","alg":"EdDSA","use":"sig""#)]);
        let key = jwks.find("e", Alg::EdDSA).unwrap();
        assert_eq!(key.kid(), Some("e"));
        assert_eq!(key.alg_member(), Some("EdDSA"));
        assert_eq!(key.use_member(), Some("sig"));
    }
}
