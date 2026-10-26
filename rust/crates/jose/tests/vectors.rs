//! Runs the shared test vectors under `testvectors/` against the Rust
//! verifier (ADR 0002). Every implementation must produce the verdict in
//! `expect`; a rejection must match on the exact error code (ADR 0003).
//!
//! `rfc_signatures_match_when_kid_is_absent` additionally checks the
//! published signature bytes of the RFC examples whose headers have no
//! `kid`. Those shared verdicts are `key_not_found` and never reach the
//! signature check.

use std::fs;
use std::path::{Path, PathBuf};

use jose::alg::Alg;
use jose::b64url;
use jose::json::{self, Value};
use jose::jwks::Jwks;
use jose::signature;
use jose::verify::{self, Policy};

fn testvectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors")
}

fn vector_files() -> Vec<PathBuf> {
    let root = testvectors_dir();
    let mut files = Vec::new();
    for sub in ["generated", "rfc"] {
        let dir = root.join(sub);
        if !dir.is_dir() {
            continue;
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
            .map(|e| e.expect("readable directory entry").path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        entries.sort();
        files.append(&mut entries);
    }
    files
}

fn string<'a>(value: &'a Value, name: &str, case: &str) -> &'a str {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{case}: {name:?} must be a string"))
}

fn integer(value: &Value, name: &str, case: &str) -> i64 {
    value
        .get(name)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{case}: {name:?} must be an integer"))
}

/// Serializes a parsed JSON value back to text so the `jwks` member of a
/// vector can be handed to `Jwks::parse` exactly as written semantically.
/// The crate has no serializer (it only parses), so this is test-local.
fn write_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n {
            json::Number::Int(i) => out.push_str(&i.to_string()),
            json::Number::Other(s) => out.push_str(s),
        },
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            for (i, (name, member)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(name, out);
                out.push(':');
                write_json(member, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn optional_policy_string(value: &Value, name: &str, case: &str) -> Option<String> {
    match value.get(name) {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => panic!("{case}: policy.{name} must be a string"),
    }
}

fn policy_from(value: &Value, case: &str) -> Policy {
    let algorithms = value
        .get("algs")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{case}: policy.algs must be an array"))
        .iter()
        .map(|alg| {
            let name = alg.as_str().unwrap_or_else(|| panic!("{case}: alg must be a string"));
            Alg::from_name(name).unwrap_or_else(|| panic!("{case}: unknown alg {name:?}"))
        })
        .collect();
    Policy {
        algorithms,
        issuer: optional_policy_string(value, "iss", case),
        audience: optional_policy_string(value, "aud", case),
        now: integer(value, "now", case),
        leeway: value
            .get("leeway")
            .map(|v| u64::try_from(v.as_i64().expect("leeway is an integer")).expect("leeway >= 0"))
            .unwrap_or(0),
        typ: optional_policy_string(value, "typ", case),
        max_token_bytes: value
            .get("max_token_bytes")
            .map(|v| {
                usize::try_from(v.as_i64().expect("max_token_bytes is an integer"))
                    .expect("max_token_bytes >= 0")
            })
            .unwrap_or(8192),
    }
}

fn run_vector(path: &Path) {
    let case = path.display().to_string();
    let text = fs::read(path).unwrap_or_else(|e| panic!("{case}: cannot read: {e}"));
    let root = json::parse(&text).unwrap_or_else(|e| panic!("{case}: invalid JSON: {e}"));

    let id = string(&root, "id", &case);
    let stem = path.file_stem().unwrap().to_str().unwrap();
    assert_eq!(id, stem, "{case}: id must equal the file name");
    assert!(!string(&root, "source", &case).is_empty(), "{case}: empty source");

    let mut jwks_text = String::new();
    write_json(
        root.get("jwks").unwrap_or_else(|| panic!("{case}: missing jwks")),
        &mut jwks_text,
    );
    let jwks = Jwks::parse(jwks_text.as_bytes())
        .unwrap_or_else(|e| panic!("{case}: JWKS is a configuration error: {e}"));

    let policy = policy_from(
        root.get("policy").unwrap_or_else(|| panic!("{case}: missing policy")),
        &case,
    );
    let token = string(&root, "token", &case);
    let expect = root.get("expect").unwrap_or_else(|| panic!("{case}: missing expect"));
    let ok = match expect.get("ok") {
        Some(Value::Bool(b)) => *b,
        _ => panic!("{case}: expect.ok must be a boolean"),
    };

    match (ok, verify::verify(token.as_bytes(), &jwks, &policy)) {
        (true, Ok(verified)) => {
            if let Some(kid) = expect.get("kid") {
                assert_eq!(verified.kid, kid.as_str().expect("kid is a string"), "{case}: kid");
            }
            if let Some(alg) = expect.get("alg") {
                assert_eq!(
                    verified.alg.name(),
                    alg.as_str().expect("alg is a string"),
                    "{case}: alg"
                );
            }
        }
        (true, Err(e)) => panic!("{case}: expected success, got {}", e.code()),
        (false, Ok(_)) => panic!("{case}: expected rejection, token verified"),
        (false, Err(e)) => {
            let expected = string(expect, "error", &case);
            assert_eq!(e.code(), expected, "{case}: wrong error code");
        }
    }
}

#[test]
fn shared_vectors_match_the_rust_verifier() {
    let files = vector_files();
    assert!(
        !files.is_empty(),
        "no vectors found under {}; the contract must not be empty",
        testvectors_dir().display()
    );
    for file in &files {
        run_vector(file);
    }
}

/// RFC 7515 Appendix A.1, RFC 7515 Appendix A.3, and RFC 8037 Appendix A.4
/// publish valid signatures on headers that have no `kid`. ADR 0003 returns
/// `key_not_found` before the signature is checked, so the shared verdict does
/// not lock those bytes. This test does.
#[test]
fn rfc_signatures_match_when_kid_is_absent() {
    let cases = [
        ("rfc7515-a1-hs256", Alg::HS256),
        ("rfc7515-a3-es256", Alg::ES256),
        ("rfc8037-a4-eddsa", Alg::EdDSA),
    ];
    for (id, alg) in cases {
        let path = testvectors_dir().join("rfc").join(format!("{id}.json"));
        let text = fs::read(&path).unwrap_or_else(|e| panic!("{id}: cannot read: {e}"));
        let root = json::parse(&text).unwrap_or_else(|e| panic!("{id}: invalid JSON: {e}"));
        assert_eq!(
            root.get("expect")
                .and_then(|expect| expect.get("error"))
                .and_then(Value::as_str),
            Some("key_not_found"),
            "{id}: shared verdict"
        );

        let mut jwks_text = String::new();
        write_json(
            root.get("jwks").unwrap_or_else(|| panic!("{id}: missing jwks")),
            &mut jwks_text,
        );
        let jwks = Jwks::parse(jwks_text.as_bytes())
            .unwrap_or_else(|e| panic!("{id}: JWKS is a configuration error: {e}"));
        let material = jwks
            .keys()
            .iter()
            .find_map(|key| key.material())
            .unwrap_or_else(|| panic!("{id}: no usable key"));

        let token = string(&root, "token", id);
        let (signing_input, signature_segment) = token
            .rsplit_once('.')
            .unwrap_or_else(|| panic!("{id}: token has no signature separator"));
        let signature_bytes = b64url::decode(signature_segment)
            .unwrap_or_else(|_| panic!("{id}: signature segment is not canonical base64url"));
        signature::verify(alg, material, signing_input.as_bytes(), &signature_bytes)
            .unwrap_or_else(|_| panic!("{id}: published signature did not verify"));
    }
}
