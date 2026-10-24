//! Integration tests for `jose-cli sign`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use jose::alg::Alg;
use jose::json::{self, Value};
use jose::jwks::Jwks;
use jose::verify::{self, Policy};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_jose-cli"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("run jose-cli")
}

fn keygen(alg: &str) -> Value {
    let output = run(&["keygen", "--alg", alg]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    json::parse(&output.stdout).expect("keygen JSON")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{name} must be a string"))
}

fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jose-cli-sign-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write temp file");
    path
}

fn jwk_to_jwks(jwk: &Value) -> String {
    let mut out = String::from(r#"{"keys":["#);
    write_json(jwk, &mut out);
    out.push_str("]}");
    out
}

fn write_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n {
            jose::json::Number::Int(i) => out.push_str(&i.to_string()),
            jose::json::Number::Other(s) => out.push_str(s),
        },
        Value::String(s) => {
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
                write_json(&Value::String(name.clone()), out);
                out.push(':');
                write_json(member, out);
            }
            out.push('}');
        }
    }
}

#[test]
fn sign_eddsa_round_trips_through_verify() {
    let key = keygen("EdDSA");
    let jwk = key.get("jwk").expect("jwk");
    let kid = field(jwk, "kid");

    let key_path = write_temp("key.json", &{
        let mut s = String::new();
        write_json(&key, &mut s);
        s.into_bytes()
    });
    let header_path = write_temp(
        "header.json",
        format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#).as_bytes(),
    );
    let payload_path = write_temp("payload.json", br#"{"exp":101}"#);

    let output = run(&[
        "sign",
        "--key",
        key_path.to_str().unwrap(),
        "--header",
        header_path.to_str().unwrap(),
        "--payload",
        payload_path.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.ends_with(b"\n"));

    let token = String::from_utf8(output.stdout).expect("utf8 token");
    let jwks = Jwks::parse(jwk_to_jwks(jwk).as_bytes()).unwrap();
    let verified = verify::verify(token.as_bytes(), &jwks, &policy(Alg::EdDSA)).unwrap();
    assert_eq!(verified.kid, kid);
    assert_eq!(verified.alg, Alg::EdDSA);
}

#[test]
fn sign_es256_round_trips_through_verify() {
    let key = keygen("ES256");
    let jwk = key.get("jwk").expect("jwk");
    let kid = field(jwk, "kid");

    let key_path = write_temp("es-key.json", &{
        let mut s = String::new();
        write_json(&key, &mut s);
        s.into_bytes()
    });
    let header_path = write_temp(
        "es-header.json",
        format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#).as_bytes(),
    );
    let payload_path = write_temp("es-payload.json", br#"{"exp":101}"#);

    let output = run(&[
        "sign",
        "--key",
        key_path.to_str().unwrap(),
        "--header",
        header_path.to_str().unwrap(),
        "--payload",
        payload_path.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let token = String::from_utf8(output.stdout).expect("utf8 token");
    let jwks = Jwks::parse(jwk_to_jwks(jwk).as_bytes()).unwrap();
    let verified = verify::verify(token.as_bytes(), &jwks, &policy(Alg::ES256)).unwrap();
    assert_eq!(verified.kid, kid);
    assert_eq!(verified.alg, Alg::ES256);
}

#[test]
fn sign_rejects_usage_and_input_errors() {
    let key = keygen("EdDSA");
    let jwk = key.get("jwk").expect("jwk");
    let kid = field(jwk, "kid");
    let mut key_text = String::new();
    write_json(&key, &mut key_text);
    let key_path = write_temp("err-key.json", key_text.as_bytes());
    let header_path = write_temp(
        "err-header.json",
        format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#).as_bytes(),
    );
    let payload_path = write_temp("err-payload.json", br#"{"exp":101}"#);
    let key_p = key_path.to_str().unwrap();
    let header_p = header_path.to_str().unwrap();
    let payload_p = payload_path.to_str().unwrap();

    let bad_key = write_temp("bad-key.json", br#"{"alg":"EdDSA"}"#);
    let hs_key = write_temp(
        "hs-key.json",
        br#"{"alg":"HS256","pkcs8":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
    );
    let mismatch_header = write_temp(
        "mismatch-header.json",
        format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#).as_bytes(),
    );

    for (args, stderr_has) in [
        (vec!["sign"], "missing --key"),
        (vec!["sign", "--key", key_p], "missing --header"),
        (
            vec!["sign", "--key", key_p, "--header", header_p],
            "missing --payload",
        ),
        (
            vec![
                "sign",
                "--key",
                key_p,
                "--header",
                header_p,
                "--payload",
                payload_p,
                "extra",
            ],
            "unexpected argument",
        ),
        (
            vec![
                "sign",
                "--key",
                bad_key.to_str().unwrap(),
                "--header",
                header_p,
                "--payload",
                payload_p,
            ],
            "pkcs8 must be a string",
        ),
        (
            vec![
                "sign",
                "--key",
                hs_key.to_str().unwrap(),
                "--header",
                header_p,
                "--payload",
                payload_p,
            ],
            "verify-only",
        ),
        (
            vec![
                "sign",
                "--key",
                key_p,
                "--header",
                mismatch_header.to_str().unwrap(),
                "--payload",
                payload_p,
            ],
            "alg does not match",
        ),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(stderr_has), "{args:?}: {stderr}");
    }
}

fn policy(alg: Alg) -> Policy {
    Policy {
        algorithms: vec![alg],
        issuer: None,
        audience: None,
        now: 100,
        leeway: 0,
        typ: None,
        max_token_bytes: 8192,
    }
}
