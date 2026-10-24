//! Integration tests for `jose-cli jwks`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use jose::alg::Alg;
use jose::json::{self, Value};
use jose::jwks::Jwks;
use jose::signing::sign_compact;
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
    let dir = std::env::temp_dir().join(format!("jose-cli-jwks-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write temp file");
    path
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
fn jwks_from_keygen_round_trips_through_verify() {
    let key = keygen("EdDSA");
    let jwk = key.get("jwk").expect("jwk");
    let kid = field(jwk, "kid");
    let mut key_text = String::new();
    write_json(&key, &mut key_text);
    let key_path = write_temp("key.json", key_text.as_bytes());

    let output = run(&["jwks", "--key", key_path.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let jwks_text = String::from_utf8(output.stdout).unwrap();
    let jwks = Jwks::parse(jwks_text.trim_end().as_bytes()).unwrap();

    let pkcs8 = jose::b64url::decode(field(&key, "pkcs8")).unwrap();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#);
    let token = sign_compact(Alg::EdDSA, &pkcs8, header.as_bytes(), br#"{"exp":101}"#).unwrap();
    let verified = verify::verify(token.as_bytes(), &jwks, &policy(Alg::EdDSA)).unwrap();
    assert_eq!(verified.kid, kid);
}

#[test]
fn jwks_accepts_bare_jwk_and_multiple_keys() {
    let ed = keygen("EdDSA");
    let es = keygen("ES256");
    let ed_jwk = ed.get("jwk").expect("jwk");
    let es_jwk = es.get("jwk").expect("jwk");

    let mut bare = String::new();
    write_json(ed_jwk, &mut bare);
    let bare_path = write_temp("bare.json", bare.as_bytes());

    let mut es_text = String::new();
    write_json(&es, &mut es_text);
    let es_path = write_temp("es.json", es_text.as_bytes());

    let output = run(&[
        "jwks",
        "--key",
        bare_path.to_str().unwrap(),
        "--key",
        es_path.to_str().unwrap(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let root = json::parse(String::from_utf8(output.stdout).unwrap().trim_end().as_bytes()).unwrap();
    let keys = root.get("keys").and_then(Value::as_array).expect("keys");
    assert_eq!(keys.len(), 2);
    assert_eq!(field(&keys[0], "kid"), field(ed_jwk, "kid"));
    assert_eq!(field(&keys[1], "kid"), field(es_jwk, "kid"));
}

#[test]
fn jwks_rejects_usage_and_input_errors() {
    let key = keygen("EdDSA");
    let mut key_text = String::new();
    write_json(&key, &mut key_text);
    let key_path = write_temp("ok.json", key_text.as_bytes());
    let key_p = key_path.to_str().unwrap();

    let no_kid = write_temp(
        "no-kid.json",
        br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    );
    let dup_a = write_temp(
        "dup-a.json",
        br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"same"}"#,
    );
    let dup_b = write_temp(
        "dup-b.json",
        br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"same"}"#,
    );
    let not_key = write_temp("not-key.json", br#"{"alg":"EdDSA","pkcs8":"AA"}"#);

    for (args, stderr_has) in [
        (vec!["jwks"], "missing --key"),
        (vec!["jwks", "--key"], "--key requires a path"),
        (vec!["jwks", "--key", key_p, "extra"], "unexpected argument"),
        (
            vec!["jwks", "--key", no_kid.to_str().unwrap()],
            "kid must be a non-empty string",
        ),
        (
            vec![
                "jwks",
                "--key",
                dup_a.to_str().unwrap(),
                "--key",
                dup_b.to_str().unwrap(),
            ],
            "duplicate",
        ),
        (
            vec!["jwks", "--key", not_key.to_str().unwrap()],
            "expected a keygen object",
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
