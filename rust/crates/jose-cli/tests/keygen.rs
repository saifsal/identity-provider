//! Integration tests for `jose-cli keygen`.

use std::path::PathBuf;
use std::process::Command;

use jose::alg::Alg;
use jose::b64url;
use jose::json::{self, Value};
use jose::jwk::PublicKey;
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

fn stdout_json(output: &std::process::Output) -> Value {
    assert_eq!(output.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    json::parse(&output.stdout).expect("keygen JSON")
}

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{name} must be a string"))
}

#[test]
fn keygen_eddsa_prints_a_key_that_signs() {
    let root = stdout_json(&run(&["keygen", "--alg", "EdDSA"]));
    assert_eq!(field(&root, "alg"), "EdDSA");
    let jwk = root.get("jwk").expect("jwk");
    assert_eq!(field(jwk, "kty"), "OKP");
    assert_eq!(field(jwk, "crv"), "Ed25519");
    let x = field(jwk, "x");
    let kid = field(jwk, "kid");
    let public = PublicKey::ed25519_from_bytes(&b64url::decode(x).unwrap()).unwrap();
    assert_eq!(public.thumbprint(), kid);

    let pkcs8 = b64url::decode(field(&root, "pkcs8")).unwrap();
    let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}"}}"#);
    let token = sign_compact(Alg::EdDSA, &pkcs8, header.as_bytes(), br#"{"exp":101}"#).unwrap();
    let jwks = Jwks::parse(
        format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","kid":"{kid}"}}]}}"#)
            .as_bytes(),
    )
    .unwrap();
    let verified = verify::verify(token.as_bytes(), &jwks, &policy(Alg::EdDSA)).unwrap();
    assert_eq!(verified.kid, kid);
    assert_eq!(verified.alg, Alg::EdDSA);
}

#[test]
fn keygen_es256_prints_a_key_that_signs() {
    let root = stdout_json(&run(&["keygen", "--alg", "ES256"]));
    assert_eq!(field(&root, "alg"), "ES256");
    let jwk = root.get("jwk").expect("jwk");
    assert_eq!(field(jwk, "kty"), "EC");
    assert_eq!(field(jwk, "crv"), "P-256");
    let x = field(jwk, "x");
    let y = field(jwk, "y");
    let kid = field(jwk, "kid");
    let public = PublicKey::p256_from_coordinates(
        &b64url::decode(x).unwrap(),
        &b64url::decode(y).unwrap(),
    )
    .unwrap();
    assert_eq!(public.thumbprint(), kid);

    let pkcs8 = b64url::decode(field(&root, "pkcs8")).unwrap();
    let header = format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#);
    let token = sign_compact(Alg::ES256, &pkcs8, header.as_bytes(), br#"{"exp":101}"#).unwrap();
    let jwks = Jwks::parse(
        format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","kid":"{kid}"}}]}}"#
        )
        .as_bytes(),
    )
    .unwrap();
    let verified = verify::verify(token.as_bytes(), &jwks, &policy(Alg::ES256)).unwrap();
    assert_eq!(verified.kid, kid);
    assert_eq!(verified.alg, Alg::ES256);
}

#[test]
fn keygen_uses_an_explicit_kid() {
    let root = stdout_json(&run(&["keygen", "--alg", "EdDSA", "--kid", "custom-1"]));
    let jwk = root.get("jwk").expect("jwk");
    assert_eq!(field(jwk, "kid"), "custom-1");
    let public = PublicKey::ed25519_from_bytes(&b64url::decode(field(jwk, "x")).unwrap()).unwrap();
    assert_ne!(public.thumbprint(), "custom-1");
}

#[test]
fn keygen_rejects_usage_errors() {
    for (args, stderr_has) in [
        (vec!["keygen"], "missing --alg"),
        (vec!["keygen", "--alg"], "--alg requires a value"),
        (vec!["keygen", "--alg", "HS256"], "verify-only"),
        (vec!["keygen", "--alg", "none"], "unknown alg"),
        (vec!["keygen", "--alg", "EdDSA", "--kid", ""], "--kid must be non-empty"),
        (vec!["keygen", "--alg", "EdDSA", "extra"], "unexpected argument"),
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
