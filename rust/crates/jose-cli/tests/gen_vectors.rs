//! Integration tests for `jose-cli gen-vectors`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn policy_from_value(value: &Value) -> Policy {
    let algorithms = value
        .get("algs")
        .and_then(Value::as_array)
        .expect("algs")
        .iter()
        .map(|a| jose::alg::Alg::from_name(a.as_str().expect("alg str")).expect("known alg"))
        .collect();
    Policy {
        algorithms,
        issuer: value.get("iss").and_then(Value::as_str).map(str::to_owned),
        audience: value.get("aud").and_then(Value::as_str).map(str::to_owned),
        now: value.get("now").and_then(Value::as_i64).expect("now"),
        leeway: value
            .get("leeway")
            .and_then(Value::as_i64)
            .map(|n| u64::try_from(n).expect("leeway"))
            .unwrap_or(0),
        typ: value.get("typ").and_then(Value::as_str).map(str::to_owned),
        max_token_bytes: value
            .get("max_token_bytes")
            .and_then(Value::as_i64)
            .map(|n| usize::try_from(n).expect("max"))
            .unwrap_or(8192),
    }
}

#[test]
fn gen_vectors_is_deterministic_and_matches_verifier() {
    let dir_a = std::env::temp_dir().join(format!("jose-gen-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("jose-gen-b-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir_a);
    let _ = fs::remove_dir_all(&dir_b);

    for dir in [&dir_a, &dir_b] {
        let output = run(&["gen-vectors", "--out", dir.to_str().unwrap()]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut names_a: Vec<_> = fs::read_dir(&dir_a)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let mut names_b: Vec<_> = fs::read_dir(&dir_b)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names_a.sort();
    names_b.sort();
    assert_eq!(names_a, names_b);
    assert_eq!(names_a.len(), 39);

    for name in &names_a {
        let a = fs::read(dir_a.join(name)).unwrap();
        let b = fs::read(dir_b.join(name)).unwrap();
        assert_eq!(a, b, "{name:?}");
    }

    for name in names_a {
        let path = dir_a.join(&name);
        let text = fs::read_to_string(&path).unwrap();
        let root = json::parse(text.as_bytes()).expect("vector JSON");
        let id = root.get("id").and_then(Value::as_str).unwrap();
        assert_eq!(id, Path::new(&name).file_stem().unwrap().to_str().unwrap());

        let mut jwks_text = String::new();
        write_json(root.get("jwks").unwrap(), &mut jwks_text);
        let jwks = Jwks::parse(jwks_text.as_bytes()).unwrap();
        let policy = policy_from_value(root.get("policy").unwrap());
        let token = root.get("token").and_then(Value::as_str).unwrap();
        let expect = root.get("expect").unwrap();

        match expect.get("ok") {
            Some(Value::Bool(true)) => {
                let verified = verify::verify(token.as_bytes(), &jwks, &policy).unwrap();
                assert_eq!(verified.kid, expect.get("kid").and_then(Value::as_str).unwrap());
                assert_eq!(
                    verified.alg.name(),
                    expect.get("alg").and_then(Value::as_str).unwrap()
                );
            }
            Some(Value::Bool(false)) => {
                let err = verify::verify(token.as_bytes(), &jwks, &policy).unwrap_err();
                assert_eq!(err.code(), expect.get("error").and_then(Value::as_str).unwrap());
            }
            _ => panic!("expect.ok"),
        }
    }
}

#[test]
fn gen_vectors_rejects_usage_errors() {
    let output = run(&["gen-vectors", "extra"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
