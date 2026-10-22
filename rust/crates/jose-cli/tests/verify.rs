//! Integration tests for `jose-cli verify`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_jose-cli"))
}

fn testvectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testvectors")
}

fn write_json(value: &jose::json::Value, out: &mut String) {
    match value {
        jose::json::Value::Null => out.push_str("null"),
        jose::json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        jose::json::Value::Number(n) => match n {
            jose::json::Number::Int(i) => out.push_str(&i.to_string()),
            jose::json::Number::Other(s) => out.push_str(s),
        },
        jose::json::Value::String(s) => {
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
        jose::json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        jose::json::Value::Object(members) => {
            out.push('{');
            for (i, (name, member)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&jose::json::Value::String(name.clone()), out);
                out.push(':');
                write_json(member, out);
            }
            out.push('}');
        }
    }
}

#[test]
fn verify_matches_shared_vectors() {
    let root = testvectors_dir();
    let mut paths = Vec::new();
    for sub in ["generated", "rfc"] {
        let dir = root.join(sub);
        let mut found: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("vectors directory {}: {e}", dir.display()))
            .map(|e| e.expect("entry").path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        found.sort();
        assert!(!found.is_empty(), "expected vectors in {}", dir.display());
        paths.append(&mut found);
    }

    for path in paths {
        let case = path.display().to_string();
        let text = fs::read_to_string(&path).expect("read vector");
        let root = jose::json::parse(text.as_bytes()).expect("vector JSON");
        let id = root.get("id").and_then(jose::json::Value::as_str).expect("id");
        assert_eq!(id, path.file_stem().unwrap().to_str().unwrap());

        let mut jwks_text = String::new();
        write_json(root.get("jwks").expect("jwks"), &mut jwks_text);
        let mut policy_text = String::new();
        write_json(root.get("policy").expect("policy"), &mut policy_text);
        let token = root.get("token").and_then(jose::json::Value::as_str).expect("token");

        let tmp = std::env::temp_dir().join(format!("jose-cli-{id}"));
        fs::create_dir_all(&tmp).expect("temp dir");
        let jwks_file = tmp.join("jwks.json");
        let policy_file = tmp.join("policy.json");
        fs::write(&jwks_file, jwks_text).expect("write jwks");
        fs::write(&policy_file, policy_text).expect("write policy");

        let mut output = Command::new(bin())
            .args([
                "verify",
                "--jwks",
                jwks_file.to_str().unwrap(),
                "--policy",
                policy_file.to_str().unwrap(),
                "--token",
                "-",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn jose-cli");

        {
            use std::io::Write;
            let mut stdin = output.stdin.take().expect("stdin");
            stdin.write_all(token.as_bytes()).expect("write token");
        }

        let finished = output.wait_with_output().expect("wait");
        let stdout = String::from_utf8(finished.stdout).expect("utf8 stdout");
        let expect = root.get("expect").expect("expect");
        let expect_ok = match expect.get("ok") {
            Some(jose::json::Value::Bool(b)) => *b,
            _ => panic!("{case}: expect.ok must be a boolean"),
        };

        if expect_ok {
            assert_eq!(finished.status.code(), Some(0), "{case}: {stdout}");
            let parsed = jose::json::parse(stdout.trim().as_bytes()).expect("verdict JSON");
            assert_eq!(parsed.get("ok"), Some(&jose::json::Value::Bool(true)));
            if let Some(kid) = expect.get("kid") {
                assert_eq!(parsed.get("kid"), Some(kid));
            }
            if let Some(alg) = expect.get("alg") {
                assert_eq!(parsed.get("alg"), Some(alg));
            }
        } else {
            assert_eq!(finished.status.code(), Some(1), "{case}: {stdout}");
            let parsed = jose::json::parse(stdout.trim().as_bytes()).expect("verdict JSON");
            assert_eq!(parsed.get("ok"), Some(&jose::json::Value::Bool(false)));
            assert_eq!(
                parsed.get("error").and_then(jose::json::Value::as_str),
                expect.get("error").and_then(jose::json::Value::as_str)
            );
        }

        let _ = fs::remove_dir_all(&tmp);
    }
}

#[test]
fn jwks_configuration_error_exits_two() {
    let tmp = std::env::temp_dir().join("jose-cli-config-err");
    fs::create_dir_all(&tmp).expect("temp dir");
    let policy_file = tmp.join("policy.json");
    fs::write(&policy_file, br#"{"algs":["EdDSA"],"now":0}"#).expect("write policy");
    let jwks_file = tmp.join("jwks.json");
    fs::write(
        &jwks_file,
        br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"dup"},{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"dup"}]}"#,
    )
    .expect("write jwks");

    let output = Command::new(bin())
        .args([
            "verify",
            "--jwks",
            jwks_file.to_str().unwrap(),
            "--policy",
            policy_file.to_str().unwrap(),
            "--token",
            "a.b.c",
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let _ = fs::remove_dir_all(&tmp);
}
