//! Command-line front end for the `jose` library.
//!
//! Exit codes:
//! - `0` — success (`verify` accepted the token, or `keygen` / `sign` / `jwks` / `gen-vectors` wrote output)
//! - `1` — `verify` rejected the token (verdict on stdout)
//! - `2` — usage or configuration error (message on stderr, no verdict)

#![forbid(unsafe_code)]

mod gen_vectors;

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use jose::alg::Alg;
use jose::b64url;
use jose::json::{self, Value};
use jose::jwk::PublicKey;
use jose::jwks::Jwks;
use jose::signing::{self, SigningError};
use jose::verify::{self, Policy};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        process::exit(2);
    }
    match args[1].as_str() {
        "verify" => run_verify(&args[2..]),
        "keygen" => run_keygen(&args[2..]),
        "sign" => run_sign(&args[2..]),
        "jwks" => run_jwks(&args[2..]),
        "gen-vectors" => run_gen_vectors(&args[2..]),
        "help" | "--help" | "-h" => {
            usage(&args[0]);
            process::exit(0);
        }
        _ => {
            eprintln!("{}: unknown subcommand {:?}", args[0], args[1]);
            usage(&args[0]);
            process::exit(2);
        }
    }
}

fn usage(bin: &str) {
    eprintln!(
        "usage:\n\
  {bin} verify --jwks PATH --policy PATH [--token PATH|-]\n\
  {bin} keygen --alg EdDSA|ES256 [--kid KID]\n\
  {bin} sign --key PATH --header PATH --payload PATH\n\
  {bin} jwks --key PATH [--key PATH ...]\n\
  {bin} gen-vectors [--out DIR]\n\
  {bin} help\n\
\n\
verify reads a compact JWS/JWT and prints a JSON verdict on stdout.\n\
If --token is omitted or '-', the token bytes are read from stdin.\n\
Configuration errors (bad JWKS or policy JSON) exit 2 with no verdict.\n\
\n\
keygen prints a JSON object on stdout. pkcs8 is the unpadded base64url\n\
encoding of a PKCS#8 v2 private key. jwk is the public key. When --kid is\n\
omitted, kid is the RFC 7638 thumbprint. HS256 is verify-only.\n\
\n\
sign reads a keygen JSON object from --key, protected-header JSON from\n\
--header, and payload JSON from --payload, then prints a compact JWS on\n\
stdout with no trailing newline. HS256 is verify-only.\n\
\n\
jwks builds a JWKS document from one or more --key files. Each file is a\n\
keygen JSON object (uses its jwk member) or a bare JWK object. The result\n\
is validated with the same parser verify uses, then printed on stdout.\n\
\n\
gen-vectors writes the ADR 0003 generated vector set to --out (default\n\
testvectors/generated). Generation is deterministic for EdDSA; the ES256\n\
DER case is a fixed committed token."
    );
}

fn run_gen_vectors(args: &[String]) {
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = Some(expect_path("gen-vectors", args, i, "--out"));
            }
            other => {
                eprintln!("gen-vectors: unexpected argument {:?}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    let out = out.unwrap_or_else(|| PathBuf::from("testvectors/generated"));
    if !out.exists() {
        if let Some(parent) = out.parent() {
            if parent != Path::new("") && !parent.exists() {
                eprintln!(
                    "gen-vectors: {} does not exist; pass --out or run from the repository root",
                    out.display()
                );
                process::exit(2);
            }
        }
    }

    match gen_vectors::run(&out) {
        Ok(n) => {
            eprintln!("gen-vectors: wrote {n} files to {}", out.display());
        }
        Err(e) => {
            eprintln!("gen-vectors: {e}");
            process::exit(2);
        }
    }
}

fn run_verify(args: &[String]) {
    let mut jwks_path: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut token_path: Option<Option<PathBuf>> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--jwks" => {
                i += 1;
                jwks_path = Some(expect_path("verify", args, i, "--jwks"));
            }
            "--policy" => {
                i += 1;
                policy_path = Some(expect_path("verify", args, i, "--policy"));
            }
            "--token" => {
                i += 1;
                let raw = expect_value("verify", args, i, "--token");
                token_path = Some(if raw == "-" {
                    None
                } else {
                    Some(PathBuf::from(raw))
                });
            }
            other => {
                eprintln!("verify: unexpected argument {:?}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    let jwks_path = jwks_path.unwrap_or_else(|| {
        eprintln!("verify: missing --jwks");
        process::exit(2);
    });
    let policy_path = policy_path.unwrap_or_else(|| {
        eprintln!("verify: missing --policy");
        process::exit(2);
    });

    let jwks_bytes = read_file("verify", &jwks_path, "JWKS");
    let jwks = match Jwks::parse(&jwks_bytes) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("verify: {e}");
            process::exit(2);
        }
    };

    let policy_bytes = read_file("verify", &policy_path, "policy");
    let policy_value = match json::parse(&policy_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("verify: policy is not valid JSON: {e}");
            process::exit(2);
        }
    };
    let policy = match policy_from_value(&policy_value, "policy file") {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("verify: {msg}");
            process::exit(2);
        }
    };

    let token_bytes = match token_path {
        None => read_stdin_token(),
        Some(None) => read_stdin_token(),
        Some(Some(path)) => read_file("verify", &path, "token"),
    };

    match verify::verify(&token_bytes, &jwks, &policy) {
        Ok(verified) => {
            println!(
                "{{\"ok\":true,\"kid\":{},\"alg\":{}}}",
                json_string(&verified.kid),
                json_string(verified.alg.name())
            );
        }
        Err(e) => {
            println!("{{\"ok\":false,\"error\":{}}}", json_string(e.code()));
            process::exit(1);
        }
    }
}

fn run_keygen(args: &[String]) {
    let mut alg_name: Option<String> = None;
    let mut kid: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--alg" => {
                i += 1;
                alg_name = Some(expect_value("keygen", args, i, "--alg"));
            }
            "--kid" => {
                i += 1;
                kid = Some(expect_value("keygen", args, i, "--kid"));
            }
            other => {
                eprintln!("keygen: unexpected argument {:?}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    let alg_name = alg_name.unwrap_or_else(|| {
        eprintln!("keygen: missing --alg");
        process::exit(2);
    });
    let alg = Alg::from_name(&alg_name).unwrap_or_else(|| {
        eprintln!("keygen: unknown alg {alg_name:?}");
        process::exit(2);
    });
    if let Some(kid) = &kid {
        if kid.is_empty() {
            eprintln!("keygen: --kid must be non-empty");
            process::exit(2);
        }
    }

    let generated = match signing::generate_signing_key(alg) {
        Ok(key) => key,
        Err(SigningError::UnsupportedAlgorithm) => {
            eprintln!("keygen: {alg_name} is verify-only");
            process::exit(2);
        }
        Err(e) => {
            eprintln!("keygen: {e}");
            process::exit(2);
        }
    };

    let kid = kid.unwrap_or_else(|| generated.public.thumbprint());
    let pkcs8 = b64url::encode(&generated.pkcs8);
    println!(
        "{{\"alg\":{},\"pkcs8\":{},\"jwk\":{}}}",
        json_string(alg.name()),
        json_string(&pkcs8),
        public_jwk(&generated.public, &kid)
    );
}

fn run_sign(args: &[String]) {
    let mut key_path: Option<PathBuf> = None;
    let mut header_path: Option<PathBuf> = None;
    let mut payload_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                key_path = Some(expect_path("sign", args, i, "--key"));
            }
            "--header" => {
                i += 1;
                header_path = Some(expect_path("sign", args, i, "--header"));
            }
            "--payload" => {
                i += 1;
                payload_path = Some(expect_path("sign", args, i, "--payload"));
            }
            other => {
                eprintln!("sign: unexpected argument {:?}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    let key_path = key_path.unwrap_or_else(|| {
        eprintln!("sign: missing --key");
        process::exit(2);
    });
    let header_path = header_path.unwrap_or_else(|| {
        eprintln!("sign: missing --header");
        process::exit(2);
    });
    let payload_path = payload_path.unwrap_or_else(|| {
        eprintln!("sign: missing --payload");
        process::exit(2);
    });

    let key_bytes = read_file("sign", &key_path, "key");
    let key_value = match json::parse(&key_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("sign: key is not valid JSON: {e}");
            process::exit(2);
        }
    };
    let (alg, pkcs8) = match signing_key_from_value(&key_value) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("sign: {msg}");
            process::exit(2);
        }
    };
    if matches!(alg, Alg::HS256) {
        eprintln!("sign: HS256 is verify-only");
        process::exit(2);
    }

    let header = read_file("sign", &header_path, "header");
    let payload = read_file("sign", &payload_path, "payload");

    match signing::sign_compact(alg, &pkcs8, &header, &payload) {
        Ok(token) => {
            let mut out = io::stdout();
            out.write_all(token.as_bytes()).unwrap_or_else(|e| {
                eprintln!("sign: cannot write token: {e}");
                process::exit(2);
            });
        }
        Err(e) => {
            eprintln!("sign: {e}");
            process::exit(2);
        }
    }
}

fn run_jwks(args: &[String]) {
    let mut key_paths: Vec<PathBuf> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                key_paths.push(expect_path("jwks", args, i, "--key"));
            }
            other => {
                eprintln!("jwks: unexpected argument {:?}", other);
                process::exit(2);
            }
        }
        i += 1;
    }

    if key_paths.is_empty() {
        eprintln!("jwks: missing --key");
        process::exit(2);
    }

    let mut jwks = String::from(r#"{"keys":["#);
    for (index, path) in key_paths.iter().enumerate() {
        let bytes = read_file("jwks", path, "key");
        let value = match json::parse(&bytes) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("jwks: key {} is not valid JSON: {e}", path.display());
                process::exit(2);
            }
        };
        let jwk = match jwk_from_key_file(&value) {
            Ok(j) => j,
            Err(msg) => {
                eprintln!("jwks: key {}: {msg}", path.display());
                process::exit(2);
            }
        };
        if index > 0 {
            jwks.push(',');
        }
        write_json(jwk, &mut jwks);
    }
    jwks.push_str("]}");

    if let Err(e) = Jwks::parse(jwks.as_bytes()) {
        eprintln!("jwks: {e}");
        process::exit(2);
    }

    println!("{jwks}");
}

fn jwk_from_key_file(value: &Value) -> Result<&Value, String> {
    if value.as_object().is_none() {
        return Err("must be a JSON object".into());
    }
    let jwk = if let Some(jwk) = value.get("jwk") {
        if jwk.as_object().is_none() {
            return Err("jwk must be a JSON object".into());
        }
        jwk
    } else if value.get("kty").and_then(Value::as_str).is_some() {
        value
    } else {
        return Err("expected a keygen object with jwk, or a bare JWK with kty".into());
    };
    match jwk.get("kid").and_then(Value::as_str) {
        Some(kid) if !kid.is_empty() => Ok(jwk),
        _ => Err("jwk kid must be a non-empty string".into()),
    }
}

fn signing_key_from_value(value: &Value) -> Result<(Alg, Vec<u8>), String> {
    if value.as_object().is_none() {
        return Err("key must be a JSON object".into());
    }
    let alg_name = value
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| "key: alg must be a string".to_string())?;
    let alg = Alg::from_name(alg_name).ok_or_else(|| format!("key: unknown alg {alg_name:?}"))?;
    let pkcs8_b64 = value
        .get("pkcs8")
        .and_then(Value::as_str)
        .ok_or_else(|| "key: pkcs8 must be a string".to_string())?;
    let pkcs8 = b64url::decode(pkcs8_b64).map_err(|_| "key: pkcs8 is not valid base64url".to_string())?;
    Ok((alg, pkcs8))
}

fn write_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n {
            json::Number::Int(i) => out.push_str(&i.to_string()),
            json::Number::Other(s) => out.push_str(s),
        },
        Value::String(s) => out.push_str(&json_string(s)),
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
                out.push_str(&json_string(name));
                out.push(':');
                write_json(member, out);
            }
            out.push('}');
        }
    }
}

fn public_jwk(public: &PublicKey, kid: &str) -> String {
    match public {
        PublicKey::Ed25519 { x } => format!(
            "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":{},\"kid\":{}}}",
            json_string(&b64url::encode(x)),
            json_string(kid)
        ),
        PublicKey::P256 { x, y } => format!(
            "{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":{},\"y\":{},\"kid\":{}}}",
            json_string(&b64url::encode(x)),
            json_string(&b64url::encode(y)),
            json_string(kid)
        ),
    }
}

fn expect_path(cmd: &str, args: &[String], i: usize, flag: &str) -> PathBuf {
    match args.get(i) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("{cmd}: {flag} requires a path");
            process::exit(2);
        }
    }
}

fn expect_value(cmd: &str, args: &[String], i: usize, flag: &str) -> String {
    match args.get(i) {
        Some(v) => v.clone(),
        None => {
            eprintln!("{cmd}: {flag} requires a value");
            process::exit(2);
        }
    }
}

fn read_file(cmd: &str, path: &PathBuf, label: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("{cmd}: cannot read {label} {}: {e}", path.display());
        process::exit(2);
    })
}

fn read_stdin_token() -> Vec<u8> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
        eprintln!("verify: cannot read token from stdin: {e}");
        process::exit(2);
    });
    if buf.is_empty() {
        eprintln!("verify: empty token");
        process::exit(2);
    }
    buf
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
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
    out
}

fn policy_from_value(value: &Value, label: &str) -> Result<Policy, String> {
    if value.as_object().is_none() {
        return Err(format!("{label} must be a JSON object"));
    }

    let algorithms = value
        .get("algs")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{label}: algs must be an array"))?
        .iter()
        .map(|alg| {
            let name = alg
                .as_str()
                .ok_or_else(|| format!("{label}: each alg must be a string"))?;
            Alg::from_name(name).ok_or_else(|| format!("{label}: unknown alg {name:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let now = integer_field(value, "now", label)?;

    let leeway = match value.get("leeway") {
        None => 0,
        Some(v) => {
            let n = integer_field_value(v, "leeway", label)?;
            u64::try_from(n).map_err(|_| format!("{label}: leeway must be non-negative"))?
        }
    };

    let max_token_bytes = match value.get("max_token_bytes") {
        None => 8192,
        Some(v) => {
            let n = integer_field_value(v, "max_token_bytes", label)?;
            usize::try_from(n).map_err(|_| format!("{label}: max_token_bytes must be non-negative"))?
        }
    };

    Ok(Policy {
        algorithms,
        issuer: value.get("iss").and_then(Value::as_str).map(str::to_owned),
        audience: value.get("aud").and_then(Value::as_str).map(str::to_owned),
        now,
        leeway,
        typ: value.get("typ").and_then(Value::as_str).map(str::to_owned),
        max_token_bytes,
    })
}

fn integer_field(value: &Value, name: &str, label: &str) -> Result<i64, String> {
    let v = value
        .get(name)
        .ok_or_else(|| format!("{label}: missing {name}"))?;
    integer_field_value(v, name, label)
}

fn integer_field_value(v: &Value, name: &str, label: &str) -> Result<i64, String> {
    v.as_i64()
        .ok_or_else(|| format!("{label}: {name} must be an integer"))
}
