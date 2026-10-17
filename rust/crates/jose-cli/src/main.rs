//! Command-line front end for the `jose` library.
//!
//! Exit codes (ADR 0003, JWKS configuration errors):
//! - `0` — token verified
//! - `1` — token rejected (verdict on stdout)
//! - `2` — usage or configuration error (message on stderr, no verdict)

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use jose::alg::Alg;
use jose::json::{self, Value};
use jose::jwks::Jwks;
use jose::verify::{self, Policy};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        process::exit(2);
    }
    match args[1].as_str() {
        "verify" => run_verify(&args[2..]),
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
  {bin} help\n\
\n\
verify reads a compact JWS/JWT and prints a JSON verdict on stdout.\n\
If --token is omitted or '-', the token bytes are read from stdin.\n\
Configuration errors (bad JWKS or policy JSON) exit 2 with no verdict."
    );
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
                jwks_path = Some(expect_path(args, i, "--jwks"));
            }
            "--policy" => {
                i += 1;
                policy_path = Some(expect_path(args, i, "--policy"));
            }
            "--token" => {
                i += 1;
                let raw = expect_value(args, i, "--token");
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

    let jwks_bytes = read_file(&jwks_path, "JWKS");
    let jwks = match Jwks::parse(&jwks_bytes) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("verify: {e}");
            process::exit(2);
        }
    };

    let policy_bytes = read_file(&policy_path, "policy");
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
        Some(Some(path)) => read_file(&path, "token"),
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

fn expect_path(args: &[String], i: usize, flag: &str) -> PathBuf {
    match args.get(i) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("verify: {flag} requires a path");
            process::exit(2);
        }
    }
}

fn expect_value(args: &[String], i: usize, flag: &str) -> String {
    match args.get(i) {
        Some(v) => v.clone(),
        None => {
            eprintln!("verify: {flag} requires a value");
            process::exit(2);
        }
    }
}

fn read_file(path: &PathBuf, label: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("verify: cannot read {label} {}: {e}", path.display());
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
