//! Deterministic regeneration of `testvectors/generated/` (ADR 0002 / 0003).
//!
//! Ed25519 uses the RFC 8032 test-1 seed, whose public key is the RFC 8037
//! Appendix A.2 `x` value already in the corpus. ES256 DER rejection keeps a
//! fixed token because ECDSA signatures are not deterministic.

use std::fs;
use std::path::Path;

use jose::alg::Alg;
use jose::b64url;
use jose::signing;

/// RFC 8032 §7.1 TEST 1 seed. Public key encodes to
/// `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`.
const ED25519_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const KID: &str = "k1";

/// Fixed ES256 + DER signature token (RFC 7515 Appendix A.3 public key, kid `p1`).
const ES256_DER_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6InAxIn0.eyJleHAiOjIwMH0.MEUCIA7RIVN5Y2xIPC9_FVgH1AKjsigDOvl8fheBmsMWnqZlAiEAxQoH04w8cOXY8S2vCEpUgKZlkMXyk1Cajz9_ioOjVNU";

struct ExpectOk {
    kid: &'static str,
    alg: &'static str,
}

enum Expect {
    Ok(ExpectOk),
    Err(&'static str),
}

struct Case {
    id: &'static str,
    description: &'static str,
    jwks: String,
    policy: String,
    token: String,
    expect: Expect,
}

pub fn run(out_dir: &Path) -> Result<usize, String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;

    let pkcs8 = ed25519_pkcs8_v2();
    let cases = build_cases(&pkcs8)?;

    for case in &cases {
        let path = out_dir.join(format!("{}.json", case.id));
        let text = format_case(case);
        fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(cases.len())
}

fn ed25519_pkcs8_v2() -> Vec<u8> {
    let public = b64url::decode(ED25519_X).expect("published test x");
    let mut pkcs8 = Vec::with_capacity(83);
    pkcs8.extend_from_slice(&[
        0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(&ED25519_SEED);
    pkcs8.extend_from_slice(&[0x81, 0x21, 0x00]);
    pkcs8.extend_from_slice(&public);
    pkcs8
}

fn ed_jwks() -> String {
    format!(
        r#"{{
    "keys": [
      {{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "{ED25519_X}",
        "kid": "{KID}"
      }}
    ]
  }}"#
    )
}

fn ed_jwks_with_alg(alg: &str) -> String {
    format!(
        r#"{{
    "keys": [
      {{
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "{ED25519_X}",
        "kid": "{KID}",
        "alg": "{alg}"
      }}
    ]
  }}"#
    )
}

fn empty_jwks() -> String {
    r#"{
    "keys": []
  }"#
    .into()
}

fn es256_jwks() -> String {
    r#"{
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "p1"
      }
    ]
  }"#
    .into()
}

fn policy_ed(now: i64) -> String {
    format!(
        r#"{{
    "algs": [
      "EdDSA"
    ],
    "now": {now}
  }}"#
    )
}

fn policy_ed_extra(now: i64, extra_lines: &str) -> String {
    format!(
        r#"{{
    "algs": [
      "EdDSA"
    ],
    "now": {now}{extra_lines}
  }}"#
    )
}

fn header_ed() -> &'static [u8] {
    br#"{"alg":"EdDSA","kid":"k1"}"#
}

fn sign_compact(pkcs8: &[u8], header: &[u8], payload: &[u8]) -> Result<String, String> {
    signing::sign_compact(Alg::EdDSA, pkcs8, header, payload)
        .map_err(|e| format!("sign_compact: {e}"))
}

fn sign_segments(pkcs8: &[u8], header: &[u8], payload_segment: &str) -> Result<String, String> {
    let header_segment = b64url::encode(header);
    let signing_input = format!("{header_segment}.{payload_segment}");
    let sig = signing::sign(Alg::EdDSA, pkcs8, signing_input.as_bytes())
        .map_err(|e| format!("sign: {e}"))?;
    Ok(format!("{signing_input}.{}", b64url::encode(&sig)))
}

fn unsigned(header: &[u8], payload: &[u8]) -> String {
    format!(
        "{}.{}.AA",
        b64url::encode(header),
        b64url::encode(payload)
    )
}

fn make_noncanonical_segment(canonical: &str) -> Result<String, String> {
    let bytes = b64url::decode(canonical).map_err(|e| e.to_string())?;
    // Flip the low bit of the last alphabet character when trailing bits exist.
    let mut chars: Vec<u8> = canonical.as_bytes().to_vec();
    let last = chars.last_mut().ok_or("empty segment")?;
    let flipped = match *last {
        b'A'..=b'Z' => *last ^ 1,
        b'a'..=b'z' => *last ^ 1,
        b'0'..=b'9' => *last ^ 1,
        b'-' => b'_',
        b'_' => b'-',
        _ => return Err("unexpected alphabet".into()),
    };
    *last = flipped;
    let candidate = String::from_utf8(chars).map_err(|e| e.to_string())?;
    match b64url::decode(&candidate) {
        Err(jose::b64url::DecodeError::NonCanonical) => Ok(candidate),
        Ok(other) if other == bytes => Err("flip stayed canonical".into()),
        Ok(_) => {
            // Different bytes — still useful for signature non-verify cases, but
            // for payload noncanonical we need NonCanonical specifically.
            // Try XOR 2 instead.
            let mut chars: Vec<u8> = canonical.as_bytes().to_vec();
            let last = chars.last_mut().unwrap();
            *last = match *last {
                b'A'..=b'Y' | b'a'..=b'y' | b'0'..=b'8' => *last + 1,
                b'Z' => b'a',
                b'z' => b'0',
                b'9' => b'-',
                b'-' => b'_',
                b'_' => b'A',
                c => c,
            };
            let candidate = String::from_utf8(chars).unwrap();
            match b64url::decode(&candidate) {
                Err(jose::b64url::DecodeError::NonCanonical) => Ok(candidate),
                other => Err(format!(
                    "could not craft noncanonical from {canonical:?}: {other:?}"
                )),
            }
        }
        Err(e) => Err(format!("unexpected decode error: {e}")),
    }
}

fn build_cases(pkcs8: &[u8]) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();

    let push_err = |cases: &mut Vec<Case>,
                    id: &'static str,
                    description: &'static str,
                    jwks: String,
                    policy: String,
                    token: String,
                    error: &'static str| {
        cases.push(Case {
            id,
            description,
            jwks,
            policy,
            token,
            expect: Expect::Err(error),
        });
    };

    push_err(
        &mut cases,
        "neg-alg-none",
        "Rejects alg=none at policy allowlist check.",
        empty_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"none","kid":"k1"}"#, b"{}"),
        "alg_not_allowed",
    );
    push_err(
        &mut cases,
        "neg-alg-not-in-policy",
        "Rejects token algorithm that is outside policy.algs.",
        empty_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"HS256","kid":"k1"}"#, b"{}"),
        "alg_not_allowed",
    );
    push_err(
        &mut cases,
        "neg-hs256-confusion",
        "Rejects HS256 naming an EdDSA key at the allowlist, before key use.",
        ed_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"HS256","kid":"k1"}"#, b"{}"),
        "alg_not_allowed",
    );

    push_err(
        &mut cases,
        "neg-too-large",
        "Rejects a token whose byte length exceeds max_token_bytes.",
        empty_jwks(),
        policy_ed_extra(0, ",\n    \"max_token_bytes\": 4"),
        "a.a.a".into(),
        "too_large",
    );
    push_err(
        &mut cases,
        "neg-padding",
        "Rejects '=' padding in a segment.",
        empty_jwks(),
        policy_ed(0),
        format!("{}=.e30.AA", b64url::encode(header_ed())),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-nonalphabet",
        "Rejects a character outside the base64url alphabet.",
        empty_jwks(),
        policy_ed(0),
        "a!.e30.AA".into(),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-extra-segment",
        "Rejects a token with four segments.",
        empty_jwks(),
        policy_ed(0),
        "a.b.c.d".into(),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-empty-segment",
        "Rejects a compact token with an empty segment.",
        empty_jwks(),
        policy_ed(0),
        "a..a".into(),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-b64-noncanonical-header",
        "Rejects a non-canonical base64url header segment.",
        empty_jwks(),
        policy_ed(0),
        "Zh.e30.AA".into(),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-dup-key-header",
        "Rejects duplicate member names in the header.",
        empty_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"EdDSA","alg":"EdDSA","kid":"k1"}"#, b"{}"),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-crit-empty",
        "Rejects an empty crit array as malformed.",
        empty_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"EdDSA","crit":[],"kid":"k1"}"#, b"{}"),
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-crit-unknown",
        "Rejects any crit header as unsupported.",
        empty_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"EdDSA","crit":["exp"],"kid":"k1"}"#, b"{}"),
        "crit_unsupported",
    );
    push_err(
        &mut cases,
        "neg-typ-missing",
        "Rejects a missing typ when policy requires one.",
        empty_jwks(),
        policy_ed_extra(0, ",\n    \"typ\": \"at+jwt\""),
        unsigned(header_ed(), b"{}"),
        "typ_mismatch",
    );
    push_err(
        &mut cases,
        "neg-typ-wrong",
        "Rejects a mismatched typ header before key lookup.",
        empty_jwks(),
        policy_ed_extra(0, ",\n    \"typ\": \"at+jwt\""),
        unsigned(br#"{"alg":"EdDSA","typ":"jwt"}"#, b"{}"),
        "typ_mismatch",
    );
    push_err(
        &mut cases,
        "neg-kid-missing",
        "Rejects a token with no kid header during key lookup.",
        empty_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"EdDSA"}"#, b"{}"),
        "key_not_found",
    );
    push_err(
        &mut cases,
        "neg-kid-unknown",
        "Rejects a kid that is not in the JWKS.",
        ed_jwks(),
        policy_ed(0),
        unsigned(br#"{"alg":"EdDSA","kid":"unknown"}"#, b"{}"),
        "key_not_found",
    );
    push_err(
        &mut cases,
        "neg-key-alg-mismatch",
        "Rejects a key whose alg member disagrees with the header alg.",
        ed_jwks_with_alg("ES256"),
        policy_ed(0),
        unsigned(header_ed(), b"{}"),
        "key_not_found",
    );
    push_err(
        &mut cases,
        "neg-jku-ignored",
        "Ignores jku; keys come only from the configured JWKS.",
        empty_jwks(),
        policy_ed(0),
        unsigned(
            br#"{"alg":"EdDSA","jku":"https://example.invalid/jwks.json","kid":"k1"}"#,
            b"{}",
        ),
        "key_not_found",
    );

    // Signed negative / positive cases.
    let payload_nc = make_noncanonical_segment(&b64url::encode(b"{}"))?;
    push_err(
        &mut cases,
        "neg-b64-noncanonical-payload",
        "Rejects a validly signed token whose payload segment has non-canonical trailing bits.",
        ed_jwks(),
        policy_ed(100),
        sign_segments(pkcs8, header_ed(), &payload_nc)?,
        "malformed",
    );

    let signed_exp200 = sign_compact(pkcs8, header_ed(), br#"{"exp":200}"#)?;
    let (si, sig_seg) = signed_exp200
        .rsplit_once('.')
        .ok_or("signed token shape")?;
    let sig_nc = make_noncanonical_segment(sig_seg)?;
    push_err(
        &mut cases,
        "neg-b64-noncanonical-signature",
        "Rejects a signature segment with non-zero trailing base64url bits.",
        ed_jwks(),
        policy_ed(100),
        format!("{si}.{sig_nc}"),
        "bad_signature",
    );

    let truncated_sig = {
        let mut s = sig_seg.to_string();
        s.pop();
        format!("{si}.{s}")
    };
    push_err(
        &mut cases,
        "neg-sig-truncated",
        "Rejects a signature whose decoded byte length is shorter than required.",
        ed_jwks(),
        policy_ed(100),
        truncated_sig,
        "bad_signature",
    );

    let tampered_sig = {
        let mut bytes = sig_seg.as_bytes().to_vec();
        if bytes[1] == b't' {
            bytes[1] = b'9';
        } else {
            bytes[1] = b't';
        }
        format!("{si}.{}", String::from_utf8(bytes).unwrap())
    };
    push_err(
        &mut cases,
        "neg-tampered-signature",
        "Rejects a token whose signature bytes do not verify.",
        ed_jwks(),
        policy_ed(100),
        tampered_sig,
        "bad_signature",
    );

    let signed_exp200_again = sign_compact(pkcs8, header_ed(), br#"{"exp":200}"#)?;
    let header_seg = signed_exp200_again.split('.').next().unwrap();
    let tampered_payload = format!(
        "{header_seg}.{}.{}",
        b64url::encode(br#"{"exp":999}"#),
        signed_exp200_again.split('.').nth(2).unwrap()
    );
    push_err(
        &mut cases,
        "neg-tampered-payload",
        "Rejects a token whose payload was modified after signing.",
        ed_jwks(),
        policy_ed(100),
        tampered_payload,
        "bad_signature",
    );

    push_err(
        &mut cases,
        "neg-sig-der-encoded",
        "Rejects an ASN.1 DER-encoded ECDSA signature instead of fixed-width 64-byte R || S.",
        es256_jwks(),
        r#"{
    "algs": [
      "ES256"
    ],
    "now": 100
  }"#
        .into(),
        ES256_DER_TOKEN.into(),
        "bad_signature",
    );

    let dup_payload = sign_segments(pkcs8, header_ed(), &b64url::encode(br#"{"exp":200,"exp":200}"#))?;
    push_err(
        &mut cases,
        "neg-dup-key-payload",
        "Rejects a validly signed token whose payload contains duplicate member names.",
        ed_jwks(),
        policy_ed(100),
        dup_payload,
        "malformed",
    );

    push_err(
        &mut cases,
        "neg-expired",
        "Rejects a token whose exp is in the past.",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"exp":50}"#)?,
        "expired",
    );
    push_err(
        &mut cases,
        "neg-exp-boundary",
        "Rejects a token at the exact instant now == exp (exp is the first invalid second).",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"exp":100}"#)?,
        "expired",
    );
    push_err(
        &mut cases,
        "neg-nbf-future",
        "Rejects a token whose nbf is in the future.",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"exp":200,"nbf":150}"#)?,
        "not_yet_valid",
    );
    push_err(
        &mut cases,
        "neg-nbf-boundary",
        "Rejects a token one second before nbf becomes valid.",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"exp":200,"nbf":101}"#)?,
        "not_yet_valid",
    );
    push_err(
        &mut cases,
        "neg-wrong-iss",
        "Rejects a token whose iss claim does not match policy.iss.",
        ed_jwks(),
        policy_ed_extra(100, ",\n    \"iss\": \"https://issuer.example\""),
        sign_compact(
            pkcs8,
            header_ed(),
            br#"{"iss":"https://other.example","exp":200}"#,
        )?,
        "wrong_issuer",
    );
    push_err(
        &mut cases,
        "neg-wrong-aud",
        "Rejects a token whose string aud claim does not match policy.aud.",
        ed_jwks(),
        policy_ed_extra(100, ",\n    \"aud\": \"api\""),
        sign_compact(pkcs8, header_ed(), br#"{"aud":"other-api","exp":200}"#)?,
        "wrong_audience",
    );
    push_err(
        &mut cases,
        "neg-aud-array-missing",
        "Rejects a token whose aud array does not contain policy.aud.",
        ed_jwks(),
        policy_ed_extra(100, ",\n    \"aud\": \"api\""),
        sign_compact(pkcs8, header_ed(), br#"{"aud":["a","b"],"exp":200}"#)?,
        "wrong_audience",
    );
    push_err(
        &mut cases,
        "neg-aud-array-nonstring",
        "Rejects a token whose aud array contains a non-string element.",
        ed_jwks(),
        policy_ed_extra(100, ",\n    \"aud\": \"api\""),
        sign_compact(pkcs8, header_ed(), br#"{"aud":["api",123],"exp":200}"#)?,
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-exp-string",
        "Rejects an exp claim given as a JSON string instead of an integer.",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"exp":"200"}"#)?,
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-exp-fractional",
        "Rejects a fractional NumericDate exp claim.",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"exp":200.5}"#)?,
        "malformed",
    );
    push_err(
        &mut cases,
        "neg-exp-missing",
        "Rejects a token that omits the required exp claim.",
        ed_jwks(),
        policy_ed(100),
        sign_compact(pkcs8, header_ed(), br#"{"iss":"https://issuer.example"}"#)?,
        "malformed",
    );

    cases.push(Case {
        id: "pos-exp-one-second-ahead",
        description: "Accepts a token whose exp is one second ahead of now.",
        jwks: ed_jwks(),
        policy: policy_ed(100),
        token: sign_compact(pkcs8, header_ed(), br#"{"exp":101}"#)?,
        expect: Expect::Ok(ExpectOk {
            kid: KID,
            alg: "EdDSA",
        }),
    });
    cases.push(Case {
        id: "pos-exp-within-leeway",
        description: "Accepts a token at now == exp + leeway - 1.",
        jwks: ed_jwks(),
        policy: policy_ed_extra(104, ",\n    \"leeway\": 10"),
        token: sign_compact(pkcs8, header_ed(), br#"{"exp":95}"#)?,
        expect: Expect::Ok(ExpectOk {
            kid: KID,
            alg: "EdDSA",
        }),
    });
    cases.push(Case {
        id: "pos-nbf-equal-now",
        description: "Accepts a token at the exact instant now == nbf.",
        jwks: ed_jwks(),
        policy: policy_ed(100),
        token: sign_compact(pkcs8, header_ed(), br#"{"exp":200,"nbf":100}"#)?,
        expect: Expect::Ok(ExpectOk {
            kid: KID,
            alg: "EdDSA",
        }),
    });

    cases.sort_by(|a, b| a.id.cmp(b.id));
    Ok(cases)
}

fn format_case(case: &Case) -> String {
    let expect = match &case.expect {
        Expect::Ok(ok) => format!(
            r#"{{
    "ok": true,
    "kid": "{}",
    "alg": "{}"
  }}"#,
            ok.kid, ok.alg
        ),
        Expect::Err(code) => format!(
            r#"{{
    "ok": false,
    "error": "{code}"
  }}"#
        ),
    };
    format!(
        r#"{{
  "id": "{}",
  "source": "generated",
  "description": {},
  "jwks": {},
  "policy": {},
  "token": {},
  "expect": {}
}}
"#,
        case.id,
        json_string(case.description),
        case.jwks,
        case.policy,
        json_string(&case.token),
        expect
    )
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
