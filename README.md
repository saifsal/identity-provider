# identity-provider

An educational OAuth 2.0 / OpenID Connect identity provider. The work checked in today is a Rust library that signs and verifies compact JWS and JWT values by hand, so the JOSE rules are visible and can later be compared across languages.

> **Educational project. Not production-ready. Do not deploy.**
> It exists to learn the protocols and to compare independent implementations of the same security-critical code. It has had no external review. For a real system, use an audited identity provider.

## What it is

Most identity code calls a JOSE library and then implements OAuth on top. This repository builds the JOSE layer itself: strict base64url, strict JSON, JWK and JWKS handling, thumbprints, signatures, and the checks a verifier runs before it trusts a token. The longer-term aim is an authorization server, with the same verifier written more than once. A shared set of test vectors, specified in [`testvectors/schema.json`](testvectors/schema.json) and [`docs/adr/0002-vectors-are-the-contract.md`](docs/adr/0002-vectors-are-the-contract.md), is how disagreements between those implementations become failing tests.

The library is the crate `jose` in [`rust/crates/jose`](rust/crates/jose). It is not published to crates.io (`publish = false`). The workspace also builds `jose-cli` with a `verify` subcommand. There is no server or other language implementation in the tree yet.

## Features

What `jose` does now:

- Compact JWS signing and verification for a JSON object payload. `jose::signing::sign_compact` keeps the protected header bytes as given. `jose::verify::verify` returns the `kid`, algorithm, and parsed claims.
- `EdDSA` (Ed25519) and `ES256` (P-256, SHA-256) signing from a PKCS#8 private key. ES256 signatures are the 64-byte JOSE concatenation of `R` and `S`, not ASN.1 DER. Ed25519 signatures are deterministic.
- Verification of `EdDSA`, `ES256`, and `HS256`. `HS256` exists so the RFC 7515 Appendix A.1 vector can be checked. The signer refuses it. `HS256` keys must be at least 32 bytes. `none` cannot be named, and `RS256` is not implemented.
- JWK public keys for `OKP` / `Ed25519` and `EC` / `P-256`, plus `oct` secrets for `HS256` verification. RFC 7638 SHA-256 thumbprints for the two public key types, covered by [`rust/crates/jose/tests/thumbprint.rs`](rust/crates/jose/tests/thumbprint.rs) (RFC 8037 Appendix A).
- JWKS parsing and lookup by exact `kid`, with the key-selection rules in [`docs/adr/0003-verifier-check-order.md`](docs/adr/0003-verifier-check-order.md).
- A strict base64url codec (unpadded, canonical trailing bits) and a strict JSON parser that rejects duplicate member names.
- Claim checks for `iss`, `aud`, `exp`, `nbf`, and `typ`, using an explicit verification time.

Cryptographic primitives come from [`ring`](https://github.com/briansmith/ring) 0.17. The JOSE layer around them is written in this crate. The crate root is `#![forbid(unsafe_code)]`.

Out of scope for this layer, and not implemented: JWE, JWS JSON serialization, detached payloads, RSA, and SAML. The planned CLI, Zig verifier, Go harness, and OAuth server are described under [Project status and roadmap](#project-status-and-roadmap). There is no UI, so this repository has no screenshots.

## Prerequisites

- Rust stable, 1.88 or newer. The base64url codec uses `slice::as_chunks`, which is unstable on Rust 1.83.
- A C compiler, because `ring` builds native code.
- Network access on the first build, to download the crates locked in [`rust/Cargo.lock`](rust/Cargo.lock).

[`rust/mise.toml`](rust/mise.toml) pins `rust = "stable"`. With [mise](https://mise.jdx.dev/) activated:

```bash
cd rust
mise install
```

The commands in the next sections were run with rustup stable (`rustc 1.99.0`) from `rust/`.

## Install

Clone the repository and build the workspace. Nothing is installed onto `PATH`.

```bash
cd rust
cargo build --workspace
```

That command succeeded with `cargo +stable build --workspace` on `rustc 1.99.0`.

## Usage

Call the library from Rust. The program below follows `signing::tests::creates_compact_jwt_that_verifies` in [`rust/crates/jose/src/signing.rs`](rust/crates/jose/src/signing.rs): generate an Ed25519 PKCS#8 key with `ring`, put its RFC 7638 thumbprint in the header as `kid`, sign a JSON object, and verify it with a JWKS that holds the matching public key. Generating the key uses `ring` directly, so the program depends on `jose` and on `ring` 0.17. This program was compiled against the crate and ran.

```rust
use jose::alg::Alg;
use jose::jwk::PublicKey;
use jose::jwks::Jwks;
use jose::signing::sign_compact;
use jose::verify::{self, Policy};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn main() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse Ed25519 key");
    let public = PublicKey::ed25519_from_bytes(pair.public_key().as_ref())
        .expect("valid Ed25519 public key");
    let kid = public.thumbprint();

    let jwks = Jwks::parse(
        format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{kid}"}}]}}"#,
            jose::b64url::encode(pair.public_key().as_ref()),
        )
        .as_bytes(),
    )
    .expect("valid JWKS");

    let header = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"at+jwt"}}"#);
    let token = sign_compact(
        Alg::EdDSA,
        pkcs8.as_ref(),
        header.as_bytes(),
        br#"{"iss":"issuer","aud":"api","exp":101}"#,
    )
    .expect("sign compact JWT");

    let verified = verify::verify(
        token.as_bytes(),
        &jwks,
        &Policy {
            algorithms: vec![Alg::EdDSA],
            issuer: Some("issuer".into()),
            audience: Some("api".into()),
            now: 100,
            leeway: 0,
            typ: Some("at+jwt".into()),
            max_token_bytes: 8192,
        },
    )
    .expect("newly signed JWT verifies");
    assert_eq!(verified.kid, kid);
    assert_eq!(verified.alg, Alg::EdDSA);
}
```

`sign` signs already-encoded ASCII `header.payload` bytes and returns the raw signature. `sign_compact` builds the three-segment token. Both reject `HS256`.

Build `jose-cli` with `cargo build --workspace`. Today it implements `verify` only; `keygen`, `jwks`, `sign`, and `gen-vectors` are still planned.

```bash
cargo build -p jose-cli
./target/debug/jose-cli verify --jwks path/to/jwks.json --policy path/to/policy.json --token -
```

`--jwks` and `--policy` are required. `--token PATH` reads the compact token from a file; omitting `--token`, or passing `--token -`, reads it from stdin. Input is used byte-for-byte and is not trimmed, so pipe a token with `printf '%s'`, not `echo`: a trailing newline makes the compact serialization malformed.

`verify` prints exactly one JSON verdict on stdout:

- `{"ok":true,"kid":"...","alg":"..."}` and exit `0` when the token verifies.
- `{"ok":false,"error":"..."}` and exit `1` when verification rejects the token. The error is one of the stable codes in [ADR 0003](docs/adr/0003-verifier-check-order.md).
- No verdict and exit `2` for usage or configuration errors, including unreadable files, an invalid JWKS or policy, and empty stdin. The explanation is written to stderr.

Policy JSON uses the field names from [`testvectors/schema.json`](testvectors/schema.json):

| Field | Required | Constraint / default |
|---|---|---|
| `algs` | Yes | Array of `EdDSA`, `ES256`, or `HS256`. An empty array rejects every token. |
| `now` | Yes | Integer Unix timestamp. The CLI does not read the system clock. |
| `iss`, `aud`, `typ` | No | Strings. An omitted or non-string field is not checked. |
| `leeway` | No | Non-negative integer seconds; defaults to `0`. |
| `max_token_bytes` | No | Non-negative integer; defaults to `8192`. |

To exercise the CLI with a committed positive vector, extract its three inputs and run the same path used by the integration test:

```bash
python3 - <<'PY'
import json
from pathlib import Path

case = json.loads(Path("../testvectors/generated/pos-exp-one-second-ahead.json").read_text())
Path("/tmp/jwks.json").write_text(json.dumps(case["jwks"]))
Path("/tmp/policy.json").write_text(json.dumps(case["policy"]))
Path("/tmp/token.jwt").write_text(case["token"])
PY

./target/debug/jose-cli verify \
  --jwks /tmp/jwks.json \
  --policy /tmp/policy.json \
  --token /tmp/token.jwt
# {"ok":true,"kid":"k1","alg":"EdDSA"}
```

Run this from `rust/`, after building the CLI. Python is only used to unpack the test-vector JSON; it is not a runtime dependency of `jose-cli`.

## Configuration

Nothing is read from the environment, a config file, or Cargo features. The caller passes a [`Policy`](rust/crates/jose/src/verify.rs) and a JWKS document.

| Field | Role |
|---|---|
| `algorithms` | Allowlist. The token header cannot add an algorithm. |
| `issuer` | When set, `iss` must equal this string. When omitted, `iss` is not checked. |
| `audience` | When set, `aud` must be that string or an array of strings containing it. |
| `now` | Verification time, Unix seconds. Expiry tests pass this in; the crate does not read the clock. |
| `leeway` | Clock skew in seconds, applied to `exp` and `nbf`. |
| `typ` | When set, the header `typ` must match, case-insensitively, after removing one leading `application/`. `at+jwt` and `application/at+jwt` match. |
| `max_token_bytes` | Tokens longer than this are `too_large`. The Rust struct has no default; the vector schema's default is 8192. |

The same field names appear in [`testvectors/schema.json`](testvectors/schema.json) and are used by the checked-in vectors under `testvectors/generated/` (`iss`, `aud`, `algs`, `now`, `leeway`, `typ`, `max_token_bytes`). RFC-derived vectors are still to be added under `testvectors/rfc/`.

JWKS JSON is an object with a `keys` array. Accepted public keys are `{"kty":"OKP","crv":"Ed25519","x":"..."}` and `{"kty":"EC","crv":"P-256","x":"...","y":"..."}`. `{"kty":"oct","k":"..."}` is for `HS256` verification only. `kid` is how a token selects a key. A duplicate `kid` is a configuration error from `Jwks::parse`. Header parameters that would fetch or embed a key (`jku`, `jwk`, `x5u`, `x5c`, `x5t`) are ignored.

The ordered checks and the exact error strings are specified in [`docs/adr/0003-verifier-check-order.md`](docs/adr/0003-verifier-check-order.md). In short: reject an oversized token, require three canonical base64url segments, parse the header, reject `crit`, enforce the algorithm allowlist and `typ`, select the key, verify the signature, and only then parse the payload and check `iss`, `aud`, `exp`, and `nbf`. `exp` is required. Fractional numeric dates are rejected.

## Development and testing

From `rust/` on stable Rust:

```bash
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
```

`cargo test --workspace` passed on `rustc 1.99.0`: 69 unit tests in `jose`, 8 tests in `tests/thumbprint.rs`, 1 vector-suite test in `tests/vectors.rs`, 2 integration tests in `jose-cli`, and no doc-tests. Clippy with `-D warnings` passed on the same toolchain.

The shared vectors under `testvectors/` run against the Rust verifier as one integration test (it loops over every case; rejections must match on the exact error code):

```bash
cargo test -p jose --test vectors
```

A single thumbprint test:

```bash
cargo test -p jose --test thumbprint -- rfc8037_a3_thumbprint
```

`cargo fmt --all -- --check` currently reports diffs. The repository has no `rustfmt.toml` and does not treat formatting as a gate.

Useful design notes while changing verification:

- [`docs/rfc-conformance.md`](docs/rfc-conformance.md) — what M0 covers, what the Rust crate already implements, and what is still missing before anything is called conformant.
- [`docs/adr/0001-eddsa-default.md`](docs/adr/0001-eddsa-default.md) — why Ed25519 is the default and why `HS256` stays out of the default allowlist.
- [`docs/adr/0002-vectors-are-the-contract.md`](docs/adr/0002-vectors-are-the-contract.md) — vectors override an implementation, except when a vector disagrees with the specification.
- [`docs/adr/0003-verifier-check-order.md`](docs/adr/0003-verifier-check-order.md) — check order, error codes, and the minimum negative-vector list.

Agent instructions for working in this repository live in [`AGENTS.md`](AGENTS.md).

## Project status and roadmap

| Milestone | Scope | Status |
|---|---|---|
| **M0** | JOSE: JWS signing and verification, JWK/JWKS, thumbprints, shared test vectors | In progress. The Rust `jose` library, ADR 0003 generated vectors, and `jose-cli verify` are in the tree. The RFC vector corpus, remaining CLI subcommands, Zig verifier, and Go harness are not. |
| M1 | OAuth 2.0 authorization code flow with PKCE | Planned |
| M2 | OpenID Connect: ID tokens, discovery, userinfo | Planned |
| M3 | Token lifecycle: refresh rotation, introspection, revocation, key rotation | Planned |
| M4 | Hardening: PAR, DPoP, RFC 9700 checklist | Planned |
| M5 | Authentication: Argon2id passwords, TOTP, WebAuthn | Planned |
| M6 | Control plane: admin API, dynamic client registration, SCIM 2.0 | Planned |
| M7 | Federation: OIDC relying-party connector, LDAP gateway | Planned |
| M8 | Assurance: OpenID conformance suite, attack harness, fuzzing in CI | Planned |

[`docs/rfc-conformance.md`](docs/rfc-conformance.md) is the working plan for M0. It records remaining evidence (shared RFC vectors and another implementation that agrees with them) and the rule for marking a behavior conformant.

The intended shape, once M0 is filled in, is three implementations of one verifier contract:

| Language | Intended component | In this repository |
|---|---|---|
| Rust | JOSE signer and, later, the authorization server core | `rust/crates/jose` only. No authorization server. |
| Zig | JOSE/JWT verifier, a C ABI, and a small edge-auth sidecar | Not started |
| Go | Control plane and the cross-implementation test harness | Not started |

```mermaid
flowchart LR
    signer[Rust signer] -->|issues token| inputs
    subgraph inputs [Inputs]
        direction TB
        tv[token]
        jv[shared JWKS]
        vv[testvectors/]
    end
    inputs --> verifiers
    subgraph verifiers [Verifiers]
        direction TB
        rv[Rust]
        zv[Zig]
        gv[Go]
    end
    verifiers --> harness{{"Go harness: do all verdicts match each other and the expectation?"}}
```

The Rust signer and the Rust verifier in that diagram exist as library functions. Generated vectors under `testvectors/generated/` now run against the Rust verifier (`cargo test -p jose --test vectors`), while the Zig verifier, Go harness, and the full RFC vector corpus are still missing.

No GitHub Actions workflow is checked in. ADR 0002 describes a future CI check that regenerates vectors and fails on a dirty tree. That check waits on the CLI and the vector files.

### Security notes

- Treat every component as unreviewed.
- SAML is deliberately not implemented. XML signature handling is a poor fit for a from-scratch project.
- Report suspected vulnerabilities by opening an issue. There is nothing here to keep private.

### Non-goals

- Production deployment or any form of support
- Full JOSE coverage (JWE, JSON serialization, every algorithm)
- SAML
- Competing with existing identity providers

## References

- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749): OAuth 2.0
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [7517](https://www.rfc-editor.org/rfc/rfc7517), [7518](https://www.rfc-editor.org/rfc/rfc7518), [7519](https://www.rfc-editor.org/rfc/rfc7519): JWS, JWK, JWA, JWT
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636): PKCE
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): JWK thumbprint
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), [8037](https://www.rfc-editor.org/rfc/rfc8037): EdDSA and its use in JOSE
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725): JWT best current practices
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): JWT profile for OAuth 2.0 access tokens
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700): OAuth 2.0 security best current practice
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

## Licence

GNU General Public License, version 3. The license text is [`LICENSE`](LICENSE). Source files do not add a separate copyright header.
