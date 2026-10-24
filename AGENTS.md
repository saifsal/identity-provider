# identity-provider

## Overview

identity-provider is an educational OAuth 2.0 / OpenID Connect identity provider. Its purpose is to learn the protocols by implementing the layers underneath them (JOSE, token issuance, verification, and later the OAuth and OIDC flows) and to compare independent implementations of the same security-critical code with a shared test-vector contract. It has had no external review. It is not a production identity provider.

Milestone M0 is in progress. The checked-in implementation is the Rust library crate `jose` at `rust/crates/jose`. That crate signs and verifies compact JWS/JWT payloads, parses JWK and JWKS documents, computes RFC 7638 thumbprints, and enforces the verifier rules in `docs/adr/0003-verifier-check-order.md`. Rust signing of EdDSA and ES256, including compact serialization, is implemented. Generated vectors covering the ADR 0003 minimum negative set and positive time-boundary cases now exist under `testvectors/generated/`. Compact RFC examples live under `testvectors/rfc/`. Still outstanding for M0: the remaining `jose-cli` subcommands (`jwks`, `gen-vectors`), a Zig verifier, and a Go differential harness. Later milestones (OAuth, OIDC, token lifecycle, authentication, control plane, federation) are planned and have no code yet.

The next step is written in [`docs/rfc-conformance.md`](docs/rfc-conformance.md). That document is the M0 scope, the evidence that exists today, and the completion rule: do not treat a behavior as conformant until shared vectors exercise it. Accepted decisions that constrain that work are in [`docs/adr/`](docs/adr/). The milestone list through M8 is in [`README.md`](README.md).

## Repository layout

```
.
├── docs/
│   ├── adr/
│   │   ├── 0001-eddsa-default.md          # EdDSA default; HS256 verify-only; no `none`
│   │   ├── 0002-vectors-are-the-contract.md
│   │   └── 0003-verifier-check-order.md   # exact check order and error codes
│   └── rfc-conformance.md                 # current M0 plan and remaining work
├── rust/
│   ├── Cargo.toml                         # workspace; members jose and jose-cli
│   ├── Cargo.lock
│   ├── mise.toml                          # rust = "stable"
│   ├── crates/jose/
│       ├── Cargo.toml                     # package jose 0.1.0, edition 2021, publish = false
│       ├── src/
│       │   ├── lib.rs                     # #![forbid(unsafe_code)]; module root
│       │   ├── alg.rs                     # EdDSA, ES256, HS256
│       │   ├── b64url.rs                  # strict unpadded canonical base64url
│       │   ├── json.rs                    # strict JSON parser (duplicate keys rejected)
│       │   ├── jwk.rs                     # Ed25519 and P-256 public keys; thumbprints
│       │   ├── jwks.rs                    # JWKS parse and kid selection
│       │   ├── signature.rs               # signature verification
│       │   ├── signing.rs                 # EdDSA and ES256 signing; compact JWS
│       │   └── verify.rs                  # compact JWS/JWT verification and claims
│       ├── tests/thumbprint.rs            # RFC 8037 Appendix A thumbprint vectors
│       └── tests/vectors.rs               # runs testvectors/ against the Rust verifier
│   └── crates/jose-cli/
│       ├── Cargo.toml                     # binary jose-cli (verify, keygen, sign)
│       ├── src/main.rs
│       ├── tests/keygen.rs
│       ├── tests/sign.rs
│       └── tests/verify.rs                # runs jose-cli against testvectors/
├── testvectors/
│   ├── generated/                         # ADR 0003 negative and boundary vectors
│   ├── rfc/                               # compact examples copied from RFC 7515 and RFC 8037
│   └── schema.json                        # vector schema
├── LICENSE                                # GNU GPL version 3
├── README.md
└── AGENTS.md
```

These paths are described in older notes and are not in the tree: `zig/`, `go/`, `docs/threat-model.md`, and `.github/workflows/`. When another language is added, give it its own `mise.toml` in that directory.

## Setup

Prerequisites:

- Rust stable, 1.88 or newer. `slice::as_chunks` is used in `rust/crates/jose/src/b64url.rs`. Rust 1.83 fails to compile the crate with `E0658` (`slice_as_chunks` still unstable). `rust/mise.toml` pins `rust = "stable"`.
- A C compiler. The only crate dependency, `ring` 0.17, builds native code.
- Network access on the first build, to fetch the crates.io packages locked in `rust/Cargo.lock`.

With [mise](https://mise.jdx.dev/) installed, from a shell where mise is activated:

```bash
cd rust
mise install
```

`mise` was not installed in the environment used to check this repository. The build, test, and clippy commands below were run with rustup's stable toolchain (`rustc 1.99.0`) as `cargo +stable …` from `rust/`, because the default toolchain there was Rust 1.83.0. Use whichever `cargo` is actually stable 1.88 or newer. `cargo +stable` is only valid when rustup has a toolchain named `stable`.

## Build, run and test

There is no binary, server, or `cargo run` target. The crate is a library (`publish = false`) and is not published to crates.io.

From `rust/`, with stable Rust on `PATH`:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets --all-features -- -D warnings
```

All three succeeded on `rustc 1.99.0` (`cargo +stable` from `rust/`). `cargo test --workspace` ran 70 unit tests, 8 integration tests in `tests/thumbprint.rs`, 2 tests in `tests/vectors.rs` (the shared-vector run, plus the RFC signature check), 9 integration tests in `jose-cli` (`tests/verify.rs`, `tests/keygen.rs`, and `tests/sign.rs`), and 0 doc-tests.

Run one integration test, or that test file:

```bash
cargo test -p jose rfc8037_a3_thumbprint
cargo test -p jose --test thumbprint -- rfc8037_a3_thumbprint
cargo test -p jose --test thumbprint
```

The first command filters every target by that name, so the library unit tests report zero matches and `tests/thumbprint.rs` runs `rfc8037_a3_thumbprint`. That is what happened when the command was run.

`cargo fmt --all -- --check` is not a clean gate today. There is no `rustfmt.toml`, and rustfmt reports diffs in existing sources. Do not reformat unrelated code while changing behavior.

## Code style and conventions

- Edition 2021. The crate root is `#![forbid(unsafe_code)]`.
- The only dependency is `ring`. Hashes, Ed25519, ECDSA P-256, and HMAC come from `ring`. JOSE parsing, canonical base64url, JSON, key selection, and claim checks are written in this crate. There is no `serde` and no `zeroize` dependency.
- JSON object member names are unique after unescaping. The hand-written parser exists so duplicate keys are errors. `exp` and `nbf` are accepted only as integer JSON numbers that fit in `i64` (`json::Number::Int`).
- Base64url is unpadded. A segment must be the canonical encoding: unused trailing bits are zero. The decoder is not constant-time and is for token text, not secret key material.
- Public error types implement `Display` and `std::error::Error`. `verify::VerifyError::code` returns the stable strings in `docs/adr/0003-verifier-check-order.md` (`malformed`, `too_large`, `alg_not_allowed`, `crit_unsupported`, `typ_mismatch`, `key_not_found`, `bad_signature`, `expired`, `not_yet_valid`, `wrong_issuer`, `wrong_audience`).
- `Alg` is `EdDSA`, `ES256`, and verify-only `HS256`. `none` is not a variant. Algorithm names match case-sensitively.
- Verification follows `docs/adr/0003-verifier-check-order.md`: size and shape, then the algorithm allowlist, then `typ` and `kid` selection, then the signature, then payload parsing and claims. The signature is checked before the payload is parsed. Keys come from the `Jwks` passed by the caller. Header `jku`, `jwk`, `x5u`, `x5c`, and `x5t` are not consulted.
- ES256 signatures are the 64-byte JOSE `R || S` form. HS256 signing returns `SigningError::UnsupportedAlgorithm`. HS256 keys shorter than 32 bytes are rejected.
- Module docs name the RFC or ADR they implement. Tests live in `#[cfg(test)]` modules next to the code, plus `rust/crates/jose/tests/thumbprint.rs` and `tests/vectors.rs` (the shared-vector runner; it re-serializes each vector's `jwks` with a test-local JSON writer because the crate has no serializer).
- `Policy.now` is an explicit Unix timestamp. Tests do not read the wall clock.
- History uses [Conventional Commits](https://www.conventionalcommits.org/), with scopes such as `feat(rust):`, `fix(rust):`, `refactor(rust):`, and `docs:`.

## CI and tooling

No CI workflow is checked in. `.github/workflows/` does not exist. `docs/adr/0002-vectors-are-the-contract.md` describes a future CI job that regenerates vectors and fails if the tree changes. That job needs `jose-cli gen-vectors` and committed vector files, which are not in the repository yet.

Local tooling that does exist:

- `rust/mise.toml` pins Rust to the stable channel.
- `rust/Cargo.lock` is committed.
- Clippy, as invoked in [Build, run and test](#build-run-and-test), passes with `-D warnings` on stable.
- rustfmt is not enforced. See the `cargo fmt` note above.

## Working rules for agents

- Keep changes small and focused.
- Run the tests before committing. From `rust/`, `cargo test --workspace` on stable Rust is the suite that exists today. Run `cargo clippy --all-targets --all-features -- -D warnings` when the change touches Rust.
- Never commit secrets. `testvectors/` is for published test keys only. Do not put real private keys, tokens, or credentials in the tree.
- Update the docs when behaviour changes. That includes `README.md`, `docs/rfc-conformance.md`, and any ADR whose decision changed. A new verifier check needs a row in `docs/adr/0003-verifier-check-order.md` and, once the vector suite exists, a case under `testvectors/` whose expected error code matches exactly.
- Use conventional commit messages.
- Read `docs/rfc-conformance.md` and the relevant ADR before changing validation, signing, or thumbprints. The vector schema in `testvectors/schema.json` and ADR 0002 are the contract between implementations, including implementations that are not written yet. Fix the implementation when it disagrees with a vector, unless the vector is shown to be wrong against the specification.
- Preserve `#![forbid(unsafe_code)]`.

## Gotchas

- The tree is the source of truth for what runs. Design notes in the ADRs and the milestone table in the README describe Zig, Go, a CLI, and an authorization server that are not implemented.
- `testvectors/generated/` holds the ADR 0003 minimum negative vector set and positive time-boundary cases. `testvectors/rfc/` holds compact examples copied from RFC 7515 and RFC 8037. Both are run against the Rust verifier by `tests/vectors.rs`. The examples whose headers have no `kid` expect `key_not_found`; their signature bytes are checked only by the Rust test `rfc_signatures_match_when_kid_is_absent`. Agreement from Zig/Go is still missing, so M0 conformance is not established. Unit tests are not a substitute for that suite; `docs/rfc-conformance.md` says so.
- `docs/threat-model.md` is not in the repository.
- Rust older than 1.88 does not compile `b64url.rs`. A default toolchain of 1.83 fails even though `Cargo.lock` resolves.
- `cargo test` does not start a server. There is nothing to run.
- `Jwks::parse` fails the whole document on bad JSON, a missing `keys` array, a non-object entry, a non-string `kid`, or a duplicate `kid`. An entry that is present but unusable (unknown `kty` or `crv`, bad base64url, wrong length, non-string `alg` or `use`, `oct` key under 32 bytes) stays in the set and can never be selected (`key_not_found`). Private members such as `d` are ignored.
- `kid` is required. There is no try-every-key fallback. A key `alg` member must equal the header `alg`. If `alg` is absent, the key type decides: `OKP`/`Ed25519` is `EdDSA`, `EC`/`P-256` is `ES256`, `oct` is `HS256`. A `use` member must be `sig`.
- `exp` is required. `nbf` is optional. When both the expiry and not-before checks fail, the error is `expired`. `typ` comparison strips one leading `application/` and then compares case-insensitively. `iss` and `aud` use exact string equality.
- Ed25519 signatures are deterministic. ES256 signatures are not, so ES256 is tested by round trip. ADR 0001 records that the RFC 7515 ES256 vector is verify-only once vector files exist.
- `PublicKey` checks coordinate lengths. It does not check that a P-256 point is on the curve; `ring` rejects an invalid point at verification time.
- This is unreviewed educational code. Cryptographic primitives come from `ring`; the JOSE layer around them is written here.
