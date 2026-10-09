# Copilot instructions for identity-provider

## Repository context

This repository is an educational OAuth 2.0 / OpenID Connect identity provider built in multiple languages, but the checked-in implementation work today is the Rust workspace under `rust/`.

The project intentionally uses a differential-testing model:

- `rust/crates/jose` contains the hand-written JOSE/JWT machinery.
- `testvectors/` is the contract between implementations; vectors are expected to be authoritative.
- `docs/adr/` records design decisions, especially the verifier check order and the rule that vectors are the contract.
- The README describes a future Rust + Zig + Go split, but the active code here is the Rust JOSE library.

When you change behavior in the JOSE layer, assume the verifier contract and vector expectations matter more than local convenience.

## Build, test, and lint commands

Always use the toolchain configured by `mise` in this repo. Rust is configured in `rust/mise.toml` on the stable channel. After changing into the folder with the `mise.toml`, run `mise install` when setting up or updating tools. When mise is activated in the shell, run project commands directly; `mise exec` / `mise x` is unnecessary.

For each independently versioned language or subproject, keep a `mise.toml` in that folder rather than combining unrelated toolchains in the repository root. From the subproject directory, run `mise use` with the desired tool and version; for Rust, `cd rust && mise use rust@stable` creates or updates `rust/mise.toml`. The file declares tools under `[tools]`, for example:

```toml
[tools]
rust = "stable"
```

Then run `mise install` in that directory. Repeat the same setup inside each other language/subproject folder using its own required tool and version. `mise` discovers the current directory's config and parent configs, so run commands from the intended subproject directory when tool versions differ. When the mise shell activation is enabled, configured tools such as `cargo` are on `PATH`.

```bash
cd rust
mise install
cargo build --workspace
cargo test --workspace
```

Run a single Rust test by name:

```bash
cd rust
cargo test -p jose rfc8037_a3_thumbprint
cargo test -p jose --test thumbprint -- rfc8037_a3_thumbprint
```

To run the integration test file only:

```bash
cd rust
cargo test -p jose --test thumbprint
```

Linting command used for this workspace:

```bash
cd rust
cargo clippy --all-targets --all-features -- -D warnings
```

Run Rust commands directly from `rust/` when mise is activated. If the shell does not have mise activated, activate it or use `mise exec -- <command>` as a fallback.

## High-level architecture

The big-picture design is described in `README.md` and ADRs:

- `docs/adr/0002-vectors-are-the-contract.md`: test vectors are the ground truth and are treated as the contract between independent implementations.
- `docs/adr/0003-verifier-check-order.md`: the verification order is intentionally strict and security-sensitive. The order matters because it prevents ambiguous/unsafe decisions before the token is authenticated.
- `rust/crates/jose`: the active implementation. This crate contains the JOSE layer: base64url handling, JSON parsing, JWK/JWKS parsing, thumbprints, signatures, and verification.
- `testvectors/`: shared positive and negative JWT/JWKS vectors used to compare implementations and catch drift.

The project is not a typical "just use a library" identity provider. The emphasis is on strict correctness, deterministic behavior, and cross-implementation comparison rather than framework-driven features.

## Project conventions and implementation expectations

These conventions are specific to this repository and matter more than generic coding advice:

- Treat `testvectors/` as authoritative. If a change affects a JWT/JWK verification rule or a key/thumbprint calculation, add or update the matching vector before considering the change complete.
- Keep verification behavior deterministic and explicit. Tests use explicit `now` values in policies so they do not depend on wall-clock time.
- Follow the strict verifier order documented in `docs/adr/0003-verifier-check-order.md`:
  - size and shape checks first
  - algorithm allowlist before key lookup
  - signature verification before payload parsing
  - claim checks last on an authenticated token
- Respect the repository's security posture: the code is intentionally hand-written and security-critical. `rust/crates/jose/src/lib.rs` forbids `unsafe` code (`#![forbid(unsafe_code)]`).
- Canonical base64url and strict JSON handling are not optional. Duplicate JSON keys, unpadded base64url, and non-canonical decodes are treated as malformed according to the ADRs.
- `kid` lookup and algorithm checks are strict. Keys come from a configured JWKS; network-fetching behaviors such as `jku` / `x5u` / embedded keys are intentionally ignored.
- For this codebase, “wrong” is not just “non-complaint”; it is “different from the vector contract or ADR-specified behavior.”

## Typical workflow for changes

When working in this repo:

1. Read the relevant ADR and the existing test vector before changing validation logic.
2. Update the Rust implementation in `rust/crates/jose`.
3. Run the smallest relevant test target first (for example, `cargo test -p jose rfc8037_a3_thumbprint` from `rust/`).
4. Re-run the relevant workspace tests if the fix affects shared JOSE behavior.
5. If the change changes public verification semantics, verify the vector set still matches the intended contract.

## Notes for future sessions

- The active implementation is Rust-first; keep changes local to the `jose` crate unless the task explicitly reaches the Zig or Go layers.
- Do not assume the README's future roadmap is implemented; the checked-in code is the current source of truth.
- This project is educational and security-sensitive, so changes in parsing/verification logic must be reviewed with a test-vector mindset.
