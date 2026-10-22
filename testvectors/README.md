# Test vectors

This directory is the M0 verifier contract described by
`docs/adr/0002-vectors-are-the-contract.md`.

- `schema.json` defines the vector schema.
- `rfc/` is for vectors copied from RFC text.
- `generated/` is for project-generated vectors (negative and boundary cases).

Each case is one JSON file. The file name must equal the vector `id`.

The Rust verifier runs every case under `generated/` and `rfc/`:

```bash
cd rust
cargo test -p jose --test vectors
cargo test -p jose-cli --test verify
```

Or run a single case with the CLI (after `cargo build -p jose-cli`), writing the vector's
`jwks` and `policy` members to files and piping `token` on stdin:

```bash
./target/debug/jose-cli verify --jwks jwks.json --policy policy.json --token -
```

That harness (`rust/crates/jose/tests/vectors.rs`) fails if no vectors are
found, if an `id` does not match its file name, or if a verdict differs —
rejections must match on the exact error code. `generated/` covers the ADR 0003
minimum negative vector set plus positive time-boundary cases. `rfc/` holds
compact serializations copied from RFC 7515 Appendix A.1–A.5 and Appendix E,
and from RFC 8037 Appendix A.4.

The protected headers in these files have no `kid`. Appendix A.5 and Appendix E
also use an empty signature segment. Under ADR 0003 the verdicts are:

| Vector | Result | What the case locks |
|---|---|---|
| `rfc7515-a1-hs256` | `key_not_found` | Missing `kid`. The Rust signature test checks the HMAC. |
| `rfc7515-a2-rs256` | `alg_not_allowed` | `RS256` is outside the allowlist. The JWKS is empty; `kty` `RSA` is outside the schema. |
| `rfc7515-a3-es256` | `key_not_found` | Missing `kid`. The Rust signature test checks the ES256 signature. |
| `rfc7515-a4-es512` | `alg_not_allowed` | `ES512` is outside the allowlist. |
| `rfc7515-a5-none` | `malformed` | Empty signature segment, which fails before `alg` is read. |
| `rfc7515-e-crit` | `malformed` | Empty signature segment, which fails before `crit` is read. |
| `rfc8037-a4-eddsa` | `key_not_found` | Missing `kid`. The Rust signature test checks the EdDSA signature. |

Policies for the Appendix A.1 payload use `now` `1300819379`, one second before
that payload's `exp`, and omit `iss` and `aud`. The Zig verifier and Go harness
will run the same files.
