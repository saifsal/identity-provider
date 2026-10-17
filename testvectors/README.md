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
```

That harness (`rust/crates/jose/tests/vectors.rs`) fails if no vectors are
found, if an `id` does not match its file name, or if a verdict differs —
rejections must match on the exact error code. `generated/` now covers the full
ADR 0003 minimum negative vector set plus positive time-boundary cases; the RFC
corpus under `rfc/` is not written yet, and the Zig verifier and Go harness will
run the same files.
