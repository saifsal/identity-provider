# ADR 0001: EdDSA (Ed25519) is the default signing algorithm

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The server must choose which JWS algorithm it uses to sign tokens by default, and
which algorithms the verifiers accept. JOSE offers many, and several are known
sources of real vulnerabilities (`none`, shared-secret `HS*` accepted where an
asymmetric key was intended, RSA PKCS#1 v1.5 implementation bugs).

Constraints specific to this project:

- The JOSE layer is written by hand in two or three languages, so a smaller,
  simpler algorithm set means fewer places for implementations to diverge.
- Zig's standard library provides Ed25519 and ECDSA P-256 but, to my knowledge,
  no RSA verification.
- The test vectors must be reproducible. Deterministic signatures make that easy.

## Decision

1. **`EdDSA` with Ed25519 is the default** for signing and the only algorithm in
   the default policy.
2. **`ES256` is supported** for interoperability with clients and key stores that
   do not offer Ed25519.
3. **`HS256` is verify-only** and exists solely so the RFC 7515 Appendix A.1 vector
   can pass. It is never in a default policy and the signer cannot produce it.
4. **`RS256` is a Rust-only stretch goal** and is documented as skipped in Zig.
5. **`none` is never accepted**, under any policy. It is not a member of the
   algorithm enum.

## Consequences

- Ed25519 signatures are deterministic, so the Rust signer can be checked against
  RFC 8037 Appendix A byte for byte. ES256 signatures are randomized, so the RFC
  7515 A.3 vector is verified only, and ES256 signing is tested by round trip.
- ES256 signatures in JWS are the raw 64-byte `R || S` concatenation, not DER.
  Verifiers must reject DER-encoded signatures and wrong-length signatures
  (`bad_signature`).
- A relying party that only supports RS256 cannot consume these tokens. That is an
  accepted limitation for an educational server.
- Keeping `HS256` out of the policy by default removes the RS256-to-HS256 key
  confusion class by construction. The negative vector `neg-hs256-confusion`
  proves it.

## Open question

The JOSE working group has been moving toward fully specified algorithm
identifiers (for example `Ed25519` in place of the polymorphic `EdDSA`). I have
not verified the current registration status. Check the IANA JOSE registry before
the first public release and, if the new identifiers are registered, supersede this
ADR to say which identifier is emitted and which are accepted.

## Alternatives considered

- **RS256 as default.** Widest compatibility, but larger keys and signatures, a
  history of padding and implementation bugs, and no Zig support.
- **ES256 as default.** Good compatibility and well understood, but nondeterministic
  signatures complicate vectors, and a bad nonce source breaks key secrecy.
- **Accept any algorithm the key supports.** Rejected. The allowlist must come from
  configuration, never from the token (RFC 8725 section 3.1).
