# RFC conformance

This document defines the intended M0 JOSE scope and tracks the evidence for
each area. It is a draft: implementation-level conformance is not established
until shared vectors exercise the behavior and all implementations agree on the
expected result, as required by ADR 0002.

**Implemented** below means Rust code exists for the listed behavior; it does not
mean that the behavior has passed the shared-vector suite. Unit tests are useful
implementation evidence, but are not a substitute for that suite.

## M0 scope

M0 covers JWS compact serialization, a deliberately small signing and
verification algorithm set, JWK/JWKS handling, RFC 7638 thumbprints, and the
JWT claims needed for the project's token profile. It does not aim to implement
all of JOSE or all JWT claims and profiles.

| Specification | In-scope sections and behavior | Current evidence / remaining work |
|---|---|---|
| RFC 7515, JWS | Compact JWS parsing and verification; protected-header handling; signing input is the ASCII `BASE64URL(protected).BASE64URL(payload)` bytes | Rust compact verification and signature primitives exist. Signing, shared RFC vectors, and Zig verification remain. JSON JWS serialization and detached payloads are out of scope. |
| RFC 7517, JWK | Public `OKP`/`Ed25519` and `EC`/`P-256` keys; `oct` keys only for HS256 verification | Rust parses these key types for the verifier. Private-key import/export, key use beyond signature verification, and other key types are out of scope. Shared-vector confirmation remains. |
| RFC 7517, JWKS | Parse a configured `keys` array and select one key by exact `kid` | Rust parsing and selection exist. Duplicate `kid` is a configuration error; there is no token-directed key fetching or fallback search. CLI behavior and shared vectors remain. |
| RFC 7518, JWA | HS256 verification only; ES256 verification with P-256 and fixed-width 64-byte signatures formed by concatenating the 32-byte R and S values | Rust verification primitives exist and reject wrong signature lengths through the verifier. HS256 keys must be at least 256 bits under RFC 7518 §3.2; the current JWKS parser accepts any non-empty secret, so this requirement remains to be enforced or explicitly resolved before claiming conformance. |
| RFC 7638, JWK thumbprints | SHA-256 thumbprints for public Ed25519 and P-256 keys using the required canonical public members | Rust implementation and RFC-derived unit tests exist. Shared vectors remain. Thumbprints for `oct` and other key types are out of scope. |
| RFC 8032, Ed25519 | Ed25519 signature verification primitive used by JOSE EdDSA | Rust implementation uses `ring`; RFC signature vectors and cross-implementation comparison remain. |
| RFC 8037, OKP / EdDSA | Ed25519 represented as `OKP`/`Ed25519` and used with JOSE `EdDSA` | Rust key parsing and verification exist. The Rust signer, RFC vectors, and Zig implementation remain. |
| RFC 7519, JWT | `iss`, `aud`, `exp`, and `nbf` checks needed by this project; integer NumericDate values only | Rust claims validation exists. This profile deliberately requires `exp`, requires `kid` for selection, rejects fractional NumericDates, and checks issuer/audience only when configured. These are project restrictions, not general JWT requirements. Shared vectors remain. |
| RFC 8725, JWT BCP | Algorithm allowlisting, issuer/audience validation when configured, explicit typing when configured, and parsing the payload only after signature verification | These decisions are specified in ADR 0003 and implemented in the Rust verifier. This does not claim full RFC 8725 conformance; shared vectors and cross-implementation verification remain. |
| RFC 9068, JWT Profile for OAuth 2.0 Access Tokens | `at+jwt` typing is supported by the verifier's configurable `typ` check | Full access-token profile validation is not in M0. Required profile claims and authorization-server behavior belong with the OAuth/OIDC milestones. |

## Deliberate restrictions and exclusions

- The accepted algorithms are EdDSA (Ed25519) and ES256, with HS256 available
  only for verification and never in the default allowlist. `none` is not
  supported. See [ADR 0001](adr/0001-eddsa-default.md).
- RSA/RS256 is not part of the baseline M0 scope. The ADR records it as a
  possible Rust-only stretch goal; it is not implemented by the current Rust
  algorithm set.
- JWE, JWS JSON serialization, detached payloads, general key management, and
  unlisted JWS algorithms are out of scope.
- Header `crit` extensions are not supported. A present `crit` value must be a
  non-empty array of strings, then the token is rejected as unsupported.
- A verifier uses only the configured JWKS. It never follows `jku` or `x5u`,
  nor trusts embedded `jwk` or certificate-chain header values.
- Duplicate JSON member names are rejected. Base64url is unpadded and canonical.
- The claim profile and check order, including project-specific deviations, are
  specified in [ADR 0003](adr/0003-verifier-check-order.md).

## Other RFCs referenced by the project

These specifications inform later milestones or provide context, but are not
conformance targets for M0:

| Specification | Planned relevance |
|---|---|
| RFC 6749, OAuth 2.0 | Authorization-server and authorization-code flow work after M0 |
| RFC 7636, PKCE | Authorization-code flow hardening after M0 |
| RFC 9700, OAuth 2.0 Security BCP | Later OAuth hardening milestone |
| OpenID Connect Core 1.0 | Later OIDC milestone |

## Completion criteria

Do not mark an item fully conformant based only on implementation or unit
tests. For M0, record the RFC-derived or generated shared vectors that exercise
the item, run them against every implemented verifier, and resolve all
disagreements according to [ADR 0002](adr/0002-vectors-are-the-contract.md).
Update this map when a scope decision changes or a known gap is closed.
