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
| RFC 7515, JWS | Compact JWS parsing, signing, and verification; protected-header handling; signing input is the ASCII `BASE64URL(protected).BASE64URL(payload)` bytes | Rust compact signing and verification exist for JSON JWT payloads. Compact examples from Appendix A.1–A.5 and Appendix E are in `testvectors/rfc/` with ADR 0003 verdicts; A.1 and A.3 stop at `key_not_found` before the signature. Zig has a matching strict base64url codec; compact JWS verification remains. JSON JWS serialization and detached payloads are out of scope. |
| RFC 7517, JWK | Public `OKP`/`Ed25519` and `EC`/`P-256` keys; `oct` keys only for HS256 verification | Rust parses these key types for the verifier. Private-key import/export, key use beyond signature verification, and other key types are out of scope. Shared-vector confirmation remains. |
| RFC 7517, JWKS | Parse a configured `keys` array and select one key by exact `kid` | Rust parsing and selection exist. Duplicate `kid` is a configuration error; there is no token-directed key fetching or fallback search. `jose-cli jwks` builds a JWKS from keygen or bare JWK inputs and validates it with the same parser. Shared-vector confirmation remains. |
| RFC 7518, JWA | HS256 verification only; ES256 verification with P-256 and fixed-width 64-byte signatures formed by concatenating the 32-byte R and S values | Rust enforces the 256-bit minimum HS256 key length in JWKS parsing and signature verification. The Appendix A.1 HMAC and Appendix A.3 ES256 signature are checked by the Rust signature test in `tests/vectors.rs` because the shared verdicts return at `key_not_found`. Cross-implementation confirmation remains. |
| RFC 7638, JWK thumbprints | SHA-256 thumbprints for public Ed25519 and P-256 keys using the required canonical public members | Rust implementation and RFC-derived unit tests exist. Shared vectors remain. Thumbprints for `oct` and other key types are out of scope. |
| RFC 8032, Ed25519 | Ed25519 signature verification primitive used by JOSE EdDSA | Rust implementation uses `ring`; RFC signature vectors and cross-implementation comparison remain. |
| RFC 8037, OKP / EdDSA | Ed25519 represented as `OKP`/`Ed25519` and used with JOSE `EdDSA` | Rust key parsing, signing, and verification exist. Appendix A.4 is `testvectors/rfc/rfc8037-a4-eddsa.json` and is `key_not_found` (no `kid`); the Rust signature test checks that signature. Zig implementation remains. |
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

## Checked-in RFC vectors

`testvectors/rfc/` copies compact serializations from the RFC text. The
expected verdict is the ADR 0003 code for this profile.

- RFC 7515 Appendix A.1 (HS256) and Appendix A.3 (ES256), and RFC 8037
  Appendix A.4 (EdDSA), have no `kid`. The shared result is `key_not_found`.
  `rfc_signatures_match_when_kid_is_absent` in
  `rust/crates/jose/tests/vectors.rs` checks those published signatures against
  the keys in the same files. That Rust test is not a substitute for another
  implementation agreeing on the verdict.
- RFC 7515 Appendix A.2 (`RS256`) and Appendix A.4 (`ES512`) are
  `alg_not_allowed`. Appendix A.5 (`none`) and Appendix E (crit, unsecured)
  are `malformed` because the signature segment is empty. Those checks happen
  before key lookup.
- JSON serialization examples (RFC 7515 Appendix A.6 and A.7) and detached
  payloads are not in this directory.

These files do not establish M0 conformance. Another verifier still has to
agree, per ADR 0002.

## Completion criteria

Do not mark an item fully conformant based only on implementation or unit
tests. For M0, record the RFC-derived or generated shared vectors that exercise
the item, run them against every implemented verifier, and resolve all
disagreements according to [ADR 0002](adr/0002-vectors-are-the-contract.md).
Update this map when a scope decision changes or a known gap is closed.
