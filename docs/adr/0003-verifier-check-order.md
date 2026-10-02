# ADR 0003: Verifier check order and rules

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

Two verifiers can agree that a token is bad and still disagree on why, purely
because they check things in a different order. Under ADR 0002 the error code is
part of the contract, so the order of checks has to be specified exactly. The order
also has security consequences: what is parsed, and what key material is touched,
before the signature is verified.

## Decision

### Check order

A verifier performs these steps in order and returns the error of the first one that
fails.

| # | Check | Error |
|---|---|---|
| 1 | Token length is at most `max_token_bytes` | `too_large` |
| 2 | Exactly three segments separated by `.`, each non-empty, each using only the base64url alphabet (`A-Z a-z 0-9 - _`), with no `=` padding | `malformed` |
| 3 | Header segment decodes as canonical base64url (length mod 4 is not 1, trailing bits are zero) | `malformed` |
| 4 | Header is a JSON object with no duplicate member names | `malformed` |
| 5 | If `crit` is present: it must be a non-empty array of strings, otherwise `malformed`. Any entry at all is unsupported | `malformed` / `crit_unsupported` |
| 6 | `alg` is a string and is in `policy.algs` | `alg_not_allowed` |
| 7 | If `policy.typ` is set, header `typ` matches it | `typ_mismatch` |
| 8 | Key lookup, see below | `key_not_found` |
| 9 | Signature segment decodes to exactly the length the algorithm requires and verifies over the ASCII bytes of `segment0 "." segment1` | `bad_signature` |
| 10 | Payload segment decodes and is a JSON object with no duplicate member names | `malformed` |
| 11 | If `policy.iss` is set, `iss` is a string equal to it | `wrong_issuer` |
| 12 | If `policy.aud` is set, `aud` is a string equal to it, or an array of strings containing it. An array with a non-string member is `malformed` | `wrong_audience` / `malformed` |
| 13 | `exp` and `nbf` hold, see below | `expired` / `not_yet_valid` / `malformed` |

### Why this order

- **Cheap, attacker-independent checks first** (size, shape). A 100 KB header is
  rejected before any JSON parser sees it.
- **The algorithm allowlist is checked before key lookup** (step 6 before 8), so an
  algorithm the policy does not allow never touches key material. This is the
  structural defence against `none` and against RS256-to-HS256 style confusion.
- **The signature is verified before the payload is parsed** (step 9 before 10), so
  no attacker-supplied claim influences any decision until the token is
  authenticated. The header is the one exception, because it is needed to select the
  algorithm and key.
- **Claims are checked last,** and only on an authenticated token.

### Key lookup (step 8)

- `kid` is required. A missing or non-string `kid` is `key_not_found`. There is no
  "try every key" fallback.
- The key is the member of the JWKS whose `kid` matches exactly.
- If the key has an `alg` member, it must equal the header `alg`. If it has none,
  the permitted algorithm is derived from the key type: `OKP`/`Ed25519` gives
  `EdDSA`, `EC`/`P-256` gives `ES256`, `oct` gives `HS256`. A mismatch is
  `key_not_found`.
- If the key has a `use` member, it must be `sig`, otherwise `key_not_found`.
- A JWKS with duplicate `kid` values is a configuration error. The CLI exits with
  code 2 and reports no verdict.
- Header members `jku`, `jwk`, `x5u`, `x5c` and `x5t` are ignored. Keys come from the
  configured JWKS only, and nothing is fetched from the network.

### Claim rules (steps 10 to 13)

- `exp` is required. Its absence is `malformed`. `nbf` is optional.
- `exp` and `nbf` must be JSON numbers with integer values. A string, a boolean,
  `null`, or a fractional number is `malformed`. RFC 7519 permits fractional
  NumericDate values. Rejecting them is a deliberate deviation, because this
  server only issues integers and accepting fractions adds a place for
  implementations to diverge.
- Time comparisons use integer seconds:
  - Expired when `now >= exp + leeway`. RFC 7519 treats `exp` as the first instant
    at which the token is no longer valid.
  - Not yet valid when `now + leeway < nbf`.
- When both fail, `expired` is reported.
- `iss` and `aud` are compared by exact string equality, with no normalization,
  trailing-slash handling or case folding.
- When the policy omits `iss` or `aud`, that check is skipped. The RFC 7515
  Appendix A.1 token carries no `aud`, so its vector relies on this.

### Base64url decoding is canonical

A segment must be the canonical encoding of the bytes it decodes to: when the length
is not a multiple of 4, the unused trailing bits of the last character must be zero.
Without this rule, several different strings decode to the same bytes (for example
`Zg`, `Zh`, `Zi` and `Zj` all decode to `f`), so a token's signature segment could be
altered without changing the decoded signature. The signature still verifies, but the
token string differs, which breaks anything that keys on the token text (caches,
revocation lists, logs).

The failure is reported by the step that decodes the segment: `malformed` for the
header (step 3) and the payload (step 10), and `bad_signature` for the signature
(step 9).

### Header rules

- `typ` comparison: both sides are compared case-insensitively after removing one
  leading `application/` from each. This follows the media-type guidance in
  RFC 7515 section 4.1.9, so `at+jwt` and `application/at+jwt` are equal.
- `alg` values are compared case-sensitively. `none`, `NONE` and `None` are all
  just strings outside the allowlist, and yield `alg_not_allowed`.
- Duplicate member names are rejected in both header and payload, at every nesting
  level that is parsed. Rust's `serde_json` and Zig's `std.json` both accept
  duplicates by default, so each implementation needs an explicit check.

### Minimum negative vector set

Each of these has a vector with exactly the code shown. This is a floor.

| Vector | Result |
|---|---|
| `neg-alg-none` | `alg_not_allowed` |
| `neg-alg-not-in-policy` | `alg_not_allowed` |
| `neg-hs256-confusion` | `alg_not_allowed` |
| `neg-tampered-payload`, `neg-tampered-signature` | `bad_signature` |
| `neg-sig-truncated` | `bad_signature` |
| `neg-sig-der-encoded` (ES256 with a DER signature) | `bad_signature` |
| `neg-kid-unknown`, `neg-kid-missing` | `key_not_found` |
| `neg-key-alg-mismatch` | `key_not_found` |
| `neg-expired`, `neg-exp-boundary` | `expired` |
| `neg-nbf-future`, `neg-nbf-boundary` | `not_yet_valid` |
| `neg-wrong-iss` | `wrong_issuer` |
| `neg-wrong-aud`, `neg-aud-array-missing` | `wrong_audience` |
| `neg-aud-array-nonstring` | `malformed` |
| `neg-typ-missing`, `neg-typ-wrong` | `typ_mismatch` |
| `neg-crit-unknown` | `crit_unsupported` |
| `neg-crit-empty` | `malformed` |
| `neg-jku-ignored` | `key_not_found` |
| `neg-padding`, `neg-nonalphabet`, `neg-extra-segment`, `neg-empty-segment` | `malformed` |
| `neg-b64-noncanonical-header`, `neg-b64-noncanonical-payload` | `malformed` |
| `neg-b64-noncanonical-signature` | `bad_signature` |
| `neg-dup-key-header`, `neg-dup-key-payload` | `malformed` |
| `neg-exp-string`, `neg-exp-fractional`, `neg-exp-missing` | `malformed` |
| `neg-too-large` | `too_large` |

Positive boundary vectors accompany the negative ones: `exp` one second ahead of
`now`, `nbf` equal to `now`, and `exp + leeway - 1`.

## Consequences

- All implementations return identical codes for identical input, so the Go harness
  can compare them with plain equality.
- The rules are stricter than the RFCs in places (no fractional `exp`, mandatory
  `kid`, mandatory `exp`). Tokens from other issuers that rely on the looser forms
  will be rejected. That is acceptable for a verifier whose issuer is known.
- `README.md` lists the same thirteen steps. If this ADR changes, update the README
  in the same commit, or replace the README list with a link to this document.
- Any new check needs a position in this table before it is implemented.

## Alternatives considered

- **Parse everything first, then verify.** Simpler to write, but it hands
  attacker-controlled claims to the application before authentication.
- **Allow `kid` to be optional with a single-key fallback.** Rejected. It makes the
  behaviour depend on how many keys happen to be in the JWKS.
- **Accept either of two codes for ambiguous cases.** Rejected by ADR 0002. Fix the
  order instead.
