# ADR 0002: The test vectors are the contract between implementations

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The JOSE layer is implemented in Rust, Zig and perhaps Go. Independent
implementations of the same specification drift apart in the corners: duplicate
JSON keys, base64url padding, numeric claims given as strings, check ordering.
Each of those corners is also a classic source of verifier vulnerabilities, because
two components that disagree about whether a token is valid can be exploited
against each other.

Without a shared reference, "correct" means whatever each implementation happens to
do. With one, a disagreement becomes a failing test.

## Decision

1. **`testvectors/` is authoritative.** The expected verdict in a vector overrides
   what any implementation does. When an implementation disagrees with a vector,
   the implementation is fixed, unless the vector is shown to be wrong against the
   specification.
2. **Vectors conform to `testvectors/schema.json`** and live one case per file. The
   file name equals the case `id`.
3. **RFC vectors are copied from the RFC text,** not retyped from memory or taken
   from another library's test suite. Each carries its RFC section in `source`.
4. **Generated vectors are committed.** `jose-cli gen-vectors` writes them to
   `testvectors/generated/`, and the files are checked in so that any change shows
   up in code review. CI regenerates them and fails if the working tree changes.
5. **Generation is deterministic.** Test keys are fixed and marked test-only. Ed25519
   signatures are deterministic. ES256 signatures are not, so ES256 vectors are
   generated once and regenerated only deliberately, with the diff reviewed.
6. **Time is explicit.** Every policy carries `now`, so no case depends on the wall
   clock.
7. **Rejections match on the exact error code.** Alternatives such as "either
   `malformed` or `bad_signature`" are not permitted. If a case could legitimately
   yield two codes, the order of checks in ADR 0003 must be amended until it
   cannot.
8. **Resolving a disagreement:**
   1. Read the relevant RFC section and decide which implementation is right.
   2. If the RFC is ambiguous, record the decision in ADR 0003 and add a vector.
   3. Fix the implementation that is wrong. Never relax the vector to make a test
      pass.

## Consequences

- Adding a feature means adding vectors first. A new check without a vector does
  not count as implemented.
- The Go harness compares every implementation both to the expected verdict and to
  each other, so a wrong vector is also visible as all implementations disagreeing
  with it in the same way.
- Committed ES256 vectors contain real signatures over test keys. That is intended,
  and the keys are published as test-only.
- The vector set is only as good as its coverage. The list of negative cases in the
  README and ADR 0003 is a floor, not a ceiling, and every bug found later gets a
  regression vector.

## Alternatives considered

- **Use an existing JOSE library as the oracle.** Rejected. It would make the
  library's quirks the specification, and it defeats the purpose of writing the
  layer by hand.
- **Generate vectors in CI only.** Rejected. Silent changes to the expected verdicts
  would not be visible in review.
- **Compare implementations only to each other.** Rejected. Two implementations can
  be wrong in the same way.
