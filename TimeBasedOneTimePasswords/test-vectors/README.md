# Conformance test vectors

**Status:** normative annex of
[totp-token-format.md](../totp-token-format.md), the specification of the
Open Charging Technology TOTP token format, and of
[totp-http-authentication.md](../totp-http-authentication.md), its HTTP
authentication binding.

These files are the single source of truth: every implementation (Hermod,
TOTP.ts, and any future port) tests against the very same JSON, so a
divergence fails in a test run instead of in the field. The annex is
executed cross-implementation by the conformance suite at
[OpenChargingCloud/TOTPConformanceTests](https://github.com/OpenChargingCloud/TOTPConformanceTests),
which consumes this repository as its `libs/specification` submodule.

**The JSON files are generated — do not edit them by hand.** They come from
[`../tools/generate-test-vectors.py`](../tools/generate-test-vectors.py), an
independent third implementation of the specification (pure Python stdlib,
sharing no code with either implementation under test). Before writing
anything, the generator re-derives the historical anchor values that were
hand-cross-validated between Hermod and TOTP.ts, and refuses to write when
one of them does not match:

```
python tools/generate-test-vectors.py           # regenerate (run in TimeBasedOneTimePasswords/)
python tools/generate-test-vectors.py --check   # drift guard
```

## totp-test-vectors.json — generation vectors

Each vector: `input` → expected `previous`/`current`/`next` token,
`remainingTimeSeconds` and `endTimeUnixSeconds`.

 * An **absent** optional field in `input` means: the harness passes
   null/undefined, so that the implementation's **own defaulting** is
   exercised. An explicitly present field is passed as given (including
   untrimmed values — trimming is the implementation's job).
 * `unixTimestampMillis` is the timestamp in Unix **milliseconds**;
   implementations floor it to whole seconds.
 * `tlsExporterMaterialHex` is the TLS exporter material as lowercase hex.
 * `endTimeUnixSeconds` is the fixed end of the current window, `(S + 1) · V`
   (spec section 4.1) — always `⌊unixTimestampMillis / 1000⌋ +
   remainingTimeSeconds`. Harnesses check it against whatever end time or
   duration their implementation reports: an implementation returning the
   exact duration from the unfloored timestamp passes when that duration's
   ceiling is `remainingTimeSeconds` and it ends at `endTimeUnixSeconds`.
 * `requires` lists capabilities a vector needs. A harness runs the vector
   iff its implementation provides **all** of them, and MUST fail (not skip)
   on capability names it does not know. Capabilities so far:
   * `tlsChannelBinding` — TLS v1.3 channel binding (spec section 6),
     implemented by Hermod and TOTP.ts.
   * `httpAuthentication` — building and parsing the `Authorization: TOTP`
     scheme, implemented by Hermod and TOTP.ts.
   * `httpVerification` — verifying it on the server, implemented by
     Hermod (its WebSocket server).

## totp-http-auth-vectors.json — the "Authorization: TOTP" scheme

Vectors for the HTTP authentication binding
([totp-http-authentication.md](../totp-http-authentication.md)) as
RFC 9110 auth-params:
`TOTP login="<b64>", totp="<b64>"[, tlscb=true|false]` — `login`/`totp`
mandatory (Base64 of UTF-8), `tlscb` optional with default **true**.

 * `vectors` — credential building (login, token, binding flag → the exact
   canonical header value); harnesses also parse the header back
   (round-trip).
 * `parseVectors` — parse-only leniency cases: scheme and value casing,
   parameter order, `tlscb` defaulting and quoting, the unknown-parameter
   must-ignore rule, token-form values.
 * `invalidHeaders` — header values parsers MUST reject (duplicates,
   missing mandatory parameters, the wire forms of earlier drafts).

The **whole file** carries a top-level `requires` list (currently
`httpAuthentication` — Hermod and TOTP.ts). A harness whose implementation lacks a
listed capability skips the file **declaratively** — one visible skip entry,
never silence — and still fails on capability names it does not know.

## totp-http-verification-vectors.json — server-side verification

What a verifier **answers** (HTTP binding sections 5.3, 6.2 and 8), not
what a header looks like. `verifier` names one verifier: `logins` maps each
login to its TOTP configuration (absent optional fields mean the verifier's
own defaults, as in `input` of the generation vectors), and
`unixTimestampMillis` is its clock. Each vector carries one `authorization`
header value (`null`: no header) and the `expected` answer:

 * `accepted` — the request is authenticated as `expected.login`
   (a WebSocket upgrade: `101`);
 * `rejected` — `401 Unauthorized`; an unknown login is indistinguishable
   from a wrong token;
 * `malformed` — `400 Bad Request`, or `401`: a server MAY treat malformed
   as failed.

The verifier holds **no TLS exporter material** — a harness talking plain
TCP to a live server has none — so a credential claiming a channel binding
(`tlscb` absent or `true`) is rejected, never verified as raw. No presented
token is bound to any session, so a verifier with exporter material reaches
the same outcomes. The clock lies at least 10 seconds before the end of its
slot for every login: a harness may set a live server's clock to it and
lag that much. The generator decides each outcome with a verifier of its
own and refuses to write when it disagrees with the outcome a vector was
written to show; its parser must first agree with every vector of
`totp-http-auth-vectors.json`.

The whole file requires `httpVerification`; harnesses without it skip
every vector by name.

## totp-invalid-inputs.json — inputs that MUST be rejected

Each vector: `input` → `expectedError`, the shared error message of spec
section 5. Harnesses assert that the thrown message **starts with**
`expectedError` (the C# side appends the parameter name).

 * `knownDeviations` lists implementations that do not perform the check yet.
   Their harnesses skip the vector and pin the actual behaviour in a
   characterization test instead — see
   [`docs/spec-deviations.md`](https://github.com/OpenChargingCloud/TOTPConformanceTests/blob/master/docs/spec-deviations.md)
   of the conformance repository.
 * `notApplicable` lists implementations whose typed API cannot represent the
   input at all (rejection by construction, not a deviation).

Implementation names used in these two fields: `hermod`, `totp.ts`.

## Consuming the vectors from the implementation repositories

Both implementation repositories carry **vendored copies** of these files
and run their own test suites against them, so that each repository stays
self-contained (no submodule init required to run its tests):

 * Hermod: `HermodTests/TOTP/TestVectors/`, run by `TOTPVectorTests.cs`
 * TOTP.ts: `test/vectors/`, run by `test/vectors.test.ts`

The copies cannot drift: the conformance repository refreshes them by
running the generator with its implementation submodules as mirrors —

```
python libs/specification/TimeBasedOneTimePasswords/tools/generate-test-vectors.py \
    --mirror libs/Hermod/HermodTests/TOTP/TestVectors \
    --mirror libs/TOTP.TS/test/vectors
```

— and its `VendoredCopiesTests` compare the copies against this annex on
every CI run (pinned submodules) and every nightly run (upstream HEADs).
`totp-http-verification-vectors.json` is not vendored: verifying is a
server's job, and the conformance suite runs it against Hermod's server.
Vector ids are stable; new vectors only ever get new ids.
