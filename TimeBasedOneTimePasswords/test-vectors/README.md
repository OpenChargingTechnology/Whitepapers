# Conformance test vectors

**Status:** normative annex of
[totp-token-format.md](../totp-token-format.md), the specification of the
Open Charging Cloud TOTP token format, and of
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

Each vector: `input` → expected `previous`/`current`/`next` token and
`remainingTimeSeconds`.

 * An **absent** optional field in `input` means: the harness passes
   null/undefined, so that the implementation's **own defaulting** is
   exercised. An explicitly present field is passed as given (including
   untrimmed values — trimming is the implementation's job).
 * `unixTimestampMillis` is the timestamp in Unix **milliseconds**;
   implementations floor it to whole seconds.
 * `tlsExporterMaterialHex` is the TLS exporter material as lowercase hex.
 * `requires` lists capabilities a vector needs. A harness runs the vector
   iff its implementation provides **all** of them, and MUST fail (not skip)
   on capability names it does not know. Capabilities so far:
   * `tlsChannelBinding` — TLS v1.3 channel binding (spec section 6),
     currently Hermod only.

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
`httpAuthentication` — Hermod only). A harness whose implementation lacks a
listed capability skips the file **declaratively** — one visible skip entry,
never silence — and still fails on capability names it does not know.

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
Vector ids are stable; new vectors only ever get new ids.
