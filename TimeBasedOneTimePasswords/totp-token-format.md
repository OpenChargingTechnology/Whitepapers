# Open Charging Technology TOTP Token Format

**Version 1.0**, 2026-08-22
[CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) · [OpenChargingTechnology/Whitepapers](https://github.com/OpenChargingTechnology/Whitepapers) · conformance suite: [OpenChargingCloud/TOTPConformanceTests](https://github.com/OpenChargingCloud/TOTPConformanceTests)

This document specifies the Time-based One-Time Password (TOTP) token format
shared by the C# `TOTPGenerator` in
[Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod) and the TypeScript
library [TOTP.ts](https://github.com/OpenChargingCloud/TOTP.ts). The format
predates this document: it is **frozen** by deployed verifiers on both sides,
and this specification therefore describes it exactly as implemented —
including two deliberate quirks (section 4.3) that MUST NOT be "fixed".

Conformance is machine-checkable: the canonical test vectors in
[`test-vectors/`](test-vectors/) are a normative annex of this specification
(section 9).


## 1. Introduction

Classic TOTP ([RFC 6238]) emits 6–8 decimal digits because its tokens are
typed by humans. The tokens specified here are exchanged **between machines**
— embedded in QR codes on charging station displays, sent as HTTP header
values, or used as a time-limited replacement for static API keys — so the
design space is deliberately larger:

 * an arbitrary **alphabet** (Base62 by default) instead of decimal digits,
 * a longer **token length** (12 characters by default, up to 255),
 * a Unicode **shared secret** string instead of a Base32-encoded binary key,
 * a **previous/current/next** token triple for a ±1-slot acceptance window,
 * an optional **TLS v1.3 channel binding** extension (section 6) that makes
   a leaked token useless outside the TLS session it was generated for.

Typical uses in the Open Charging Cloud ecosystem include OCPP QR-code based
payment and authorization flows (secure dynamic QR codes), a drop-in
replacement for legacy HTTP Basic Auth in constrained environments, and
adding time-limiting to OCPI-style token authentication. The HTTP bindings —
the `Authorization: TOTP` scheme and the `TOTP` request header — are
specified in the companion document
[totp-http-authentication.md](totp-http-authentication.md).

### 1.1. Relationship to RFC 6238

The slot arithmetic (`floor(unixTime / validityTime)`) follows RFC 6238 with
`T0 = 0`. The keyed function is HMAC ([RFC 2104]) over the 8-byte big-endian
slot number, as in RFC 4226/6238. The **truncation differs**: instead of RFC
4226's dynamic truncation to a 31-bit integer, each output character is drawn
directly from one hash byte (section 4.2). Tokens are therefore **not**
interoperable with RFC 6238 authenticator apps — by design.

### 1.2. Relationship to OCPP 2.1

This token format was originally developed for **OCPP v2.1**, which already
uses it in the same way for dynamic QR codes: use case C25 *"Ad hoc payment
via a QR code"* of [OCPP 2.1] Part 2 normatively defines *"TOTP algorithm,
version 1"* — HMAC-SHA256 over the big-endian 64-bit time slot, the low
nibble of the last hash byte as offset, and the byte-to-character mapping of
section 4.2 over the Base62 default alphabet. **OCPP TOTP v1 is exactly the
profile of this specification with `hashAlgorithm = sha256` and the default
alphabet**; OCPP's *"Validation of TOTP"* window (current, then previous,
then next interval) is the token triple of section 4.4. The
`ocpp-v1-length-8` and `ocpp-v1-min-profile` test vectors pin this
compatibility.

OCPP profiles the operational parameters via its `WebPaymentsCtrlr`
component (`ValidityTime` 6…3600 s, `Length` ≥ 6, a write-only
`SharedSecret`) and adds the URL-template and payment machinery around the
token; this specification generalizes the algorithm itself (hash agility,
alphabet agility, length 4…255, TLS channel binding). Divergences between
the OCPP text and this specification — including OCPP's lower shared-secret
minimum of 8 characters, which the implementations reject — are tracked in
[`docs/ocpp-totp-comparison.md`](https://github.com/OpenChargingCloud/TOTPConformanceTests/blob/master/docs/ocpp-totp-comparison.md)
of the conformance repository, together with modernization proposals for the
OCPP side.


## 2. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in [RFC 2119] and [RFC 8174] when, and only when, they appear in
all capitals.

*Characters* and *string lengths* in this document count UTF-16 code units —
the native string semantics of both C# and JavaScript. Characters outside the
Basic Multilingual Plane MUST NOT be used in alphabets (section 3).


## 3. Parameters

| Parameter          | Type            | Default                 | Constraints |
|--------------------|-----------------|-------------------------|-------------|
| `sharedSecret`     | Unicode string  | — (REQUIRED)            | after trimming: at least 16 characters, no whitespace |
| `validityTime`     | integer seconds | `30`                    | positive integer |
| `totpLength`       | integer         | `12`                    | 4 … 255 |
| `alphabet`         | Unicode string  | Base62 (see below)      | after trimming: at least 4 characters, no duplicates, no whitespace, BMP only |
| `timestamp`        | Unix time       | current time            | ≥ 0 (1970-01-01T00:00:00Z or later) |
| `hashAlgorithm`    | enumeration     | `sha256`                | one of `sha256`, `sha384`, `sha512` |
| `tlsExporterMaterial` | byte string  | absent                  | OPTIONAL extension, section 6 |

The default alphabet is the 62-character Base62 set, in exactly this order:

```
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
```

Normalization, applied before validation and use:

 * `sharedSecret` and `alphabet` are **trimmed** (leading and trailing
   whitespace removed).
 * A timestamp given in milliseconds is **floored** to whole seconds.
 * **No Unicode normalization** is applied to the shared secret: both ends
   must agree on the exact code points (a composed `é` and a decomposed
   `e`+`◌́` are different secrets). Provisioning SHOULD use NFC.

The canonical names of the hash algorithms are the lowercase strings
`sha256`, `sha384` and `sha512` (used in JSON configurations and in the test
vectors). Parsers MAY additionally accept case variants and separator
variants such as `SHA-256` or `HMAC_SHA512`.

The alphabet SHOULD consist of printable ASCII characters. An alphabet whose
size divides 256 (e.g. 16, 32 or 64 characters) is RECOMMENDED where the
modulo bias of section 4.3 matters.


## 4. Token derivation

### 4.1. Slot number

For a Unix timestamp `T` (in whole seconds, after flooring) and a validity
time `V`:

```
S  =  floor(T / V)        interpreted as an unsigned 64-bit integer
```

The remaining validity of the current token is

```
remainingTime  =  V − (T mod V)
```

which equals the full validity time `V` when `T` falls exactly on a slot
boundary.

### 4.2. One token for one slot

For a slot number `S`, the token is derived as follows:

1. `SlotBytes` = `S` encoded as **8 bytes, big-endian**.
2. `D` = `HMAC-<hashAlgorithm>( key = UTF8(sharedSecret), message = SlotBytes )`
   — the shared secret is encoded as **UTF-8** to key the HMAC.
3. *(Channel binding only, section 6:*
   `D` = `HMAC-<hashAlgorithm>( key = tlsExporterMaterial, message = D )`*)*
4. `offset` = `D[len(D) − 1] & 0x0F` — the low nibble of the last hash byte.
5. For `i = 0 … totpLength − 1`:

   ```
   token[i]  =  alphabet[ D[ (offset + i) mod len(D) ]  mod  |alphabet| ]
   ```

`len(D)` is 32, 48 or 64 bytes for `sha256`, `sha384` and `sha512`.

### 4.3. Frozen properties of the mapping

Two properties of step 5 are deliberate parts of the frozen format. Both are
pinned by test vectors; an implementation that "improves" them stops being
this format:

 * **Modulo bias.** Whenever the alphabet size does not divide 256, the first
   `256 mod |alphabet|` characters of the alphabet are reachable from one
   extra byte value. With the default 62-character alphabet (`256 = 4·62+8`)
   the characters `0`–`7` appear with probability 5/256 each, the remaining
   54 with 4/256 — a relative excess of 25 %. A 12-character default token
   still carries ≈ 71.40 bits of Shannon entropy (ideal: 71.45) and ≈ 68.1
   bits of min-entropy. Implementations MUST NOT remove the bias (e.g. by
   rejection sampling); deployments that care choose an alphabet of size 16,
   32 or 64 instead, where the bias is exactly zero.

 * **The hash is a ring buffer.** The byte index `(offset + i) mod len(D)`
   wraps, so token position `i + len(D)` always repeats position `i`
   verbatim. Tokens longer than 32/48/64 characters therefore gain no further
   entropy — they repeat. `totpLength` SHOULD NOT exceed the hash length.

### 4.4. The token triple

Generators return tokens for three consecutive slots:

```
previous = token(S − 1)      current = token(S)      next = token(S + 1)
```

The slot arithmetic is **unsigned 64-bit with wraparound**: within the first
slot after the Unix epoch (`S = 0`), the previous slot number is
`2^64 − 1`, not `−1`. This is pinned by the `epoch-previous-slot-wraps`
vector.


## 5. Input validation

Implementations MUST reject the following inputs. Both existing
implementations share the error message texts verbatim; new implementations
SHOULD reuse them, and conformance harnesses assert that a thrown message
**starts with** the shared text (implementations MAY append details such as a
parameter name):

| Condition (after normalization)            | Shared error message |
|--------------------------------------------|----------------------|
| shared secret empty                        | `The given shared secret must not be null or empty!` |
| shared secret contains whitespace          | `The given shared secret must not contain any whitespace characters!` |
| shared secret shorter than 16 characters   | `The length of the given shared secret must be at least 16 characters!` |
| token length outside 4 … 255, or not an integer | `The expected length of the TOTP must be between 4 and 255 characters!` |
| validity time not a positive integer       | `The validity time must be a positive integer number of seconds!` |
| timestamp before the Unix epoch            | `The timestamp must be a non-negative Unix timestamp in milliseconds!` |
| unknown hash algorithm                     | `The hash algorithm must be one of: sha256, sha384, sha512!` |
| alphabet empty                             | `The given alphabet must not be null or empty!` |
| alphabet shorter than 4 characters         | `The given alphabet must contain at least 4 characters!` |
| alphabet contains duplicate characters     | `The given alphabet must not contain duplicate characters!` |
| alphabet contains whitespace               | `The given alphabet must not contain any whitespace characters!` |

The checks are ordered: whitespace inside the shared secret is reported
before its length; duplicate alphabet characters are reported before interior
whitespace. An implementation whose typed API makes an input unrepresentable
(e.g. a fractional token length where the parameter is an unsigned integer)
rejects it by construction.

Statically typed APIs MAY perform the *unknown hash algorithm* rejection at
their parsing boundary (string → enumeration) instead of inside the
generator.


## 6. TLS v1.3 channel binding (OPTIONAL extension)

When the TOTP travels over a TLS v1.3 connection, the token MAY be bound to
that specific TLS session, making a captured or logged token useless
anywhere else:

1. Both endpoints derive exporter material per [RFC 8446] section 7.5 with

   * label: `EXPORTER-Time-Based-One-Time-Password-v1`
   * context: empty
   * length: 32 bytes RECOMMENDED

2. The token derivation applies a second HMAC (step 3 of section 4.2): the
   first digest is HMAC'ed again, keyed with the exporter material, using the
   **same** hash algorithm. Offset and character mapping then operate on the
   second digest.

An **empty** exporter material MUST be treated as *absent* (no binding) — not
as an HMAC with an empty key.

In the test vectors this capability is named `tlsChannelBinding`. It is
currently implemented by Hermod only; the vectors that require it are skipped
by harnesses of implementations without it.


## 7. Verification

A verifier computes `previous`, `current` and `next` for its own clock and
accepts a presented token iff it equals one of the three. This tolerates a
clock skew plus transmission delay of up to one validity time in either
direction.

 * The comparison SHOULD be constant-time.
 * Verifiers MUST NOT widen the window beyond ±1 slot; deployments needing
   more tolerance increase the validity time instead.
 * Accepted tokens SHOULD be remembered (per secret, for the lifetime of
   their slot) and rejected on reuse where replay matters and no TLS channel
   binding is in place.
 * Verifiers SHOULD rate-limit failed attempts; the entropy figures of
   section 4.3 assume an attacker cannot try tokens at wire speed for 30
   seconds.


## 8. Security considerations

 * **Secret strength.** The 16-character minimum is a floor, not a
   recommendation. Secrets SHOULD be generated randomly with at least 128
   bits of entropy (e.g. 22+ random Base62 characters); human-chosen
   passphrases SHOULD NOT be used. The secret is a symmetric key: every
   holder can both generate and verify tokens.
 * **Token entropy** is bounded by both `totpLength · log2(|alphabet|)` and
   the hash length (section 4.3). The 12-character Base62 default (~71 bits)
   is far beyond online brute force under any rate limiting.
 * **Replay.** Within its validity window a plain token is replayable by
   design — anyone who sees it can use it until the slot ends. Where that
   matters, use TLS channel binding (section 6) or single-use enforcement
   (section 7).
 * **Algorithm agility.** The hash algorithm is a per-deployment
   configuration, not negotiated in-band; both ends must be configured
   identically. There is no way to signal the algorithm inside a token.
 * **SHA-1 and MD5** are rejected by name (section 5) and MUST NOT be added.
 * **The clock is a security boundary.** Every guarantee of this format is
   time-boxed: a token expires only if the verifier's clock actually moves
   on. An attacker who can shift a peer's clock — classic unauthenticated
   NTP is trivially spoofable on-path — can resurrect expired tokens,
   pre-compute future ones against a generator, or deny service by pushing
   clocks apart. Generators and verifiers SHOULD therefore obtain time from
   an **authenticated source**; we strongly RECOMMEND Network Time Security
   ([RFC 8915]) for NTP ([RFC 5905]) deployments.

### 8.1. Known-answer material

All shared secrets, tokens and exporter materials in this specification's
test vectors are, of course, **test data**: they are public, and none of them
may protect anything.


## 9. Test vectors (normative)

The canonical vectors live in [`test-vectors/`](test-vectors/), the
normative annex of this specification:

 * [`totp-test-vectors.json`](test-vectors/totp-test-vectors.json) —
   generation vectors. In each vector's `input`, an **absent** optional
   parameter means: the harness passes null/undefined, so that the
   implementation's own defaulting is exercised. A vector with a `requires`
   list applies only to implementations providing all listed capabilities.
 * [`totp-invalid-inputs.json`](test-vectors/totp-invalid-inputs.json) —
   inputs that MUST be rejected, with the shared error messages of section 5.

The files are generated by
[`tools/generate-test-vectors.py`](tools/generate-test-vectors.py), an
independent third implementation of this specification, which verifies the
historical hand-cross-validated anchor values before writing anything. The
annex is executed cross-implementation by the conformance suite at
[OpenChargingCloud/TOTPConformanceTests](https://github.com/OpenChargingCloud/TOTPConformanceTests).

An implementation **conforms** to this specification when it passes every
applicable vector of both files: all generation vectors whose `requires` it
satisfies, and all invalid-input vectors not listing it under
`notApplicable`. Deviations grandfathered in existing implementations are
tracked per vector under `knownDeviations` and documented in
[`docs/spec-deviations.md`](https://github.com/OpenChargingCloud/TOTPConformanceTests/blob/master/docs/spec-deviations.md)
of the conformance repository.


## 10. References

 * [RFC 2104] — HMAC: Keyed-Hashing for Message Authentication
 * [RFC 2119] / [RFC 8174] — Key words for use in RFCs
 * [RFC 4226] — HOTP: An HMAC-Based One-Time Password Algorithm
 * [RFC 5905] — Network Time Protocol Version 4
 * [RFC 6238] — TOTP: Time-Based One-Time Password Algorithm
 * [RFC 8446] — The Transport Layer Security (TLS) Protocol Version 1.3
 * [RFC 8915] — Network Time Security for the Network Time Protocol
 * [OCPP 2.1] — Open Charge Point Protocol 2.1 Edition 2, Part 2 -
   Specification, Open Charge Alliance, 2025 (use case C25, "TOTP algorithm,
   version 1", component `WebPaymentsCtrlr`)

[RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
[RFC 5905]: https://www.rfc-editor.org/rfc/rfc5905
[RFC 8915]: https://www.rfc-editor.org/rfc/rfc8915
[OCPP 2.1]: https://openchargealliance.org/protocols/open-charge-point-protocol/
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 4226]: https://www.rfc-editor.org/rfc/rfc4226
[RFC 6238]: https://www.rfc-editor.org/rfc/rfc6238
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446


## Appendix A — Known implementations (informative)

| Implementation | Language | Channel binding | Source |
|----------------|----------|-----------------|--------|
| Vanaheimr Hermod `TOTPGenerator` | C# / .NET | yes | [`Hermod/TOTP/TOTP.cs`](https://github.com/Vanaheimr/Hermod/blob/master/Hermod/TOTP/TOTP.cs) |
| TOTP.ts (`@open-charging-cloud/totp`) | TypeScript / Node | no | [`src/index.ts`](https://github.com/OpenChargingCloud/TOTP.ts/blob/main/src/index.ts) |
| Vector generator (reference) | Python | yes | [`tools/generate-test-vectors.py`](tools/generate-test-vectors.py) |


## Appendix B — JSON configuration (informative)

Hermod's `TOTPConfig` serializes a TOTP configuration as JSON. Field names
and value spellings match this specification and are RECOMMENDED for other
implementations storing configurations:

```json
{
    "sharedSecret":            "secure!Charging!",
    "validityTime":            30,
    "length":                  12,
    "alphabet":                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "useTLSExporterMaterial":  false,
    "hashAlgorithm":           "sha256"
}
```

All fields except `sharedSecret` are optional and default as in section 3.
`hashAlgorithm` uses the canonical lowercase names.
