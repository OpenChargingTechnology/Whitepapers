# Conformance test vectors

**Status:** normative annex of [README.md](../README.md), the specification
of CBOR tag 44252, and of [metrological-text.md](../metrological-text.md),
the text format and CBOR/JSON conversion built on it.

Machine-readable test vectors for implementations of Metrological CBOR. They
are exercised continuously against both reference implementations by the
cross-implementation conformance suite at
[Vanaheimr/MCBORConformanceTests](https://github.com/Vanaheimr/MCBORConformanceTests),
which also cross-feeds every text and every JSON document written by one
implementation into the other.

All hex strings are uppercase and contain no whitespace. All JSON documents
inside vectors are given as *exact text* (compact, no insignificant
whitespace), because the digits of a JSON number are data and must be
compared textually, not numerically.

Each file is one suite, selected by its `"suite"` field.

## Classes

Every expectation carries a class, explicit or implied:

- **normative** — required by the specification. A mismatch is a conformance
  failure.
- **survey** — a point the specification deliberately leaves open, kept here
  so that the open question is on record and implementations' behaviour is
  observed. A survey entry never fails a conforming implementation; should
  the specification later decide the point, the entry becomes normative.

## Suite `values` (`values.json`)

Single metrological values: wire bytes, canonical re-encoding, canonical text
form, and text parsing.

| Field | Meaning |
|---|---|
| `id` | unique case id |
| `description` | what the case exercises |
| `source` | where the expectation comes from (e.g. `spec §5`) |
| `hex` | the encoded value; a decoder MUST accept it |
| `canonicalHex` | what re-encoding the decoded value must produce (default: `hex`) |
| `canonicalHexClass` | `normative` (default) or `survey` |
| `text` | expected canonical text rendering (optional) |
| `textClass` | `normative` (default) or `survey` |
| `parseTexts` | additional texts to parse: `{text, hex?, expect}` where `expect` is `accept` (must parse to `hex`, defaulting to `canonicalHex`), `reject` (must not parse) or `survey` |

## Suite `values-invalid` (`values-invalid.json`)

Inputs a conforming decoder or text parser must reject (`expect: "reject"`,
the default), or whose treatment the specification leaves to the decoder
profile of its Section 6 (`expect: "survey"`).

| Field | Meaning |
|---|---|
| `id`, `description`, `reason` | as above; `reason` names the violated rule |
| `hex` | encoded input for the CBOR decoder (mutually exclusive with `text`) |
| `text` | input for the text parser |
| `expect` | `reject` (default) or `survey` |

## Suite `documents` (`documents.json`)

Document-level CBOR → JSON conversion (and back), the profile of
metrological-text.md Section 3. Map keys of round-trip cases are in canonical
(bytewise) order so that a deterministic re-encoding can reproduce the input.

| Field | Meaning |
|---|---|
| `cborHex` | the CBOR document |
| `json` | expected JSON text (optional) |
| `jsonClass` | `normative` (default when `json` present) or `survey` |
| `expectToJsonError` | the conversion must refuse the document |
| `roundtrip` | `true`: converting the produced JSON back must reproduce `cborHex` byte for byte; `false`: documented one-way; `"survey"`: record only |
| `roundtripHex` | when converting back yields *different, expected* bytes (a float that returns as an exact decimal, a prose string that reads as a measurement), the bytes it must yield |

## Suite `json-to-cbor` (`json-to-cbor.json`)

The JSON → CBOR direction alone, exercised on exact JSON text.

| Field | Meaning |
|---|---|
| `json` | the JSON document, as exact text |
| `cborHex` | expected canonical CBOR (optional) |
| `class` | `normative` (default when `cborHex` present) or `survey` |

Note for implementers: JSON numbers must be read from their digits as
written (metrological-text.md, Section 3.2). An ecosystem whose standard
JSON parser hands out binary floats — JavaScript's `JSON.parse` — cannot
satisfy these vectors through its native tree and needs a text-level
conversion path.
