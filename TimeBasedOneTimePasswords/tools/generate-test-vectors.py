#!/usr/bin/env python3
"""
Generate the canonical TOTP conformance test vectors.

This script is a THIRD, independent implementation of the token format
specified in ../totp-token-format.md, written in pure Python stdlib and
deliberately sharing no code with either implementation under test:

    * Vanaheimr Hermod   (C#)          Hermod/TOTP/TOTP.cs
    * TOTP.ts            (TypeScript)  src/index.ts

Before writing anything, the script re-derives every anchor vector - the
token sets that were hand-cross-validated between the two implementations
before this annex existed - and refuses to write when even one of them
does not match. The emitted JSON is therefore backed by three independent
implementations agreeing on every anchored value.

The files in ../test-vectors/ are the NORMATIVE ANNEX of the specification.
They are executed cross-implementation by the conformance suite at
https://github.com/OpenChargingCloud/TOTPConformanceTests, which consumes
this repository as its libs/specification submodule. Both implementation
repositories additionally carry VENDORED COPIES, so that their own test
suites run against the very same vectors; the conformance repository
refreshes those copies by naming them as mirrors:

    python libs/specification/TimeBasedOneTimePasswords/tools/generate-test-vectors.py \\
        --mirror libs/Hermod/HermodTests/TOTP/TestVectors \\
        --mirror libs/TOTP.TS/test/vectors

Its VendoredCopiesTests fail when a pinned (CI) or upstream (nightly) copy
has drifted.

Usage:
    python tools/generate-test-vectors.py            # (re)write ../test-vectors/
    python tools/generate-test-vectors.py --check    # verify it is current

The JSON files are generated - do not edit them by hand.
"""

import argparse
import base64
import hmac
import json
import os
import sys
from pathlib import Path

SPEC_DIR     = Path(__file__).resolve().parent.parent
VECTORS_DIR  = SPEC_DIR / "test-vectors"

SPEC_NAME       = "Open Charging Cloud TOTP Token Format 1.0"
SPEC_NAME_HTTP  = "Open Charging Cloud TOTP HTTP Authentication 1.0 (draft)"
GENERATOR       = "TimeBasedOneTimePasswords/tools/generate-test-vectors.py"

MASK64       = 0xFFFF_FFFF_FFFF_FFFF

# Shared defaults, normative in the specification.
DEFAULT_VALIDITY  = 30
DEFAULT_LENGTH    = 12
DEFAULT_ALPHABET  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
DEFAULT_ALGORITHM = "sha256"

BASE32_ALPHABET   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE64URL_ALPHABET = DEFAULT_ALPHABET + "-_"

SECRET            = "secure!Charging!"


# --------------------------------------------------------------------------
# The reference implementation of the token format (spec section 4).
# --------------------------------------------------------------------------

def calc_slot_token(slot:      int,
                    secret:    bytes,
                    length:    int,
                    alphabet:  str,
                    algorithm: str,
                    material:  bytes | None = None) -> str:
    """One token for one slot number (spec section 4.3 / 6)."""

    slot_bytes = (slot & MASK64).to_bytes(8, "big")
    digest     = hmac.new(secret, slot_bytes, algorithm).digest()

    # TLS v1.3 channel binding extension: a second HMAC, keyed with the TLS
    # exporter material, over the first digest - same hash algorithm.
    if material:
        digest = hmac.new(material, digest, algorithm).digest()

    offset = digest[-1] & 0x0F

    return "".join(alphabet[digest[(offset + i) % len(digest)] % len(alphabet)]
                   for i in range(length))


def generate_totps(shared_secret: str,
                   unix_ms:       int,
                   validity:      int | None = None,
                   length:        int | None = None,
                   alphabet:      str | None = None,
                   algorithm:     str | None = None,
                   material:      bytes | None = None) -> dict:
    """Previous/current/next token plus remaining time (spec sections 4-5)."""

    validity  = validity  if validity  is not None else DEFAULT_VALIDITY
    length    = length    if length    is not None else DEFAULT_LENGTH
    alphabet  = (alphabet if alphabet  is not None else DEFAULT_ALPHABET).strip()
    algorithm = algorithm if algorithm is not None else DEFAULT_ALGORITHM

    secret    = shared_secret.strip().encode("utf-8")

    unix_s    = unix_ms // 1000
    slot      = unix_s  // validity
    remaining = validity - (unix_s % validity)

    return {
        "previous":              calc_slot_token((slot - 1) & MASK64, secret, length, alphabet, algorithm, material),
        "current":               calc_slot_token(slot,                secret, length, alphabet, algorithm, material),
        "next":                  calc_slot_token((slot + 1) & MASK64, secret, length, alphabet, algorithm, material),
        "remainingTimeSeconds":  remaining
    }


# --------------------------------------------------------------------------
# Anchors: token sets hand-cross-validated between Hermod and TOTP.ts
# (HermodTests/TOTP/TOTPGeneratorTests.cs and TOTP.TS/test/index.test.ts)
# before this annex existed. If one of these fails, this script is
# wrong - never the other way around.
# --------------------------------------------------------------------------

TS1 = 1718611200000   # 2024-06-17T08:00:00Z, an exact slot boundary for 30s
TS2 = 1716423785000   # 2024-05-23T00:23:05Z, mid-slot

ANCHORS = [
    (dict(shared_secret=SECRET, unix_ms=TS1, validity=30, length=12),
     ("QT1cCdKsIb9e", "akF3c7qY2uiu", "1U70OgaBA48M", 30)),
    (dict(shared_secret=SECRET, unix_ms=TS2),
     ("MdPU0jCm5tXz", "CN63y502maVh", "dI54vnA25m2h", 25)),
    (dict(shared_secret=SECRET, unix_ms=TS2, length=23),
     ("MdPU0jCm5tXzkaPrPj61KwI", "CN63y502maVhAsv27Sd7JlE", "dI54vnA25m2hWW3bUcdY13q", 25)),
    (dict(shared_secret=SECRET, unix_ms=TS2, alphabet="0123456789"),
     ("233045043555", "894361286613", "545817627227", 25)),
    (dict(shared_secret=SECRET, unix_ms=TS2, validity=60),
     ("nTdkiuG6yUyg", "XJZr0L1DGKn0", "ft0ONZ62MdMj", 55)),
    (dict(shared_secret=SECRET, unix_ms=TS2, algorithm="sha384"),
     ("0SbZV69lSa4W", "jAzmwLzuPuUb", "mqtkOMRrX1aS", 25)),
    (dict(shared_secret=SECRET, unix_ms=TS2, algorithm="sha512"),
     ("wjmTW4LVTdwv", "yBhTTbXO2ILd", "MHMqTXE1oVf9", 25)),
    (dict(shared_secret=SECRET, unix_ms=0),
     ("SzcwtcR5qcY7", "u5CoKdo5HUS1", "tVGiyLys7Y1V", 30)),
]

def check_anchors() -> None:

    for inputs, (previous, current, next_, remaining) in ANCHORS:
        result = generate_totps(**inputs)
        expected = {
            "previous":             previous,
            "current":              current,
            "next":                 next_,
            "remainingTimeSeconds": remaining
        }
        if result != expected:
            raise AssertionError(f"Anchor mismatch for {inputs}:\n"
                                 f"  expected {expected}\n"
                                 f"  got      {result}")

    # The 64 character sha256 ring buffer anchor (both test suites).
    ring = generate_totps(SECRET, TS1, validity=30, length=64)
    if ring["current"] != "akF3c7qY2uiuO4rpyU0SC0W8VFE6nvxz" * 2:
        raise AssertionError("Ring buffer anchor mismatch")

    # The options object API anchor of TOTP.ts (length 6, decimal alphabet).
    short = generate_totps(SECRET, TS1, validity=30, length=6, alphabet="0123456789")
    if short["current"] != "441749":
        raise AssertionError("Six digit anchor mismatch")


# --------------------------------------------------------------------------
# The generation vectors.
#
# "input" carries only the parameters that are explicitly set; an absent
# optional parameter means: the harness passes null/undefined, so that the
# implementation's own defaulting is exercised.
# --------------------------------------------------------------------------

def vector(id_:        str,
           description: str,
           *,
           secret:     str = SECRET,
           unix_ms:    int,
           validity:   int | None = None,
           length:     int | None = None,
           alphabet:   str | None = None,
           algorithm:  str | None = None,
           material_hex: str | None = None,
           requires:   list[str] | None = None) -> dict:

    input_: dict = {
        "sharedSecret":         secret,
        "unixTimestampMillis":  unix_ms
    }
    if validity     is not None: input_["validityTimeSeconds"]    = validity
    if length       is not None: input_["totpLength"]             = length
    if alphabet     is not None: input_["alphabet"]               = alphabet
    if algorithm    is not None: input_["hashAlgorithm"]          = algorithm
    if material_hex is not None: input_["tlsExporterMaterialHex"] = material_hex

    result = {
        "id":           id_,
        "description":  description,
        "input":        input_,
        "expected":     generate_totps(
                            secret, unix_ms, validity, length, alphabet, algorithm,
                            bytes.fromhex(material_hex) if material_hex else None
                        )
    }
    if requires:
        result["requires"] = requires

    return result


def generation_vectors() -> list[dict]:

    TLS_MATERIAL_32 = bytes(range(0x00, 0x20)).hex()
    TLS_MATERIAL_64 = bytes(range(0x00, 0x40)).hex()
    TLS_MATERIAL_8  = "0011223344556677"

    return [

        # -- Anchors (hand-cross-validated between Hermod and TOTP.ts) -----

        vector("defaults-slot-boundary",
               "All defaults, timestamp exactly on a 30s slot boundary: remaining time is the full validity time.",
               unix_ms=TS1, validity=30, length=12),

        vector("defaults-mid-slot",
               "All parameters defaulted (validity 30s, length 12, Base62 alphabet, HMAC-SHA256), mid-slot timestamp.",
               unix_ms=TS2),

        vector("length-23",
               "Explicit token length of 23 characters.",
               unix_ms=TS2, length=23),

        vector("alphabet-decimal",
               "Decimal alphabet (10 characters, modulo bias: 256 = 25*10 + 6).",
               unix_ms=TS2, alphabet="0123456789"),

        vector("validity-60",
               "60 second validity time.",
               unix_ms=TS2, validity=60),

        vector("sha384-defaults",
               "HMAC-SHA384 (48 hash bytes) with default parameters.",
               unix_ms=TS2, algorithm="sha384"),

        vector("sha512-defaults",
               "HMAC-SHA512 (64 hash bytes) with default parameters.",
               unix_ms=TS2, algorithm="sha512"),

        vector("epoch-previous-slot-wraps",
               "Timestamp 0: within the first slot after the Unix epoch the previous slot number wraps to 2^64 - 1 (unchecked 64 bit arithmetic).",
               unix_ms=0, validity=30, length=12),

        vector("length-64-sha256-ring-buffer",
               "A 64 character HMAC-SHA256 token: the hash is read as a ring buffer, so the 32 character token repeats verbatim.",
               unix_ms=TS1, validity=30, length=64),

        vector("length-6-decimal",
               "Six decimal digits - the classic RFC 6238 look, in this token format.",
               unix_ms=TS1, validity=30, length=6, alphabet="0123456789"),

        # -- Token length ---------------------------------------------------

        vector("length-min-4",
               "Minimum allowed token length.",
               unix_ms=TS2, length=4),

        vector("length-max-255",
               "Maximum allowed token length (with SHA-512; positions beyond 64 repeat the ring buffer).",
               unix_ms=TS2, length=255, algorithm="sha512"),

        vector("length-33-sha256",
               "One character beyond the 32 byte SHA-256 hash: position 32 repeats position 0.",
               unix_ms=TS2, length=33),

        vector("length-48-sha384",
               "Token length equal to the 48 byte SHA-384 hash length.",
               unix_ms=TS2, length=48, algorithm="sha384"),

        vector("length-64-sha512",
               "Token length equal to the 64 byte SHA-512 hash length: no repetition.",
               unix_ms=TS2, length=64, algorithm="sha512"),

        # -- Alphabets ------------------------------------------------------

        vector("alphabet-min-4",
               "Minimum allowed alphabet size (4 characters).",
               unix_ms=TS2, alphabet="ACGT"),

        vector("alphabet-hex",
               "Hexadecimal alphabet (16 characters, no modulo bias: 16 divides 256).",
               unix_ms=TS2, alphabet="0123456789abcdef"),

        vector("alphabet-base32",
               "RFC 4648 Base32 alphabet (32 characters, no modulo bias).",
               unix_ms=TS2, alphabet=BASE32_ALPHABET),

        vector("alphabet-base64url",
               "Base64url alphabet (64 characters, no modulo bias: 256 = 4*64). RECOMMENDED when bias matters.",
               unix_ms=TS2, alphabet=BASE64URL_ALPHABET),

        # -- Validity times -------------------------------------------------

        vector("validity-1",
               "One second validity time: the slot number equals the Unix time.",
               unix_ms=TS2, validity=1),

        vector("validity-5",
               "Five second validity time.",
               unix_ms=TS2, validity=5),

        vector("validity-7",
               "Seven second validity time - not a divisor of 60, exercises slot arithmetic.",
               unix_ms=TS2, validity=7),

        vector("validity-86400",
               "One day validity time.",
               unix_ms=TS2, validity=86400),

        # -- Timestamps and remaining time ----------------------------------

        vector("remaining-1-second",
               "Last second of a slot: remaining time is 1.",
               unix_ms=1716423779000),

        vector("milliseconds-floor",
               "Milliseconds are floored to whole seconds: x999 ms yields the same tokens as x000 ms.",
               unix_ms=1716423785999),

        vector("milliseconds-floor-slot-edge",
               "999 ms before a slot change: still the old slot, remaining time 1 second.",
               unix_ms=1716423809999),

        vector("timestamp-y2038",
               "Unix time 2^31 - 1 (2038-01-19T03:14:07Z): no 32 bit rollover.",
               unix_ms=2147483647000),

        # 23:59:28, not 23:59:59: in the very last slot of the calendar
        # Hermod's EndTime (timestamp + remaining time) would leave the
        # DateTime range - a documented deviation, see docs/spec-deviations.md.
        vector("timestamp-year-9999",
               "9999-12-31T23:59:28Z, the far end of the calendar.",
               unix_ms=253402300768000),

        # -- Shared secrets -------------------------------------------------

        vector("secret-utf8",
               "Non-ASCII shared secret: the secret is encoded as UTF-8 before keying the HMAC. No Unicode normalization is applied.",
               secret="sécürè!Chärgîng!", unix_ms=TS2),

        vector("secret-64-chars",
               "A long, 64 character shared secret.",
               secret="0ZPatRVe1DTLBHRipD5cyOU9d1TCsdLLYhtLXGajUATuOwaVSVFPnbUAJyTFrPFI", unix_ms=TS2),

        vector("secret-surrounding-whitespace",
               "The shared secret is trimmed before use: surrounding whitespace yields the tokens of the trimmed secret.",
               secret="  " + SECRET + "  ", unix_ms=TS2),

        vector("alphabet-surrounding-whitespace",
               "The alphabet is trimmed before use: surrounding whitespace yields the tokens of the trimmed alphabet.",
               unix_ms=TS2, alphabet=" 0123456789 "),

        # -- OCPP 2.1 profile ----------------------------------------------
        #
        # OCPP 2.1 Ed.2, use case C25 "Ad hoc payment via a QR code" defines
        # "TOTP algorithm, version 1" = this format with HMAC-SHA256 and the
        # Base62 default alphabet. These vectors pin OCPP-representable
        # parameter sets (see docs/ocpp-totp-comparison.md).

        vector("ocpp-v1-length-8",
               "OCPP 2.1 C25 'TOTP algorithm, version 1' with the example token length 8 of WebPaymentsCtrlr.Length.",
               unix_ms=TS2, validity=30, length=8),

        vector("ocpp-v1-min-profile",
               "The weakest OCPP-legal corner: WebPaymentsCtrlr minimum Length 6 with maximum ValidityTime 3600s.",
               unix_ms=TS2, validity=3600, length=6),

        # -- Everything at once --------------------------------------------

        vector("all-parameters-custom",
               "Every parameter away from its default at once.",
               secret="Conformance!Secret#2026", unix_ms=TS2,
               validity=120, length=20, alphabet=BASE32_ALPHABET, algorithm="sha384"),

        # -- TLS v1.3 channel binding (optional extension, spec section 6) --

        vector("tls-binding-sha256",
               "TLS v1.3 channel binding: a second HMAC, keyed with 32 bytes of TLS exporter material, over the first digest.",
               unix_ms=TS2, material_hex=TLS_MATERIAL_32,
               requires=["tlsChannelBinding"]),

        vector("tls-binding-sha512",
               "TLS v1.3 channel binding with HMAC-SHA512: both HMACs use the same hash algorithm.",
               unix_ms=TS2, algorithm="sha512", material_hex=TLS_MATERIAL_64,
               requires=["tlsChannelBinding"]),

        vector("tls-binding-short-material",
               "TLS channel binding with only 8 bytes of exporter material (HMAC accepts any key length).",
               unix_ms=TS2, material_hex=TLS_MATERIAL_8,
               requires=["tlsChannelBinding"]),

    ]


# --------------------------------------------------------------------------
# The invalid input vectors.
#
# Implementations MUST reject these inputs (spec section 5.1). Both existing
# implementations share their error message texts verbatim; harnesses assert
# that the thrown message STARTS WITH "expectedError" (the C# side appends
# the parameter name).
#
# "knownDeviations" lists implementations that are known NOT to perform the
# check yet - see docs/spec-deviations.md. Harnesses for those skip the
# vector and characterize the actual behaviour separately.
#
# "notApplicable" lists implementations whose typed API cannot represent the
# input at all (which is a rejection by construction, not a deviation).
# --------------------------------------------------------------------------

def invalid(id_:         str,
            description: str,
            input_:      dict,
            error:       str,
            *,
            known_deviations: list[str] | None = None,
            not_applicable:   list[str] | None = None) -> dict:

    result = {
        "id":            id_,
        "description":   description,
        "input":         {"unixTimestampMillis": TS2, **input_},
        "expectedError": error
    }
    if known_deviations:
        result["knownDeviations"] = known_deviations
    if not_applicable:
        result["notApplicable"] = not_applicable

    return result


ERR_SECRET_EMPTY      = "The given shared secret must not be null or empty!"
ERR_SECRET_WHITESPACE = "The given shared secret must not contain any whitespace characters!"
ERR_SECRET_SHORT      = "The length of the given shared secret must be at least 16 characters!"
ERR_LENGTH            = "The expected length of the TOTP must be between 4 and 255 characters!"
ERR_VALIDITY          = "The validity time must be a positive integer number of seconds!"
ERR_TIMESTAMP         = "The timestamp must be a non-negative Unix timestamp in milliseconds!"
ERR_HASH              = "The hash algorithm must be one of: sha256, sha384, sha512!"
ERR_ALPHABET_EMPTY    = "The given alphabet must not be null or empty!"
ERR_ALPHABET_SIZE     = "The given alphabet must contain at least 4 characters!"
ERR_ALPHABET_DUP      = "The given alphabet must not contain duplicate characters!"
ERR_ALPHABET_WS       = "The given alphabet must not contain any whitespace characters!"


def invalid_vectors() -> list[dict]:

    return [

        # -- Shared secret --------------------------------------------------

        invalid("secret-empty",
                "An empty shared secret is rejected.",
                {"sharedSecret": ""},
                ERR_SECRET_EMPTY),

        invalid("secret-whitespace-only",
                "A whitespace-only shared secret trims to empty and is rejected.",
                {"sharedSecret": "        "},
                ERR_SECRET_EMPTY),

        invalid("secret-too-short",
                "A 15 character shared secret is rejected (minimum is 16).",
                {"sharedSecret": "secure!Charging"},
                ERR_SECRET_SHORT),

        invalid("secret-inner-whitespace",
                "A shared secret with interior whitespace is rejected (checked before the length).",
                {"sharedSecret": "secure Charging!"},
                ERR_SECRET_WHITESPACE),

        # -- Token length ---------------------------------------------------

        invalid("length-3",
                "A token length below 4 is rejected.",
                {"sharedSecret": SECRET, "totpLength": 3},
                ERR_LENGTH),

        invalid("length-256",
                "A token length above 255 is rejected.",
                {"sharedSecret": SECRET, "totpLength": 256},
                ERR_LENGTH),

        invalid("length-fractional",
                "A non-integer token length is rejected. (Unrepresentable in the C# API: the parameter is a UInt32.)",
                {"sharedSecret": SECRET, "totpLength": 12.5},
                ERR_LENGTH,
                not_applicable=["hermod"]),

        # -- Validity time --------------------------------------------------

        invalid("validity-zero",
                "A validity time of zero seconds is rejected.",
                {"sharedSecret": SECRET, "validityTimeSeconds": 0},
                ERR_VALIDITY),

        invalid("validity-negative",
                "A negative validity time is rejected.",
                {"sharedSecret": SECRET, "validityTimeSeconds": -30},
                ERR_VALIDITY),

        invalid("validity-fractional",
                "A non-integer validity time is rejected.",
                {"sharedSecret": SECRET, "validityTimeSeconds": 4.5},
                ERR_VALIDITY),

        # -- Timestamp ------------------------------------------------------

        invalid("timestamp-negative",
                "A timestamp before the Unix epoch is rejected.",
                {"sharedSecret": SECRET, "unixTimestampMillis": -1000},
                ERR_TIMESTAMP),

        # -- Hash algorithm -------------------------------------------------

        invalid("hash-sha1",
                "SHA-1 is not part of the format.",
                {"sharedSecret": SECRET, "hashAlgorithm": "sha1"},
                ERR_HASH),

        invalid("hash-md5",
                "MD5 is not part of the format.",
                {"sharedSecret": SECRET, "hashAlgorithm": "md5"},
                ERR_HASH),

        # -- Alphabet -------------------------------------------------------

        invalid("alphabet-empty",
                "An explicitly empty alphabet is rejected (it does not fall back to the default).",
                {"sharedSecret": SECRET, "alphabet": ""},
                ERR_ALPHABET_EMPTY),

        invalid("alphabet-whitespace-only",
                "A whitespace-only alphabet trims to empty and is rejected.",
                {"sharedSecret": SECRET, "alphabet": "   "},
                ERR_ALPHABET_EMPTY),

        invalid("alphabet-3-chars",
                "An alphabet with fewer than 4 characters is rejected.",
                {"sharedSecret": SECRET, "alphabet": "abc"},
                ERR_ALPHABET_SIZE),

        invalid("alphabet-duplicates",
                "An alphabet with duplicate characters is rejected.",
                {"sharedSecret": SECRET, "alphabet": "abcdeff"},
                ERR_ALPHABET_DUP),

        invalid("alphabet-inner-whitespace",
                "An alphabet with interior whitespace is rejected (duplicates are checked first).",
                {"sharedSecret": SECRET, "alphabet": "ab cdef"},
                ERR_ALPHABET_WS),

    ]


# --------------------------------------------------------------------------
# The HTTP authentication vectors (../totp-http-authentication.md,
# "Authorization: TOTP" scheme) - RFC 9110 auth-params:
#
#     TOTP login="<b64>", totp="<b64>"[, tlscb=true|false]
#
# login/totp are mandatory (Base64 of UTF-8), tlscb is optional and
# DEFAULTS TO TRUE (secure by default: an unbound deployment must say
# tlscb=false explicitly). Unknown parameters are ignored, duplicates are
# rejected. The whole file requires the "httpAuthentication" capability -
# currently Hermod only; harnesses without it skip the file DECLARATIVELY
# (a visible skip, never silence). The Basic Auth binding of the
# specification gets no vectors here: its encoding is RFC 7617's, not ours.
# --------------------------------------------------------------------------

HTTP_LOGIN      = "chargingstation-0001"
HTTP_RAW_TOTP   = "CN63y502maVh"    # vector "defaults-mid-slot"
HTTP_BOUND_TOTP = "gAzxPfYtmRgd"    # vector "tls-binding-sha256"


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def http_header(login: str, totp: str, tlscb: bool) -> str:
    # The canonical form: login and totp as quoted strings (Base64 padding
    # "=" is not a token character), tlscb omitted at its default (true).
    header = f'TOTP login="{b64(login)}", totp="{b64(totp)}"'
    if not tlscb:
        header += ", tlscb=false"
    return header


def http_auth_vector(id_: str, description: str,
                     login: str, totp: str, tlscb: bool) -> dict:
    return {
        "id":           id_,
        "description":  description,
        "input":        {"login": login, "totp": totp, "tlscb": tlscb},
        "expected":     {"header": http_header(login, totp, tlscb)}
    }


def http_auth_vectors() -> list[dict]:

    return [

        http_auth_vector("raw-token",
                         "A raw token must say so: tlscb defaults to true, so tlscb=false is explicit.",
                         HTTP_LOGIN, HTTP_RAW_TOTP, False),

        http_auth_vector("tls-channel-bound",
                         "The canonical bound form omits tlscb - true is the default (secure by default).",
                         HTTP_LOGIN, HTTP_BOUND_TOTP, True),

        http_auth_vector("login-with-colon",
                         "Login and token are Base64-encoded separately, so a colon in the "
                         "login - HTTP Basic Auth's classic ambiguity - is harmless.",
                         "EVSE:DE*GEF*E1234*1", HTTP_RAW_TOTP, False),

        http_auth_vector("login-utf8",
                         "A non-ASCII login is UTF-8 encoded before Base64.",
                         "Ladesäule-Süd-01", "SLuwWQOYh3g0", False),

        http_auth_vector("short-token",
                         "A six character token (the OCPP minimum length).",
                         HTTP_LOGIN, "Ik0dNs", False),

    ]


def http_parse_vectors() -> list[dict]:

    login_q = f'login="{b64(HTTP_LOGIN)}"'
    raw_q   = f'totp="{b64(HTTP_RAW_TOTP)}"'
    bound_q = f'totp="{b64(HTTP_BOUND_TOTP)}"'

    def parses(id_: str, description: str, header: str,
               login: str, totp: str, tlscb: bool) -> dict:
        return {
            "id":           id_,
            "description":  description,
            "header":       header,
            "expected":     {"login": login, "totp": totp, "tlscb": tlscb}
        }

    return [

        parses("scheme-lowercase",
               "The scheme name is matched case-insensitively.",
               f'totp {login_q}, {raw_q}, tlscb=false',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

        parses("scheme-mixed-case",
               "The scheme name is matched case-insensitively.",
               f'tOtP {login_q}, {bound_q}',
               HTTP_LOGIN, HTTP_BOUND_TOTP, True),

        parses("explicit-tlscb-true",
               "tlscb=true is the spelled-out default.",
               f'TOTP {login_q}, {bound_q}, tlscb=true',
               HTTP_LOGIN, HTTP_BOUND_TOTP, True),

        parses("tlscb-value-case-insensitive",
               "The tlscb value is matched case-insensitively.",
               f'TOTP {login_q}, {raw_q}, tlscb=FALSE',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

        parses("tlscb-quoted",
               "Auth-param values may use the quoted-string form.",
               f'TOTP {login_q}, {raw_q}, tlscb="false"',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

        parses("parameter-order-insensitive",
               "Auth-params are unordered.",
               f'TOTP {raw_q}, tlscb=false, {login_q}',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

        parses("unknown-parameter-ignored",
               "Unknown auth-params MUST be ignored - the standard extension point.",
               f'TOTP {login_q}, {raw_q}, tlscb=false, foo="bar"',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

        parses("token-form-value",
               "A Base64 value without padding is a valid token and may come unquoted.",
               f'TOTP {login_q}, totp={b64(HTTP_RAW_TOTP)}, tlscb=false',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

        parses("whitespace-around-separators",
               'Optional whitespace around "=" and "," is accepted.',
               f'TOTP login = "{b64(HTTP_LOGIN)}" , {raw_q} ,tlscb=false',
               HTTP_LOGIN, HTTP_RAW_TOTP, False),

    ]


def http_invalid_headers() -> list[dict]:

    login_q = f'login="{b64(HTTP_LOGIN)}"'
    raw_q   = f'totp="{b64(HTTP_RAW_TOTP)}"'

    def bad(id_: str, description: str, header: str) -> dict:
        return {"id": id_, "description": description, "header": header}

    return [

        bad("missing-login",
            "The login parameter is mandatory.",
            f'TOTP {raw_q}'),

        bad("missing-totp",
            "The totp parameter is mandatory.",
            f'TOTP {login_q}'),

        bad("empty-login",
            "An empty login is rejected.",
            f'TOTP login="", {raw_q}'),

        bad("duplicate-login",
            "Duplicate parameters are ambiguous and rejected.",
            f'TOTP {login_q}, {login_q}, {raw_q}'),

        bad("duplicate-totp",
            "Duplicate parameters are ambiguous and rejected.",
            f'TOTP {login_q}, {raw_q}, {raw_q}'),

        bad("duplicate-tlscb",
            "Duplicate parameters are ambiguous and rejected.",
            f'TOTP {login_q}, {raw_q}, tlscb=false, tlscb=true'),

        bad("tlscb-invalid-value",
            "tlscb is a boolean.",
            f'TOTP {login_q}, {raw_q}, tlscb=maybe'),

        bad("login-not-base64",
            "The login value must be valid Base64.",
            f'TOTP login="not-base64!", {raw_q}'),

        bad("totp-not-base64",
            "The totp value must be valid Base64.",
            f'TOTP {login_q}, totp="not-base64!"'),

        bad("unterminated-quote",
            "A quoted-string must be closed.",
            f'TOTP login="{b64(HTTP_LOGIN)}'),

        bad("abandoned-type-digit-form",
            "The whitespace-separated type digit of an earlier draft is not the format.",
            f'TOTP 0 {b64(HTTP_LOGIN)}:{b64(HTTP_RAW_TOTP)}'),

        bad("abandoned-colon-type-form",
            "The colon-separated type of an earlier draft is not the format.",
            f'TOTP 1:{b64(HTTP_LOGIN)}:{b64(HTTP_RAW_TOTP)}'),

        bad("abandoned-two-segment-form",
            "The typeless two-segment form of an earlier draft is not the format.",
            f'TOTP {b64(HTTP_LOGIN)}:{b64(HTTP_RAW_TOTP)}'),

        bad("bare-token68-blob",
            "A single token68-style blob is not auth-params.",
            f'TOTP {b64(HTTP_LOGIN)}'),

        bad("wrong-scheme",
            "A different authentication scheme is not ours to parse.",
            f'Basic {login_q}, {raw_q}'),

        bad("empty",
            "An empty header value is rejected.",
            ""),

        bad("scheme-only",
            "The scheme name alone is not a credential.",
            "TOTP"),

    ]


# --------------------------------------------------------------------------
# File emission.
# --------------------------------------------------------------------------

def render(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"


def build_files(mirror_dirs: list[Path]) -> dict[Path, str]:

    header = {
        "$comment":       f"GENERATED by {GENERATOR} "
                          f"(OpenChargingTechnology/Whitepapers) - do not edit by "
                          f"hand. Regenerate by rerunning the generator.",
        "specification":  SPEC_NAME,
    }

    canonical = {
        VECTORS_DIR / "totp-test-vectors.json": render({
            **header,
            "description": "Canonical TOTP generation vectors. Absent optional input "
                           "parameters mean: pass null/undefined, so that the "
                           "implementation's own defaulting is exercised. Vectors with "
                           "a 'requires' list only apply to implementations providing "
                           "all listed capabilities.",
            "vectors": generation_vectors()
        }),
        VECTORS_DIR / "totp-invalid-inputs.json": render({
            **header,
            "description": "Inputs that implementations MUST reject, with the shared "
                           "error message text. Harnesses assert that the thrown "
                           "message starts with 'expectedError'. See the file's "
                           "'knownDeviations'/'notApplicable' semantics in "
                           "test-vectors/README.md.",
            "vectors": invalid_vectors()
        }),
        VECTORS_DIR / "totp-http-auth-vectors.json": render({
            "$comment":       header["$comment"],
            "specification":  SPEC_NAME_HTTP,
            "description":    "The 'Authorization: TOTP' scheme as RFC 9110 auth-params: "
                              "TOTP login=\"<b64>\", totp=\"<b64>\"[, tlscb=true|false]. "
                              "login/totp are mandatory Base64 of UTF-8; tlscb is "
                              "optional and defaults to TRUE; unknown parameters are "
                              "ignored, duplicates rejected. 'vectors' round-trip (build "
                              "the canonical header AND parse it back), 'parseVectors' "
                              "are parse-only leniency cases, 'invalidHeaders' MUST be "
                              "rejected by parsers. The whole file requires the listed "
                              "capabilities; harnesses without them skip it declaratively.",
            "requires":       ["httpAuthentication"],
            "vectors":        http_auth_vectors(),
            "parseVectors":   http_parse_vectors(),
            "invalidHeaders": http_invalid_headers()
        }),
    }

    files = dict(canonical)
    for mirror_dir in mirror_dirs:
        for path, content in canonical.items():
            files[mirror_dir / path.name] = content

    return files


def main() -> int:

    parser = argparse.ArgumentParser(
        description="Generate or verify the TOTP test vector annex.")
    parser.add_argument("--check",  action="store_true",
                        help="verify the files instead of writing them (drift guard)")
    parser.add_argument("--mirror", action="append", type=Path, default=[],
                        metavar="DIR",
                        help="also write/verify a copy of each file in DIR "
                             "(repeatable); used by the conformance repository "
                             "for the vendored copies inside its implementation "
                             "submodules")
    args = parser.parse_args()

    for mirror_dir in args.mirror:
        if not mirror_dir.is_dir():
            print(f"--mirror {mirror_dir}: not a directory (submodule not checked out?)")
            return 2

    check_anchors()

    files = build_files(args.mirror)

    stale = []
    for path, content in files.items():
        # The vendored copies live in repositories without an eol=lf
        # .gitattributes rule, so autocrlf checkouts materialize them with
        # CRLF - that is not drift. (The canonical files are LF-pinned by
        # this repository's .gitattributes.)
        current = path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else None
        if current != content:
            stale.append(path)
            if not args.check:
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(content)

    if args.check:
        if stale:
            for path in stale:
                print(f"STALE: {os.path.relpath(path)}")
            mirrors = "".join(f" --mirror {d}" for d in args.mirror)
            print(f"Regenerate with: python {sys.argv[0]}{mirrors}")
            return 1
        print(f"All anchors hold and {len(files)} vector files are current.")
        return 0

    for path in files:
        marker = "updated" if path in stale else "unchanged"
        print(f"{marker}: {os.path.relpath(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
