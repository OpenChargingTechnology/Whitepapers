# Open Charging Cloud TOTP — HTTP Authentication

**Version 1.0 — Draft**, 2026-08-22
[CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) · [OpenChargingTechnology/Whitepapers](https://github.com/OpenChargingTechnology/Whitepapers) · conformance suite: [OpenChargingCloud/TOTPConformanceTests](https://github.com/OpenChargingCloud/TOTPConformanceTests)

This document specifies how the tokens of the
[Open Charging Cloud TOTP Token Format](totp-token-format.md) are carried in
HTTP for **machine-to-machine authentication** — as a drop-in replacement for
HTTP Basic Authentication and for long-lived static bearer tokens (e.g.
OCPI-style `Authorization: Token …`). Three bindings are defined:

 * **TOTP over HTTP Basic Authentication** (section 4) — the token in
   Basic's password field: zero new wire code, the migration path;
 * the **`Authorization: TOTP` scheme** (section 5) — login and token as
   RFC 9110 auth-params, with TLS channel binding signaled in-band
   (`tlscb`, default **true**): the native Basic replacement;
 * the **`TOTP` request header** (section 6) — a typed token only, for
   deployments where the peer's login is already established.

The native bindings are implemented by [Vanaheimr
Hermod](https://github.com/Vanaheimr/Hermod); Appendix A records the
implementation status. Unlike the token format itself — frozen by deployed
verifiers and finalized — this binding document is a **draft**: it has a
single implementation, and its wire details may still change.


## 1. Introduction

HTTP Basic Authentication ships a static password with every request: one
captured request, one log line, one misconfigured proxy, and the credential
is compromised until somebody rotates it. Replacing the password with a TOTP
bounds that damage to the token's validity time (30 seconds by default), and
adding TLS channel binding (section 6.2) removes even that window: a bound
token is useless outside the TLS session it was derived for.

The tokens themselves — derivation, parameters, validation rules, the
previous/current/next acceptance window — are defined in the [token format
specification](totp-token-format.md) and are **not** redefined here. This
document only defines how they travel in HTTP requests and how HTTP servers
verify them.

Typical deployments: OCPP charging station WebSocket connections (the HTTP
Upgrade handshake, section 7, today mostly protected by Basic Auth), OCPI
peer connections, and internal service-to-service APIs.


## 2. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in
[RFC 2119] and [RFC 8174] when, and only when, they appear in all capitals.

*Token format spec* refers to [totp-token-format.md](totp-token-format.md).
The **login** is the name under which the verifier looks up a peer's TOTP
configuration (shared secret, validity time, length, alphabet, hash
algorithm — the `TOTPConfig` of token format spec Appendix B). It is
deliberately not called a "user": a login names a **role** — a charging
station, a backend service, a tenant — and nothing about it implies a
natural person. *Base64* is the Base64 encoding of [RFC 4648] section 4,
with padding.


## 3. Prerequisites

Client and verifier share a TOTP configuration per login, provisioned out of
band. The verifier maintains a mapping *login → TOTP configuration*; the
client knows its own login and configuration. How the mapping is provisioned
and rotated is out of scope (token format spec section 8 states the
requirements on the secret itself).


## 4. TOTP over HTTP Basic Authentication

The simplest deployment needs no new wire format at all: the client puts the
**current token into Basic's password field**, exactly as defined by
[RFC 7617]:

```abnf
credentials  = "Basic" SP base64( login ":" totp )
```

Example — login `chargingstation-0001`, token `CN63y502maVh` (the
`defaults-mid-slot` vector of the canonical test vectors):

```http
GET /ocpp HTTP/1.1
Host: csms.example.com
Authorization: Basic Y2hhcmdpbmdzdGF0aW9uLTAwMDE6Q042M3k1MDJtYVZo
```

The verifier decodes the credentials per RFC 7617 and verifies the password
as a presented token — the procedure of section 5.3, steps 2–3, unchanged.

**What this buys.** The "password" now rotates itself every validity
interval: an observed or logged credential dies within the acceptance window
instead of living until somebody remembers to rotate it. On the client this
is often a **zero-code change** — every HTTP stack, proxy, load balancer and
CLI on earth already speaks Basic, and many devices can be pointed at a
rotating password without touching their firmware. Only the server's
password comparison changes.

**What it cannot do** — Basic is traditional, and it shows:

 * The login **MUST NOT contain a `":"`** — RFC 7617 encodes
   `login ":" password` as one Base64 blob, so a colon in the login is
   unrepresentable (the classic Basic ambiguity).
 * There is **no channel binding signal**: every Basic-carried token is a
   raw token (section 6.2 does not apply).
 * Non-ASCII logins and tokens inherit RFC 7617's charset vagueness
   (the `charset` auth-param covers only UTF-8, and support varies).
 * From the outside it stays *Basic*: intermediaries, security scanners and
   log-redaction tooling treat the credential as a static password, with all
   the caching and prompting behaviour that entails.

Deployments that control both ends SHOULD therefore use the native scheme of
section 5; the Basic binding is the zero-friction migration path, and a
verifier MAY accept both during a transition.


## 5. The `Authorization: TOTP` scheme

### 5.1. Syntax

The credentials are a list of **auth-params** ([RFC 9110] section 11.3),
exactly as that specification recommends for new schemes:

```abnf
credentials  = "TOTP" 1*SP #auth-param

; defined parameters:
;   login = <Base64 of the UTF-8 encoded login>          (MANDATORY)
;   totp  = <Base64 of the UTF-8 encoded TOTP>           (MANDATORY)
;   tlscb = "true" / "false"                             (OPTIONAL, default: true)
```

 * The scheme name and all parameter names are matched case-insensitively;
   parameters are unordered.
 * `login` and `totp` are MANDATORY. Senders MUST use the quoted-string
   form for them — Base64 padding (`=`) is not a `token` character;
   recipients MUST also accept the token form where it is syntactically
   valid (unpadded Base64).
 * `tlscb` says whether the token is bound to this TLS session (section
   6.2). It is OPTIONAL and **defaults to `true`** — secure by default: a
   credential that says nothing about binding claims the strong mode, and
   a deployment sending raw tokens must say `tlscb=false` explicitly.
   Senders SHOULD omit `tlscb` when it is `true`. The value is matched
   case-insensitively, in token or quoted-string form.
 * Recipients MUST ignore unknown parameters — the standard auth-param
   extension point. Duplicate parameters, missing mandatory parameters,
   invalid Base64 and invalid `tlscb` values are rejected as malformed
   (section 8).

Example — login `chargingstation-0001`, raw token `CN63y502maVh` (the
`defaults-mid-slot` vector of the canonical test vectors):

```http
GET /ocpp HTTP/1.1
Host: csms.example.com
Authorization: TOTP login="Y2hhcmdpbmdzdGF0aW9uLTAwMDE=", totp="Q042M3k1MDJtYVZo", tlscb=false
```

The same login with a TLS-channel-bound token (`gAzxPfYtmRgd`, the
`tls-binding-sha256` vector) — the canonical form omits `tlscb`:

```http
Authorization: TOTP login="Y2hhcmdpbmdzdGF0aW9uLTAwMDE=", totp="Z0F6eFBmWXRtUmdk"
```

Unlike Basic Authentication — which Base64-encodes `login:password` as one
string and therefore cannot represent a `":"` inside the login ([RFC 7617]
section 2) — login and token are encoded **separately** here, so both may
contain any Unicode character, including `":"`.

### 5.2. Client behaviour

For every request the client computes the **current** token for its
configuration (token format spec section 4) and sends it as above. A token
MAY be reused for consecutive requests within its remaining validity time;
clients MUST NOT send a cached token beyond that.

### 5.3. Server verification

On receiving the header, the verifier:

1. Parses the auth-params: unknown parameters are ignored; duplicate
   parameters, a missing `login` or `totp`, invalid Base64 and an invalid
   `tlscb` value are rejected as malformed (section 8). `login` and `totp`
   are Base64-decoded and UTF-8-decoded; `tlscb` defaults to `true` when
   absent.
2. Looks up the TOTP configuration for the login. An unknown login is
   rejected exactly like a wrong token (section 8).
3. Computes `previous`, `current` and `next` for its own clock and the
   login's configuration — with `tlscb=true` (explicit or by default) the
   exporter material of the receiving TLS session is applied on the
   verifier's side as well, under the rules of section 6.2 — and accepts
   iff the presented token equals one of the three: the acceptance window
   of token format spec section 7, including its guidance: constant-time
   comparison, no widening of the window, single-use enforcement and rate
   limiting where replay matters.

Requests without an `Authorization` header, and requests that fail
verification, are answered with `401 Unauthorized`; the response SHOULD
carry a challenge:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: TOTP realm="ocpp"
```

The `realm` parameter is OPTIONAL and follows [RFC 9110] section 11.


## 6. The `TOTP` request header

### 6.1. Syntax

For deployments where the peer's login is already established — a mutual
TLS connection, a per-client URL path, an already-authenticated session —
the token travels in a dedicated request header, prefixed with a one-digit
**type**. This binding descends from the proprietary `Token`-style
authentication that GitHub's REST API originally defined
(`Authorization: token <token>`) and that e-mobility protocols such as OCPI
later adopted (`Authorization: Token <static-token>`): the same lightweight
shape, except that the token now exchanges itself every validity interval
instead of being a static, long-lived secret.

```abnf
TOTP-header  = "TOTP:" OWS totp-type SP totp-value OWS
totp-type    = "0" / "1"
totp-value   = 1*VCHAR   ; a token of the token format spec
```

| Type | Meaning |
|------|---------|
| `0`  | A raw token (token format spec section 4). |
| `1`  | A token bound to this TLS session (token format spec section 6). |

Examples — the `defaults-mid-slot` and `tls-binding-sha256` vectors:

```http
TOTP: 0 CN63y502maVh
```

```http
TOTP: 1 gAzxPfYtmRgd
```

Verifiers MUST reject unknown type digits.

### 6.2. TLS v1.3 channel binding

A bound token is derived with TLS exporter material per token format spec
section 6 (label `EXPORTER-Time-Based-One-Time-Password-v1`, empty context,
32 bytes RECOMMENDED). The verifier derives the **same** material from its
own side of the TLS connection the request arrived on, and verifies against
tokens computed with it. A captured bound token is useless on any other
connection, which makes replay impractical even if the token leaks into a
log.

Channel binding MUST only be used on TLS v1.3 (or newer) connections —
earlier TLS versions have no exporter interface with these properties. A
verifier that cannot derive exporter material for the receiving connection
MUST reject a bound token; it MUST NOT fall back to verifying it as raw.

These rules apply to channel binding in **either** native binding: the
`TOTP` request header signals it with type digit `1`, the
`Authorization: TOTP` scheme with `tlscb` absent or `true` (section 5.1).

### 6.3. Verification

As in section 5.3, steps 2–3, with the login taken from the connection
context instead of the header, and — for type `1` — the exporter material of
the receiving TLS session applied to the token derivation on the verifier's
side as well.

### 6.4. Caching

Generic HTTP caches do not know that the `TOTP` header carries a
credential: the request looks unauthenticated to them, so a shared cache
could store a response to an authenticated request and serve it to an
unauthenticated client. Servers authenticating via the `TOTP` request
header MUST therefore mark such responses `Cache-Control: private` (or
`no-store`). `Vary: TOTP` is NOT a substitute — with tokens changing every
validity interval it merely fragments the cache without expressing that the
header is a credential. (The Authorization-based bindings of sections 4 and
5 do not need this rule: [RFC 9111] section 3.5 already restricts caching
of responses to requests with an `Authorization` header field.)


## 7. WebSocket handshakes

All three bindings apply unchanged to the HTTP Upgrade request of a
WebSocket handshake ([RFC 6455]) — the primary use in OCPP, where a charging
station's WebSocket connection is today typically protected by HTTP Basic
Auth. Verification happens once, during the handshake; an accepted
connection stays authenticated for its lifetime. Deployments needing
periodic re-authentication of long-lived connections re-establish the
connection or use an application-level mechanism; in OCPP the TOTP then also
plays its other role, in dynamic QR codes (token format spec section 1.2).


## 8. Error handling

 * Syntactically malformed credentials (bad Base64, a missing mandatory
   parameter, duplicate parameters, an invalid `tlscb` value, an unknown
   type digit, an empty token): `400 Bad Request` — or `401` as below; a
   server MAY treat malformed as failed.
 * Failed verification and unknown logins: `401 Unauthorized`. The
   response MUST NOT distinguish "unknown login" from "wrong token"
   (login enumeration).
 * Servers SHOULD NOT write presented tokens to logs. A leaked raw token
   dies with its slot, but log lines outlive validity windows and reveal
   token length and alphabet; a leaked bound token is harmless, which is
   one more reason to prefer channel binding.


## 9. Protocol considerations (RFC 9110 §16.4.2)

[RFC 9110] section 16.4.2 lists considerations for new authentication
schemes. This scheme is private-use (see the third point), but answers them
anyway:

 * **Statelessness.** Every request carries everything the verifier needs:
   login, token and the binding flag. Verification requires only the
   verifier's clock and the provisioned login → configuration mapping
   (section 3) — no per-client session state. Two deliberate exceptions:
   the OPTIONAL single-use enforcement of section 5.3 (anti-replay) is
   server state bounded to one validity slot per accepted token, and a
   bound token binds to the **TLS session** it was derived for (section
   6.2) — transport state, by design, never application session state.

 * **The `realm` parameter** keeps exactly its [RFC 9110] section 11.5
   protection-space semantics; this document does not reinterpret it. The
   login → configuration mapping is scoped per protection space, and a
   client MAY send credentials preemptively for further requests within a
   protection space it has already authenticated against.

 * **token68 / auth-param.** Both directions are conformant: the challenge
   uses auth-params (`realm`), and the credentials use the auth-param
   syntax exactly as section 16.4.2 recommends for new schemes — an IANA
   registration would need no syntactic migration. The scheme name `TOTP`
   is nevertheless **not** registered in the IANA HTTP Authentication
   Scheme Registry yet; until it is, this stays a private-use scheme
   between consenting implementations.

 * **Unknown parameters.** In *credentials*: recipients MUST ignore
   parameters they do not recognize — the standard auth-param extension
   point, and the route future extensions of this scheme will take.
   Ambiguity still fails closed: duplicate parameters and missing
   mandatory parameters are rejected. (The `TOTP` request header of
   section 6 has no parameters; its extension point is the type digit.)
   In *challenges*: clients MUST ignore unknown auth-params, as
   [RFC 9110] already requires.

 * **Origin-server and proxy authentication.** The scheme is designed for
   origin-server authentication (`401` / `WWW-Authenticate` /
   `Authorization`). It MAY be used for proxy authentication (`407` /
   `Proxy-Authenticate` / `Proxy-Authorization`) with raw tokens
   (`tlscb=false`), where the proxy holds the login's configuration.
   Channel binding is only meaningful when the verifier is the TLS
   endpoint of the connection carrying the request — with classic CONNECT
   tunneling a proxy is not, so bound tokens MUST NOT be used for proxy
   authentication there.

 * **Caching.** For the Basic binding and the `Authorization: TOTP` scheme
   the credentials travel in the `Authorization` header field, which HTTP
   caches already treat specially ([RFC 9111] section 3.5: shared caches do
   not store such responses unless response directives explicitly allow
   it). The `TOTP` request header is invisible to generic caches — the
   normative rule of section 6.4 exists for exactly that reason.


## 10. Security considerations

 * **TLS is REQUIRED** for the Basic binding, and for raw tokens
   (`tlscb=false` / type `0`) in the native bindings: a raw token is
   replayable within its acceptance window by anyone who observes it.
   (This is still a categorical improvement over classic Basic Auth, where
   observation compromises the credential *permanently*.) A bound token is
   self-protecting against replay, but the login and everything else in
   the request still deserve TLS.
 * **The verifier's clock is a security boundary.** Every guarantee in
   this document is time-boxed: a token "dies with its slot" only if the
   verifier's clock actually moves on. An attacker who can shift that
   clock — classic unauthenticated NTP is trivially spoofable on-path —
   can resurrect expired tokens, pre-date captured ones, or push the clock
   forward to deny service. Verifiers (and generators) SHOULD therefore
   obtain time from an **authenticated source**; we strongly RECOMMEND
   Network Time Security ([RFC 8915]) for NTP ([RFC 5905]) deployments.
 * The full guidance of token format spec sections 7 and 8 applies:
   constant-time comparison, single-use enforcement per (login, slot,
   token) where replay matters, rate limiting of failed attempts, and
   randomly generated secrets of at least 128 bits.
 * Registration status, credentials grammar and caching interplay are
   protocol properties, not vulnerabilities — see section 9.


## 11. Test vectors (normative for the native scheme)

The `Authorization: TOTP` scheme is covered by canonical vectors in the
normative annex:
[`test-vectors/totp-http-auth-vectors.json`](test-vectors/totp-http-auth-vectors.json),
gated as a whole file by the capability **`httpAuthentication`**:

 * `vectors` — credential building: login, token and binding flag in, the
   exact canonical header value out; harnesses also parse the header back
   and compare (round-trip).
 * `parseVectors` — parse-only leniency cases: scheme and value casing,
   parameter order, `tlscb` defaulting and quoting, the
   unknown-parameter must-ignore rule, token-form values.
 * `invalidHeaders` — header values parsers MUST reject, including
   duplicates, missing mandatory parameters, and the wire forms of
   earlier drafts of this document.

Harnesses of implementations without the capability skip the file
**declaratively** (a visible skip, never silence). The token values inside
come from the canonical token vectors (`defaults-mid-slot`,
`tls-binding-sha256`, …).

The Basic binding (section 4) gets no vectors of its own: its encoding is
[RFC 7617]'s, not ours, and the tokens are the token format's. The `TOTP`
request header's value is a bare token (its wire format is trivial); its
channel binding semantics are exercised through the scheme vectors.


## 12. References

 * [Token format specification](totp-token-format.md) — the tokens carried here
 * [RFC 2119] / [RFC 8174] — Key words for use in RFCs
 * [RFC 4648] — The Base16, Base32, and Base64 Data Encodings
 * [RFC 5905] — Network Time Protocol Version 4
 * [RFC 6455] — The WebSocket Protocol
 * [RFC 7617] — The 'Basic' HTTP Authentication Scheme
 * [RFC 8446] — The Transport Layer Security (TLS) Protocol Version 1.3
 * [RFC 8915] — Network Time Security for the Network Time Protocol
 * [RFC 9110] — HTTP Semantics
 * [RFC 9111] — HTTP Caching

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC 5905]: https://www.rfc-editor.org/rfc/rfc5905
[RFC 6455]: https://www.rfc-editor.org/rfc/rfc6455
[RFC 7617]: https://www.rfc-editor.org/rfc/rfc7617
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446
[RFC 8915]: https://www.rfc-editor.org/rfc/rfc8915
[RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110
[RFC 9111]: https://www.rfc-editor.org/rfc/rfc9111


## Appendix A — Implementation status (informative)

| Piece | Hermod | TOTP.ts |
|-------|--------|---------|
| Token derivation | yes | yes |
| TOTP over Basic Authentication (section 4) — existing RFC 7617 machinery; only the server-side password check changes | wire: yes, verification: pending | no |
| `Authorization: TOTP` — build & parse as auth-params: `login`, `totp`, `tlscb` with its true-default (`HTTPTOTPAuthentication`, vector-driven tests) | yes | no |
| `TOTP` request header — build & parse (`TOTPHTTPHeader`), auto-attached by the HTTP client from its `TOTPConfig` | yes | no |
| TLS exporter material (channel binding derivation) | yes | no |
| Server-side verification against the login → config mapping (`AWebSocketServer.ClientTOTPConfig`) | prepared, in progress | no |

The server-side verification procedure of sections 5.3 and 6.3 is what this
document exists to pin down before that code lands.
