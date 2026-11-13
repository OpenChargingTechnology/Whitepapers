# EVQI Transport: Key Pins and TLS 1.3 Raw Public Keys - Specification

**Version 0.1, Draft**, 2026-11-13
[CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) · [OpenChargingTechnology/Whitepapers](https://github.com/OpenChargingTechnology/Whitepapers)

This is the specification that belongs to
[Key Pins and TLS 1.3 Raw Public Keys for Local Controllers](RawPublicKeys.md), its work package K8.
That paper says why; this one says what a node has to do, so that a second implementation can be
built from it and work with the first. Where the two differ, this document describes what the
reference implementation does and what was tested; [Annex A](#annex-a-the-reference-implementation)
lists where that implementation falls short of the text.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119 and RFC 8174.

---

## Contents

1. [Scope and terms](#1-scope-and-terms)
2. [The key pin](#2-the-key-pin)
3. [Endpoints](#3-endpoints)
4. [TLS: the wire profile](#4-tls-the-wire-profile)
5. [Trust on first use and probation](#5-trust-on-first-use-and-probation)
6. [The signed pin set](#6-the-signed-pin-set)
7. [Device model](#7-device-model)
8. [Security events](#8-security-events)
9. [A node that is dialled: the Local Controller's station port](#9-a-node-that-is-dialled-the-local-controllers-station-port)
10. [The CSMS](#10-the-csms)
11. [What is not specified](#11-what-is-not-specified)
12. [References](#12-references)

- [Annex A: the reference implementation](#annex-a-the-reference-implementation)
- [Annex B: a pin set, worked through](#annex-b-a-pin-set-worked-through)

---

## 1. Scope and terms

The specification covers a TLS connection one OCPP node dials to another, where the node dialled
has no certificate a certificate authority vouches for: a charging station to its Local Controller,
and a Local Controller to its CSMS. It covers OCPP 2.1. For OCPP 1.6 it defines the security
events and the request gate only (section 11).

| Term | Meaning |
|---|---|
| **dialling node** | the node that opens the connection: a charging station, or a Local Controller on its line to the CSMS |
| **dialled node** | the node that accepts it: a Local Controller on its station port, or a CSMS |
| **endpoint** | one connection a dialling node is configured with, with an identification that does not change while it exists |
| **key pin** | section 2 |
| **pin set** | the key pins of one endpoint with a version, handed over signed (section 6) |
| **pin set signer** | a public key a dialling node believes pin sets by; given to it at commissioning |
| **CA-checked**, **key-pinned** | the two modes of an endpoint (section 3) |
| **raw public key** | a key presented in the TLS handshake without a certificate (RFC 7250) |

---

## 2. The key pin

1. A key pin is the SHA-256 hash over the DER encoding of the SubjectPublicKeyInfo of a key: 32
   bytes. It is the matching data of a TLSA record `3 1 1` and the `pin-sha256` of RFC 7469.
2. A key pin is **written** as 64 lowercase hexadecimal digits. Every device model variable and
   every security event of this specification writes it so.
3. A node MUST **read** a key pin in each of these notations, after removing surrounding white
   space:
   - 64 hexadecimal digits, upper or lower case;
   - 95 characters: 32 pairs of hexadecimal digits with one colon between the pairs;
   - `sha256//` (compared without regard to case) and 44 characters of base64 with padding that
     decode to 32 bytes.

   It MUST refuse everything else, among it other lengths, other separators and base64 without
   padding.
4. A list of key pins is separated by single commas, without white space. An empty entry makes the
   list invalid. A node SHOULD remove duplicates when it stores a list.
5. An endpoint holds **at most four** key pins. A list with more entries is refused as a whole.
6. Before a key is hashed and compared, its SubjectPublicKeyInfo MUST be checked (section 4.5).

A key pin is not the fingerprint of a certificate and not an SSH fingerprint; neither may be
accepted in its place.

---

## 3. Endpoints

1. An endpoint is either **CA-checked** or **key-pinned**. It is key-pinned when it holds at least
   one key pin or when its `TrustOnFirstUse` is `Key`. There is no third mode.
2. A key-pinned endpoint believes its server when, and only when, the server proved possession of
   a key (section 4.6) whose pin is among the endpoint's pins - or, with no pins and
   `TrustOnFirstUse = Key`, when it is the first key it sees (section 5). It MUST NOT check the
   chain, the name, the validity period or the revocation of a certificate the key came in, and it
   MUST NOT fall back to those checks when the pin does not match.
3. A CA-checked endpoint MUST NOT offer raw public keys and MUST abort the handshake when the
   server presents one.
4. A pin that does not match is always a refusal. There is no setting that records or accepts a
   mismatch.
5. An endpoint has these settings; section 7.1 names them as variables:

   | Setting | Values | Default |
   |---|---|---|
   | key pins | up to four | none |
   | version of the pin set | integer ≥ 0 | 0 |
   | `RawPublicKeys` | `Off`, `Prefer`, `Require` | `Off` |
   | `TrustOnFirstUse` | `None`, `Key` | `None` |
   | probation time | 1 s to 604800 s | 600 s |

   `RawPublicKeys` other than `Off` is allowed on a key-pinned endpoint only.
6. An endpoint with no pins and `TrustOnFirstUse = None` is CA-checked, not unauthenticated.

---

## 4. TLS: the wire profile

This section holds for every handshake in which the certificate type `RawPublicKey` (RFC 7250) is
offered or chosen. A key-pinned endpoint with `RawPublicKeys = Off` uses TLS as before and checks
the pin of the key in the server's certificate; of this section, only 4.5 to 4.7 apply to it.

### 4.1 TLS 1.3 only

A client that offers `RawPublicKey` MUST offer TLS 1.3 alone, and a server MUST NOT choose
`RawPublicKey` in another version. In TLS 1.2 the Certificate messages are sent in the clear.

### 4.2 What the client offers

| `RawPublicKeys` of the endpoint | `server_certificate_type` in the ClientHello |
|---|---|
| `Off` | the extension is not sent |
| `Prefer` | `[RawPublicKey, X509]` |
| `Require` | `[RawPublicKey]` |

A client that has a key of its own and whose endpoint allows raw public keys sends
`client_certificate_type` with `RawPublicKey` first. It MAY list `X509` after it when it has a
certificate for the same key.

### 4.3 What the server chooses

1. A server has a setting of its own, `Off`, `Prefer` or `Require`, with the default `Off`.
2. `Off`: the server answers without the extension and presents its certificate.
3. `Prefer`: the server chooses `RawPublicKey` when the client offers it, and presents its
   certificate otherwise. The pin is the same in both cases: the certificate carries the same key.
4. `Require`: the server chooses `RawPublicKey`, and aborts with `unsupported_certificate` when
   the client does not offer it.
5. For the client's key, the server's preference decides: where it takes raw client keys and the
   client offers them, it chooses `RawPublicKey`.

### 4.4 Types nobody offered, and the Certificate message

1. A client MUST abort when the server chooses a certificate type it did not offer: with
   `unsupported_extension` when it sent no such extension, with `illegal_parameter` when the type
   is not on its list. A server MUST take either alert for the same refusal: not every TLS stack
   tells the two cases apart.
2. A Certificate message of the type `RawPublicKey` holds the SubjectPublicKeyInfo in the place of
   the certificate. A server's has exactly one entry; a client's has one, or none when the client
   has no key. More than one entry MUST be refused with `bad_certificate`.
3. The extensions of the entry are ignored. There is no OCSP stapling for a raw public key.
4. A server MUST refuse, with `bad_certificate`, a client Certificate message of another type
   than the one it chose.

### 4.5 The SubjectPublicKeyInfo

Before a key is hashed, compared or used to verify a signature, a node MUST check that

- the input is DER and nothing follows the SubjectPublicKeyInfo or any part of it, and the BIT
  STRING of the key has no unused bits;
- the algorithm is one of those below, with exactly the parameters named;
- the key is one of that algorithm.

| Algorithm | Parameters | The key |
|---|---|---|
| EC, `1.2.840.10045.2.1` | the named curve secp256r1, secp384r1 or secp521r1 | an uncompressed point, both coordinates below the field prime, on the curve |
| Ed25519, `1.3.101.112` | none | 32 bytes that decode to a point on the curve, not one of the eight points of small order |
| ML-DSA-44, -65, -87, `2.16.840.1.101.3.4.3.17` to `.19` | none | 1312, 1952 or 2592 bytes |
| RSA, `1.2.840.113549.1.1.1` | NULL | **in a certificate only**: an odd modulus, an odd exponent of at least 3 |

A **raw** RSA key MUST be refused. A key that fails the check is refused with `bad_certificate`,
and no pin is computed, compared or learned.

Every node MUST support ECDSA with P-256 (`ecdsa_secp256r1_sha256`) as the key of a server and of
a client. Ed25519, P-384 and ML-DSA are optional.

### 4.6 Proof of possession

CertificateVerify is verified against the presented key, as in any TLS 1.3 handshake. A key whose
pin matches and whose CertificateVerify does not verify MUST be refused; nothing is accepted and
nothing is learned from such a handshake. A client MUST NOT complete a handshake in which the
server sent no Certificate and no CertificateVerify, unless the handshake resumes a session
(section 4.8).

### 4.7 The verdict ends the handshake

| Case | Alert |
|---|---|
| the client refuses the server's key (pin mismatch, or a key that fails section 4.5) | `bad_certificate` |
| the server refuses a client's raw public key | `access_denied` |
| the server refuses a client's certificate | `bad_certificate` |
| the server needs a client key and gets none | `certificate_required` |
| no certificate type in common | `unsupported_certificate` |

A refusal MUST end the handshake before a byte of application data is sent or accepted. Where a
library reports the verdict apart from the handshake, the application MUST look at it first.

### 4.8 Resumption

A ticket belongs to the key pin it was issued under. A client MUST NOT offer a ticket of a
key-pinned endpoint once that pin is no longer among the endpoint's pins. A server MUST NOT accept
a ticket of a client whose key pin it no longer authorizes; it falls back to a full handshake.
A node MAY leave resumption out for connections with raw public keys.

### 4.9 Unchanged

ALPN, SNI and exporters are as without raw public keys. A client that dials an address sends no
SNI.

---

## 5. Trust on first use and probation

### 5.1 Learning

1. An endpoint learns only where `TrustOnFirstUse` is `Key` and it holds no pins.
2. It learns the pin of the key of the first handshake that passes sections 4.5 and 4.6.
3. The node enters the connection into **probation** first, then writes down the learned pin and
   the time it learned it, then reports `KeyPinLearned` (section 8). When the pin cannot be
   written down the connection is on probation all the same, and no event is sent.
4. The probation ends at the time of learning plus the probation time. It continues across a
   restart: the node holds a learned pin it finds written down to the same deadline.
5. A learned pin is never kept unconfirmed: it is confirmed, replaced or discarded (section 5.4).

### 5.2 The request gate

While a connection is on probation the node MUST refuse every request that comes over it, with
these exceptions:

| Request | Let through when |
|---|---|
| `SetVariables` | it has at least one entry, and every entry is of the component `TLSClientController` with the instance of this endpoint |
| `GetVariables` | every entry is of the component `TLSClientController`, any instance |
| `GetReport` | every `componentVariable` names the component `TLSClientController` |
| `ChangeConfiguration` (OCPP 1.6) | the key is `evqi.serverKeyPins` or `evqi.serverKeyPinsVersion` |

- A refused request is answered with a CALLERROR `SecurityError` whose description says that the
  server is believed by a learned key pin on probation, and names the pin.
- `GetBaseReport` is refused.
- When the node cannot decide, it refuses.
- A node that forwards (a Local Controller on probation towards its CSMS) MUST NOT pass on to
  another node anything that comes over the connection on probation: a request is answered with a
  CALLERROR, a send message is dropped. That holds for pin sets addressed to its stations as well.

What the node sends of its own accord - `BootNotification`, security events, what it queued while
offline, and what its stations send upwards - is not held back.

### 5.3 The three outcomes

**Confirmed.** A signed pin set (section 6) is taken, and the learned pin is among its pins.

1. The node writes down the pins, the version, and that they were confirmed, and clears the
   learned pin - while it holds the endpoint, so that no connection is, in between, neither on
   probation nor refused.
2. The connection leaves probation and stays up. The state is `Confirmed`.
3. The node reports `KeyPinConfirmed`.

**Rejected.** A signed pin set is taken, and the learned pin is not among its pins.

1. The node writes down the signed pins and the version and clears the learned pin. The state is
   `Configured`.
2. From now on the node refuses everything over the connection (`SecurityError`).
3. It reports `KeyPinRejected`.
4. It answers the `SetVariables` request - with `Accepted` for both entries, since the pin set was
   taken - and closes the connection only after the answer is out, waiting at most 10 s for that.
   A WebSocket is closed with the code 1008 (policy violation).
5. The next connection is held to the signed pins.

**Expired.** No signed pin set was taken before the probation ended.

1. The node refuses everything over the connection.
2. It discards the learned pin, written down or not.
3. It reports `KeyPinProbationExpired`.
4. It closes the connection (WebSocket: 1008) and dials again as its reconnect policy says. With
   no pins and `TrustOnFirstUse = Key` it learns again.

### 5.4 States

| State | Holds when |
|---|---|
| `Learned` | the endpoint has no pins and a learned pin |
| `Confirmed` | the endpoint has pins, and a signed pin set confirmed a pin it had learned |
| `Configured` | everything else, an endpoint without pins included |

A later pin set, as in a rollover, leaves `Configured`: `Confirmed` says only that a learned pin
was confirmed. Setting `TrustOnFirstUse` to `None` discards a learned pin.

---

## 6. The signed pin set

### 6.1 The request

A pin set is one OCPP 2.1 `SetVariables` request with exactly these two entries for one instance
of `TLSClientController`, the instance being the endpoint's identification:

| Variable | `attributeValue` |
|---|---|
| `ServerKeyPins` | one to four key pins, written as in section 2.2, separated by commas |
| `ServerKeyPinsVersion` | the version, a decimal integer |

No `attributeType` is sent (`Actual`). The request is addressed to the node that holds the
endpoint, and carries at least one signature (section 6.3).

### 6.2 How a node decides

For the entries of one instance, in this order. The first rule that fails decides for every entry
it names.

| # | Rule | `attributeStatus` | `reasonCode` |
|---|---|---|---|
| 1 | the instance is an endpoint of this node with a TLS handshake | `UnknownComponent` | `NotFound` |
| 2 | one signature of the request is valid and of a pin set signer of this node, checked **without a time window** (section 6.3) | `Rejected` | `Unsigned` |
| 3 | every entry is a valid value of its variable (section 7.1): a list of at most four key pins, an integer ≥ 0 | `Rejected` | `InvalidValue`, or `ValueOutOfRange` for more than four pins |
| 4 | `ServerKeyPins` and `ServerKeyPinsVersion` come together; one without the other is refused | `Rejected` | `InvalidValue` |
| 5 | the list holds at least one pin | `Rejected` | `InvalidValue` |
| 6 | the version is **strictly higher** than the one the endpoint holds | `Rejected` | `InvalidValue` |

When all hold, the node takes the pins and the version, answers `Accepted` for both entries, and
goes on as section 5.3 says where a pin was learned. Where none was learned it reports
`ReconfigurationOfSecurityParameters`.

- Rule 2 is what an **unsigned** write of these two variables gets: `Rejected`, `Unsigned`.
- The authority lies in the signature alone. The role of the connection the request came over is
  not asked, and neither is a role of the signer: a pin set signer is a key the node was given for
  this purpose. A node policy that would require another signature for `SetVariables` MUST leave
  these two variables to the pin set signers.
- The version is what keeps an older pin set from coming back. It needs no clock.

`RawPublicKeys`, `TrustOnFirstUse` and `ProbationTime` of the same instance MAY be written in the
same request or in one of their own. They need a signature of a pin set signer too, but are
checked **with** the time window of the signature (`Rejected`, `OutOfTime` outside it) and carry
no version. A node that cannot dial with raw public keys MUST refuse `RawPublicKeys = Require`
with `Rejected`, `NotSupported`.

### 6.3 The signature

The signature is a JWS signature of [Signed Messages](../SignedMessages/README.md), in the
`signatures` array of the request:

```json
{ "protected": "<base64url of the protected header>",
  "header":    { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "signature": "<base64url>" }
```

**Signed is** the ASCII text `protected + "." + payload`, where the payload is the base64url of
the request's JSON in the canonical form of RFC 8785, without its members `signatures` and
`@context`.

**The protected header** has these members:

| Member | Value |
|---|---|
| `alg` | `ES256` |
| `kid` | the RFC 7638 thumbprint of the signer's JWK |
| `OCPPVersion` | `ocpp2.1` |
| `OCPPMessageTypeId` | `2` |
| `OCPPAction` | `SetVariables` |
| `OCPPMessageId` | `*` |
| `OCPPNonce` | base64url of 16 random bytes |
| `OCPPSource` | the signer's node, e.g. `CSMS` |
| `OCPPDestination` | the node that holds the endpoint |
| `iat` | the signing time, seconds since 1970 |
| `crit` | the names of the `OCPP…` members present |

`OCPPMessageId` is `*` with a nonce because a node that forwards the request - a Local Controller
- sends it on under a message id of its own.

**A node verifies**, for each of its pin set signers, that

1. it understands every member `crit` names;
2. `kid` is the thumbprint of that signer's key;
3. the signature verifies under that key;
4. `OCPPVersion`, `OCPPMessageTypeId` and `OCPPAction` are those of the request;
5. `OCPPMessageId` is the request's message id, or `*` with an `OCPPNonce` present;
6. `OCPPDestination` is this node;
7. `iat` is present. Its value is not compared with the node's clock, and no expiry is applied:
   this is what "without a time window" means. A node that was never given the time has to be
   able to take the pin set that lets it reach a time server;
8. the same `kid`, message type and nonce were not seen before, for as long as the node keeps its
   replay cache (at least 900 s). Beyond that the version protects.

A pin set signer's key is an ECDSA key on P-256. A node MUST be able to hold more than one.

---

## 7. Device model

### 7.1 `TLSClientController`: a node that dials

One instance per endpoint that dials with TLS, named by the endpoint's identification. The
identification is the node's own and need not mean anything; a Local Controller names its line to
the CSMS `csms`. All variables can be monitored.

| Variable | Type | Mutability | Values | Default | Meaning |
|---|---|---|---|---|---|
| `ServerKeyPins` | string | ReadWrite | up to 4 key pins, comma separated; may be empty | "" | the pins of the keys the server may present. Written only as a pin set (section 6) |
| `ServerKeyPinsVersion` | integer | ReadWrite | ≥ 0 | 0 | the version of the pin set held |
| `ServerKeyPinState` | OptionList | ReadOnly | `Configured`, `Learned`, `Confirmed` | `Configured` | section 5.4 |
| `RawPublicKeys` | OptionList | ReadWrite | `Off`, `Prefer`, `Require` | `Off` | section 4.2 |
| `TrustOnFirstUse` | OptionList | ReadWrite | `None`, `Key` | `None` | section 5.1 |
| `ProbationTime` | integer, seconds | ReadWrite | 1 to 604800 | 600 | section 5.1 |
| `LearnedKeyPin` | string | ReadOnly | a key pin, or "" | "" | the pin on probation |
| `KeyPinShown` | string | ReadOnly | a key pin, or "" | "" | the pin of the key the server showed at the last handshake |
| `URL` | string | ReadOnly | | | the URL dialled, without a password |

One further instance, **without an instance name**, holds what is the node's own:

| Variable | Type | Mutability | Meaning |
|---|---|---|---|
| `ClientKeyPin` | string | ReadOnly | the pins of the keys this node presents as a TLS client, comma separated |

- A write of a read-only variable is answered `Rejected` with the reason code `ReadOnly`, of a
  variable the component does not have `Rejected` with `NotFound`.
- A node that does not know the component answers `UnknownComponent`. A CSMS learns from that
  which nodes can be key-pinned.
- Four pins take 259 characters and fit every `attributeValue`.

### 7.2 `EVQICtrlr[TLSServer]`: a node that is dialled

Of a Local Controller, towards its CSMS, for the key of its station port:

| Variable | Type | Mutability | Meaning |
|---|---|---|---|
| `KeyPins` | string | ReadOnly | the pin of the current key, then of the announced next one |
| `ActiveKeyPin` | string | ReadWrite | the pin of the key presented now. Writing the pin of the announced next key switches to it |
| `NextKeyPin` | string | ReadOnly | the pin of the announced next key, or "" |
| `KeyCreated` | dateTime | ReadOnly | when the current key was made |
| `RawPublicKeys` | OptionList | ReadOnly | `Off`, `On`: whether the port presents its key raw to a client that offers it |

Writing `ActiveKeyPin`:

| Value written | Answer | Effect |
|---|---|---|
| the pin of the current key | `Accepted` | none |
| the pin of the announced next key | `Accepted` | the next key is presented from the next handshake on; no connection is dropped |
| another pin, or no key pin | `Rejected`, `InvalidValue` | none |

---

## 8. Security events

Sent as `SecurityEventNotification` in the node's own name. `<pin>` is a key pin as in section
2.2, `<id>` the endpoint's identification, `<url>` the URL dialled. `techInfo` is cut at 255
characters.

| `type` | `techInfo` | Sent |
|---|---|---|
| `KeyPinLearned` | `Key pin <pin> of endpoint '<id>' (<url>) learned on first use, on probation` | once, when the learned pin was written down |
| `KeyPinConfirmed` | `Key pin <pin> of endpoint '<id>' (<url>) confirmed by the signed pin set of version <n>` | once, when the pin set is taken |
| `KeyPinRejected` | `Key pin <pin> of endpoint '<id>' (<url>) is not among the signed pins of version <n>, which replace it` | once, when the pin set is taken |
| `KeyPinProbationExpired` | `Key pin <pin> of endpoint '<id>' (<url>) not confirmed within <seconds> s; discarded` | once, when the probation ends |
| `InvalidCsmsCertificate` (OCPP 2.1), `InvalidCentralSystemCertificate` (OCPP 1.6) | `Key pin mismatch: <pin> at endpoint '<id>' (<url>)`; `no key` in the place of the pin where the server showed none | on a refused handshake, once per change of the verdict |
| `ReconfigurationOfSecurityParameters` | free text that names the endpoint and the version | a pin set taken where no pin was learned; a change of `RawPublicKeys`, `TrustOnFirstUse` or `ProbationTime` |

1. A receiver MUST take the pin and the endpoint from `KeyPinLearned` by this pattern:
   `Key pin <pin> of endpoint '<id>'`, the rest being for people. A sender MUST NOT change that
   beginning.
2. The events are evidence: a node that is offline keeps them until its CSMS took them.
3. The events of a station behind a Local Controller reach the CSMS through it, with the station
   as their source and the Local Controller as the last hop of their path. A Local Controller's
   events about its own line carry the Local Controller as their source and no further hop.
4. A verdict is new when it is the first refusal, or the refusal of another pin than the last
   with no accepted key in between.

---

## 9. A node that is dialled: the Local Controller's station port

1. The node has one TLS server key per port, and may hold one **next** key, announced before it is
   used. It presents the same key
   - raw, when the client offers `RawPublicKey` and the port's setting allows it (section 4.3);
   - otherwise in a certificate: one a certificate authority issued for that key, or a
     self-signed **carrier certificate** made from it.
2. A carrier certificate says nothing a client may rely on. It SHOULD be valid from
   1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z, carry `basicConstraints` CA:FALSE, `keyUsage`
   digitalSignature and `extendedKeyUsage` serverAuth, and no subject alternative name.
3. **Stations by key.** The node keeps, per station identity, a list of at most four authorized
   key pins. One key pin belongs to one station.
   - A client key whose pin is on the list of a station that is enabled is accepted in the
     handshake by its pin alone; its certificate, if it came in one, is not checked, and its common
     name names no identity.
   - After the handshake the node MUST check that the station the request's URL names is the
     station the pin is listed for, and refuse with HTTP 401 otherwise. The same answer is given
     where the station is disabled or its login group does not allow authentication by key pin.
   - A key that is on no list is a certificate like any other: it is checked against the accepted
     certificate authorities, and fails the handshake where it does not chain to one.
   - A station is authenticated either by key pin or by a certificate and its common name, never
     by both. A station listed with key pins that shows a certificate with another key is refused.
4. Over a connection it accepted, the node MUST refuse what only its CSMS may ask of it -
   `SetVariables` and `GetVariables` of its own device model among it.

---

## 10. The CSMS

### 10.1 Whose word it takes

A forwarded frame names its sender and its path itself. Before anything is done with a request or
a send message that came over a connection the CSMS accepted:

1. **The last hop is the connection.** The last hop of the frame's path MUST be the node the
   connection signed in as.
2. **A connection speaks for itself.** A frame whose source is that node is taken.
3. **Only a Local Controller speaks for others.** A frame with another source is taken only where
   the operator marked the connection's login as a Local Controller's.

A frame that fails is dropped **without an answer**: an answer would go to the node the frame
names. In addition:

4. **The first Local Controller keeps a station.** A station noted behind one Local Controller is
   not moved by a frame that comes through another, and no pin set is sent through that other one.
   The operator releases a station that really moved.

### 10.2 A station learned a pin

On a `KeyPinLearned` of a station that came through the Local Controller the station is noted
behind, the CSMS, after it answered the notification:

1. reads `ActiveKeyPin` and `NextKeyPin` of `EVQICtrlr[TLSServer]` of the Local Controller;
2. asks the station for a `GetReport` of `TLSClientController`, and finds the endpoint: the one
   the event names;
3. sends the station a pin set (section 6) for that endpoint with the Local Controller's current
   pin, and its next one if it has one, and the version **one above** the version the station
   reported;
4. takes the pin set for delivered when both entries are answered `Accepted`.

The pins the CSMS signs are those the Local Controller reported over its own connection, never the
pin the station says it learned.

### 10.3 Rollover of a Local Controller's key

1. The Local Controller announces a next key. Without one the CSMS does not begin.
2. The CSMS sends every station behind it a pin set with the current and the next pin.
3. It reads `ServerKeyPins` of every station. Where one does not hold the next pin, it stops and
   switches nothing.
4. It writes the next pin to `ActiveKeyPin` of the Local Controller (section 7.2).
5. After a grace period it sends every station a pin set with the new pin alone.

Each pin set has the version one above the last the station took.

### 10.4 A Local Controller learned the pin of the CSMS

On a `KeyPinLearned` of a login marked as a Local Controller's, about its own line:

1. Where the pin is the pin of the key the CSMS itself presents at the port the Local Controller
   dialled, the CSMS sends a pin set with its own pin at once, as in section 10.2, steps 2 to 4.
2. Where it is not - TLS ends at a proxy before the CSMS, or somebody answered in its place - or
   where the CSMS presents no key itself, the CSMS MUST NOT send a pin set of its own accord. It
   shows the learned pin beside its own, and the operator names the pins to sign.
3. A CSMS that is asked to confirm without pins being named MUST refuse where the Local Controller
   learned another pin than the CSMS's own.

### 10.5 The signing key

The CSMS signs pin sets with a key of its own for that purpose, on P-256, whose public key the
stations and Local Controllers were given as a pin set signer at commissioning. Without it the
CSMS sends no pin set.

---

## 11. What is not specified

- **OCPP 1.6.** The keys `evqi.serverKeyPins` and `evqi.serverKeyPinsVersion` are named by the
  request gate (section 5.2) so that a later version can hand a pin set over; how it is signed
  there is not defined, and nothing takes one today.
- **The list of authorized station keys** reaches a Local Controller by local means only
  (section 9, rule 3). A message of the CSMS for it is open.
- **`NetworkConfiguration`.** The variables are on a component of their own
  (`TLSClientController`), not on the network profile slots of OCPP 2.1.
- **Roles.** A pin set signer is asked for no role, and a key pin carries none.
- **DANE**, and a QR code of the pins at commissioning.
- **The age of a key**: `KeyCreated` reports it; no policy follows from it.
- **A rollover of the CSMS's own key** towards its Local Controllers.

---

## 12. References

- RFC 2119, RFC 8174: key words
- RFC 7250: Using Raw Public Keys in TLS and DTLS
- RFC 9846: TLS 1.3 · RFC 9001: Using TLS to Secure QUIC
- RFC 5280: X.509 certificates · RFC 8032: Ed25519 (section 5.1.7, points of small order)
- RFC 7469 (`pin-sha256`) · RFC 6698, RFC 7671 (TLSA `3 1 1`)
- RFC 7515: JSON Web Signature · RFC 7638: JWK thumbprint · RFC 8785: JSON canonicalization ·
  RFC 6979: deterministic ECDSA
- RFC 6455: WebSocket (close code 1008)
- OCPP 2.1 Edition 2, Part 2 (`SetVariables`, `GetVariables`, `GetReport`,
  `SecurityEventNotification`; A00.FR.308-310, A00.FR.511), Part 4 (§6.5 *Local Controller
  Security*)
- [Key Pins and TLS 1.3 Raw Public Keys for Local Controllers](RawPublicKeys.md): the reasons, the
  alternatives, and what is built
- [Signed Messages](../SignedMessages/README.md): the JWS signature of an OCPP message
- [EVQI Transport](README.md)

---

## Annex A: the reference implementation

Hermod (transport), WWCP_OCPP, ChargingStation, LocalController and CSMS, as of 2026-11-13; the
commits are in [section 10.8](RawPublicKeys.md#108-what-is-built) of the paper. "QUIC" is Hermod's
own TLS 1.3 under HTTP/3, "TCP" its second TLS stack, BouncyCastle 2.7.0, for HTTP/1.1, HTTP/2 and
WebSockets; a connection without raw public keys stays on .NET's `SslStream`.

| Section | Differs how |
|---|---|
| 4.2 | Over QUIC `client_certificate_type` follows the client credential's own setting (`Prefer`: `[RawPublicKey, X509]`, `Require`: `[RawPublicKey]`), not the endpoint's. Over TCP it is `[RawPublicKey, X509]` whenever the client has a key and the endpoint is `Prefer` or `Require` |
| 4.4, rule 1 | Over TCP an extension that was not offered at all is answered with `illegal_parameter`, not `unsupported_extension`; read in BouncyCastle's source, not tested |
| 4.4, rules 2 and 4 | Over TCP the check for exactly one entry is there and has no test; a client Certificate of another type ends in BouncyCastle's own parsing alert |
| 4.5 | Over TCP the check sees BouncyCastle's re-encoding of the SubjectPublicKeyInfo, not the bytes received. The node's own raw key over TCP is P-256 or P-384; no Ed25519 there. Over QUIC P-256, P-384, Ed25519 and ML-DSA-65 are tested |
| 4.6 | A CertificateVerify that does not verify ends with `handshake_failure` over QUIC and `decrypt_error` over TCP |
| 4.7 | The server answers `access_denied` only where its policy takes raw public keys and what came was a key; otherwise `bad_certificate` |
| 4.8 | Built and tested over QUIC. Over TCP there is no resumption and no 0-RTT with raw public keys |
| 6.2 | `RawPublicKeys = Require` was refused (`NotSupported`) by every node until work package K7; with it (WWCP_OCPP `dd939b01`) an endpoint that requires raw public keys is dialled and the value is taken |
| 6.3 | Pin set signers on P-384 and P-521 are accepted when written down and cannot verify: P-256 only |
| 7.2 | `RawPublicKeys` of `EVQICtrlr[TLSServer]` is always `Off`: the Local Controller's station port does not present its key raw yet, and takes no raw station keys. A write of `ActiveKeyPin` asks for no right of its own beyond the rule of section 9, 4 |
| 8 | `InvalidCsmsCertificate` can be reported again for the same pin after a new dial |
| 9 | Raw client keys reach a WebSocket server over HTTP/1.1 and HTTP/2, not over HTTP/3 |
| 10.4 | A CSMS has no setting of its own yet to present its key raw; the end-to-end tests of K7 use a server of the tests in its place |

**Interoperability.** Both stacks are tested against OpenSSL 3.5 (`s_client` and `s_server` with
`-enable_server_rpk` and `-enable_client_rpk`; over QUIC `s_client -quic`), on Windows and on
Linux. Hermod's QUIC client cannot be tested against OpenSSL, whose `s_server` has no QUIC.

**Tests.** Every refusal this specification asks for has a test that is red on a deliberate
mutation of the code, except where the table above says "no test".

---

## Annex B: a pin set, worked through

A station `CS001` dials `wss://192.168.10.5/ocpp/CS001` with `TrustOnFirstUse = Key`. Its endpoint
is `3f9a1c0e5b7d2a44`.

1. Handshake: the Local Controller presents a key with the pin `6a1f…9b2e`. The station holds no
   pin, learns it, and the connection is on probation for 600 s.
2. The station sends, through the Local Controller:

   ```json
   [2, "17", "SecurityEventNotification",
     { "type": "KeyPinLearned", "timestamp": "2026-11-13T10:00:00.000Z",
       "techInfo": "Key pin 6a1f…9b2e of endpoint '3f9a1c0e5b7d2a44' (wss://192.168.10.5/ocpp/CS001) learned on first use, on probation" }]
   ```

3. The CSMS reads `EVQICtrlr[TLSServer].ActiveKeyPin` of the Local Controller: `6a1f…9b2e`, no next
   key. It asks the station for a report of `TLSClientController` and finds
   `ServerKeyPinsVersion = 0`.
4. The CSMS sends the station:

   ```json
   { "setVariableData": [
       { "component": { "name": "TLSClientController", "instance": "3f9a1c0e5b7d2a44" },
         "variable":  { "name": "ServerKeyPins" },
         "attributeValue": "6a1f…9b2e" },
       { "component": { "name": "TLSClientController", "instance": "3f9a1c0e5b7d2a44" },
         "variable":  { "name": "ServerKeyPinsVersion" },
         "attributeValue": "1" } ],
     "signatures": [
       { "protected": "…",
         "header":    { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
         "signature": "…" } ] }
   ```

   with the protected header

   ```json
   { "alg": "ES256", "kid": "…", "OCPPVersion": "ocpp2.1", "OCPPMessageTypeId": 2,
     "OCPPAction": "SetVariables", "OCPPMessageId": "*", "OCPPNonce": "…",
     "OCPPSource": "CSMS", "OCPPDestination": "CS001", "iat": 1794564005,
     "crit": [ "OCPPVersion", "OCPPMessageTypeId", "OCPPAction", "OCPPMessageId", "OCPPNonce",
               "OCPPSource", "OCPPDestination" ] }
   ```

5. The gate lets the request through: every entry is `TLSClientController` of this endpoint. The
   signature is of a pin set signer, the version 1 is higher than 0, the learned pin is among the
   signed pins. The station answers `Accepted` twice, the state is `Confirmed`, and it reports
   `KeyPinConfirmed`.

Had the CSMS signed another pin, the station would have answered `Accepted` twice as well, reported
`KeyPinRejected`, closed the connection after its answer, and refused the same server at its next
handshake with `bad_certificate`.

---

## License

This document is licensed under [CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
