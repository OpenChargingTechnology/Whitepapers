# NTS-KE Record Type "SSH Key Binding"

**Version 1.0 — Draft**, 2026-11-09
[CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) · [OpenChargingTechnology/Whitepapers](https://github.com/OpenChargingTechnology/Whitepapers) · white paper: [NTS Key Establishment over SSH](README.md) · reference implementation: [Vanaheimr/Norn](https://github.com/Vanaheimr/Norn)

This document specifies the NTS-KE record *SSH Key Binding* of section 5 of the white paper
[NTS Key Establishment over SSH](README.md) as a specification of its own, so that IANA can
register its record type from the range 1024–16383 ("Specification Required") of the registry
"Network Time Security Key Establishment Record Types". Until then the record uses the
provisional type 16386 (Appendix C); this document writes the type as **TBD**.

Editor: Achim Friedland, GraphDefined GmbH.
Stable URL: <https://github.com/OpenChargingTechnology/Whitepapers/blob/master/NTS-over-SSH/nts-ke-ssh-key-binding.md>


## 1. Introduction

Network Time Security (NTS) [RFC8915] derives the two keys of an NTP association from the
TLS exporter of the NTS-KE connection (Section 5.1 of [RFC8915]). The white paper "NTS Key
Establishment over SSH" [NTS-SSH] runs the unchanged NTS-KE records of [RFC8915] inside an
SSH subsystem instead of TLS, so that a private network, such as a charging infrastructure,
can use NTS without a PKI: the server is authenticated by its SSH host key, the client by its
SSH user key.

An SSH connection has no TLS exporter. This document defines the one NTS-KE record that NTS-KE
over SSH adds, *SSH Key Binding*, which negotiates where the keying material comes from
instead, and it specifies the key derivation of each method. Everything else is unchanged:
the other records, the cookies, and NTP itself. An NTP server cannot tell over which transport
the keys inside a cookie were agreed.


## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

- `string(x)` is the SSH string encoding of Section 5 of [RFC4251]: a uint32 length in network
  byte order, followed by the octets of `x`.
- `||` is concatenation.
- All integers are unsigned and in network byte order.
- *Over SSH* means an NTS-KE exchange in the SSH subsystem `ntske/1@open.charging.cloud` of
  [NTS-SSH]. *Over TLS* means an NTS-KE exchange as specified in [RFC8915].


## 3. The SSH Key Binding Record

### 3.1. Format

The record uses the record format of Section 4 of [RFC8915]:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|      Record Type (TBD)      |          Body Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
.                                                               .
.                          Record Body                          .
.                                                               .
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Critical Bit:** MUST be 1, in requests and in responses. A server that implements the
  records of [RFC8915] but not this one has no keying material to give and must refuse the
  request rather than carry on (see Section 6.5).
- **Record Type:** TBD, the value assigned by IANA.
- **Body:** a request and a response carry different bodies, see Sections 3.3 and 3.4. The
  record does not say in which direction it travels; the receiver knows.

### 3.2. Method IDs

A method is a source of keying material. Each method is identified by a 16-bit Method ID:

| Method ID | Name | Data in a response | Requirement |
|---|---|---|---|
| `0x0000` | Reserved | – | MUST NOT be sent |
| `0x0001` | SSH Exporter | `exporter_nonce` (32 octets) | OPTIONAL |
| `0x0002` | Transported Secret | `nts_ke_secret` (32 octets) | REQUIRED to implement |
| `0x0003`–`0x7FFF` | Unassigned | – | assigned by a later version of this document |
| `0x8000`–`0xFFFF` | Private or Experimental Use | defined by the user | – |

Clients and servers MUST implement method `0x0002`. Section 5 specifies the key derivation of
each method.

### 3.3. In a Request

The body is a list of one or more Method IDs, most preferred first:

```
Body = Method ID (2 octets) || Method ID (2 octets) || ...
```

A request over SSH MUST carry exactly one SSH Key Binding record. Its body MUST NOT be empty,
and its length MUST be even. Since every server implements method `0x0002`, a client MUST
include it in every offer; it MAY place other methods before it, including methods the server
may not know.

### 3.4. In a Response

The body is the Method ID the server selected, followed by the data of that method:

```
Body = Selected Method ID (2 octets) || Method Data
```

The length of the Method Data is fixed by the method (Section 3.2).

A response over SSH that carries no Error record MUST carry exactly one SSH Key Binding
record. An error response (Section 4.1.3 of [RFC8915]) carries none.


## 4. Processing Rules

### 4.1. Server

Over SSH, the server:

1. MUST respond with Error code 1 (Bad Request) to a request that does not carry exactly one
   SSH Key Binding record, or whose SSH Key Binding body is empty or of odd length.
2. MUST ignore Method IDs it does not know. They are not an error.
3. MUST select the first method of the client's list that it supports, and MUST respond with
   Error code 1 (Bad Request) when it supports none of them.
4. MUST generate the Method Data of the selected method, `exporter_nonce` for method `0x0001`
   and `nts_ke_secret` for method `0x0002`, anew for every exchange, from a cryptographically
   secure random number generator, and MUST NOT use it for more than one exchange.
5. MUST derive the keys it seals into the cookies of the response as specified for the
   selected method in Section 5.

Over TLS, the record has no meaning. A server that implements this document MUST treat an SSH
Key Binding record received over TLS as an unrecognized record (Section 4 of [RFC8915]). With
its Critical Bit set, that means Error code 0 (Unrecognized Critical Record), which is what
every server that implements only [RFC8915] responds anyway.

### 4.2. Client

Over SSH, the client MUST abort the exchange when the response, unless it carries an Error
record,

- carries no SSH Key Binding record, or more than one,
- selects a method the client did not offer, or
- carries Method Data whose length differs from the one the selected method defines.

Over TLS, a client MUST NOT send the record and MUST treat it in a response as an unrecognized
record (Section 4 of [RFC8915]). With its Critical Bit set, that aborts the exchange.

A client configured for NTS-KE over SSH whose subsystem request is refused or whose exchange
fails MUST NOT silently fall back to another transport (Section 3.2 of [NTS-SSH]): that would
trade the host key it authenticated for whatever the other transport trusts.

### 4.3. Exchanges per Connection

Each channel of the subsystem carries one NTS-KE exchange, as each TLS connection does in
[RFC8915]. A client MAY open the subsystem again on the same SSH connection for another
exchange. Every exchange gets keys of its own: with method `0x0002` from its secret, with
method `0x0001` from its nonce (Section 5.2).


## 5. Key Derivation

### 5.1. Common to All Methods

Section 5.1 of [RFC8915] applies unchanged, except for the function that produces the keying
material. Where [RFC8915] calls the TLS exporter with a label, a context and a length, NTS-KE
over SSH calls `Exporter(label, context, L)` of the selected method, with

- `label` = `"EXPORTER-network-time-security"` (US-ASCII, 30 octets),
- `context` = the five octets of Section 5.1 of [RFC8915]: `0x0000` (NTPv4), the Numeric
  Identifier of the negotiated AEAD algorithm, and `0x00` for the C2S key or `0x01` for the
  S2C key,
- `L` = the key length of the negotiated AEAD algorithm.

Both methods of this document are HKDF-Expand (Section 2.3 of [RFC5869]) under a pseudorandom
key of their own for every exchange; they differ only in where that key comes from. Both use

```
info = string(label) || string(context)
```

The record "Compliant AES-128-GCM-SIV Exporter Context" (record type 1024) has no meaning
over SSH: the context is always that of Section 5.1 of [RFC8915], with the Numeric Identifier
of the negotiated algorithm. A client SHOULD NOT send that record over SSH. A server MUST
ignore it over SSH and MUST NOT echo it.

### 5.2. Method 0x0001: SSH Exporter

The keying material comes from the SSH connection itself. A nonce, which the server sends as
the Method Data of its response, makes it differ for every exchange:

```
exporter_secret = HASH(K || H || string("ssh-exporter@open.charging.cloud") || session_id)

PRK = HKDF-Extract(salt = exporter_nonce,
                   IKM  = exporter_secret)

Exporter(label, context, L) = HKDF-Expand(PRK,
                                          info = string(label) || string(context),
                                          L)
```

- `HASH` is the hash function of the SSH key exchange method. HKDF-Extract and HKDF-Expand
  use HMAC with that hash function.
- `K` and `H` are those of the first key exchange of the SSH connection, and `session_id` is
  the session identifier of Section 7.2 of [RFC4253], so `H` equals `session_id`. The formula
  keeps both, following the key derivation of Section 7.2 of [RFC4253]. `K` is encoded exactly
  as the key exchange method encodes it for its own key derivation (as mpint for most methods,
  as string for some).
- `exporter_secret` is computed once, when the first key exchange completes, and kept for the
  lifetime of the connection. A re-key does not change it, just as a KeyUpdate does not change
  the exporter secret of TLS 1.3 [RFC8446]. Both peers therefore agree on it however re-keys
  and NTS-KE exchanges interleave.
- `exporter_nonce` is the 32 octets of Method Data, generated anew for every exchange
  (Section 4.1). It need not be secret; it keeps the keys of the exchanges on one connection
  apart.

This method requires an SSH implementation that makes `exporter_secret`, or the `K` and `H` of
the first key exchange, available to the NTS-KE subsystem.

Appendix A.3 has test vectors.

### 5.3. Method 0x0002: Transported Secret

The server sends a secret of 32 octets, `nts_ke_secret`, as the Method Data of its response:

```
Exporter(label, context, L) = HKDF-Expand-SHA256(PRK  = nts_ke_secret,
                                                 info = string(label) || string(context),
                                                 L)
```

HKDF-Expand uses HMAC-SHA256 whatever the hash function of the SSH key exchange is. 32 octets
are the output length of SHA-256, the minimum length of a pseudorandom key for HKDF-Expand
with SHA-256.

Appendix A.2 has test vectors.


## 6. Security Considerations

### 6.1. Authentication

The keys are as trustworthy as the authentication of the SSH connection. The client MUST
authenticate the server's host key, against a pinned key or an SSH certificate authority,
before it opens the subsystem; NTS-KE over SSH has no other way to authenticate the server.
Whoever may open the subsystem receives cookies, so the server SHOULD authenticate clients by
SSH user authentication.

### 6.2. Method 0x0002

With method `0x0002` the server alone chooses the keying material. That loses nothing
compared with [RFC8915]: in every NTS deployment the server knows both keys, because it seals
them into the cookies it issues. The secret is confidential and integrity-protected only as
long as the SSH channel is. Whoever can read the secret can also read the cookies and forge
the records of the exchange, and so has already broken the SSH connection. The secret MUST be
generated as Section 4.1 requires.

### 6.3. Method 0x0001

Method `0x0001` binds the keys to the SSH connection, as the TLS exporter binds them to the
TLS connection in [RFC8915]: only the two ends of the connection know `exporter_secret`, and
no keying material crosses the wire. `exporter_nonce` does cross it and need not be secret.

Without the nonce, every exchange on one connection would derive the same keys. A key refresh
would then change nothing, a key that leaked would stay valid for as long as the connection
lives, and associations with different NTP servers would share their keys. The server chooses
the nonce alone, and that is enough: it learns both keys under any method (Section 6.2), and
the nonce only has to keep the exchanges apart.

### 6.4. Method Negotiation

The offer and the selection travel inside the encrypted and authenticated SSH channel. An
on-path attacker cannot remove methods from the offer without breaking SSH.

### 6.5. Transport Confusion

The record is always critical. A server that implements the records of [RFC8915] but not
this one, for instance a TLS-based implementation attached to an SSH subsystem, would
otherwise ignore it and issue cookies whose keys the client cannot derive: an exchange that
succeeds, followed by an association in which every packet fails to authenticate. Over TLS
the keys MUST come from the TLS exporter and nothing else, which Sections 4.1 and 4.2 make
sure of.


## 7. IANA Considerations

IANA is requested to register the following value in the "Network Time Security Key
Establishment Record Types" registry (Section 7.6 of [RFC8915]), from the range 1024–16383,
whose registration procedure is Specification Required:

| Record Type Number | Description | Reference |
|---|---|---|
| TBD | SSH Key Binding | this document |

This document creates no IANA registry. The Method IDs of Section 3.2 are maintained in this
document; new methods are added by a later version of it.


## 8. References

### 8.1. Normative References

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, March 1997.
- **[RFC4251]** Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Protocol
  Architecture", RFC 4251, January 2006.
- **[RFC4253]** Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Transport Layer
  Protocol", RFC 4253, January 2006.
- **[RFC5869]** Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation
  Function (HKDF)", RFC 5869, May 2010.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, May 2017.
- **[RFC8915]** Franke, D., Sibold, D., Teichel, K., Dansarie, M., and R. Sundblad,
  "Network Time Security for the Network Time Protocol", RFC 8915, September 2020.
- **[NTS-SSH]** Open Charging Technology, "NTS Key Establishment over SSH", white paper (draft),
  <https://github.com/OpenChargingTechnology/Whitepapers/blob/master/NTS-over-SSH/README.md>.

### 8.2. Informative References

- **[RFC4254]** Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Connection
  Protocol", RFC 4254, January 2006.
- **[RFC8126]** Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA
  Considerations Section in RFCs", BCP 26, RFC 8126, June 2017.
- **[RFC8446]** Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3",
  RFC 8446, August 2018.


## Appendix A. Test Vectors

All vectors use HKDF with SHA-256.

### A.1. The HKDF info

`info` for AES-SIV-CMAC-256 (Numeric Identifier 15), C2S key:

```
0000001e                                                          length of label (30)
4558504f525445522d6e6574776f726b2d74696d652d7365637572697479      "EXPORTER-network-time-security"
00000005                                                          length of context (5)
0000000f00                                                        NTPv4, algorithm 15, C2S
```

### A.2. Method 0x0002

```
nts_ke_secret = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

| AEAD algorithm | L | C2S key | S2C key |
|---|---|---|---|
| AES-SIV-CMAC-256 (15) | 32 | `8a9424e3fd81e14cbc9731adff3ae5b6d2fe66349b4ad384f59a1f5bd7d552ec` | `2abf8475eda5bb1798b5d3d0f2fc413d62461c0bce93707fed97366193422713` |
| AES-128-GCM-SIV (30) | 16 | `e7961cb8c44fcc3d44d091c8574ad0f2` | `964988be02f188bbc3c96bd86bba825d` |
| AES-256-GCM-SIV (31) | 32 | `5f32ede85ca7a7607baa1c2bf14057c9afb7458114e476f6a187f2f96da0aa2e` | `0b6576d8ee6e31e992f4821dac89ec44d1e575a0f1b69a4f64225dc6051ec128` |

### A.3. Method 0x0001

From `exporter_secret` on, for a key exchange method that hashes with SHA-256. The
`exporter_secret` is the `nts_ke_secret` of A.2, so the nonce is what makes the keys differ:

```
exporter_secret = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
exporter_nonce  = 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
PRK             = a27b86e7a70a029cba778d6f738d952696d6d8361b95103dd84ae9df6af063af
```

| AEAD algorithm | L | C2S key | S2C key |
|---|---|---|---|
| AES-SIV-CMAC-256 (15) | 32 | `dcf81015c16cb4b955624949e824e89f45cac437995a873e938ec3c7adc0218b` | `6b91d1a3ad1eb448fa5010e20dd79b280f7c303aec2252b464a4642fb70ea12d` |
| AES-128-GCM-SIV (30) | 16 | `fd8733d215d9d3a79f0d95b86884ed28` | `f7fe123370cdd2ed478906c34bd6d7b8` |
| AES-256-GCM-SIV (31) | 32 | `05d23579f0905080af0243173053808adad6d276ed0560a9fe64ef714b690554` | `d72234762b25d744d00016818b8f23ad65d1ac5c85009d1ada6215046c73ebcc` |


## Appendix B. Encoding Examples

`T` is the 16-bit value `0x8000 | TBD`, the record type with the Critical Bit set.

A request that prefers the SSH Exporter and also offers the Transported Secret:

```
T  0004  0001 0002
```

A response that selects the Transported Secret:

```
T  0022  0002 <nts_ke_secret, 32 octets>
```

A response that selects the SSH Exporter:

```
T  0022  0001 <exporter_nonce, 32 octets>
```


## Appendix C. Implementation Status

This appendix is informative.

- **Norn** (GraphDefined GmbH, <https://github.com/Vanaheimr/Norn>, AGPL-3.0): client and
  server. Implements method `0x0002`. Method `0x0001` is in preparation, on the SSH exporter of
  [Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod).

Before the registration, Norn used the provisional value 16386 (`0x4002`) from the Private or
Experimental Use range. Implementations of this document use only the value assigned by IANA.
