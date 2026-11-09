# NTS-KE Record Type "SSH Key Binding"

**Version 1.0 — Draft**, 2026-11-10
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

| Method ID | Name | Data in a request | Data in a response | Requirement |
|---|---|---|---|---|
| `0x0000` | Reserved | – | – | MUST NOT be sent |
| `0x0001` | SSH Exporter | none (0 octets) | `exporter_nonce` (32 octets) | OPTIONAL |
| `0x0002` | Transported Secret | none (0 octets) | `nts_ke_secret` (32 octets) | REQUIRED to implement |
| `0x0003`–`0x7FFF` | Unassigned | – | – | assigned by a later version of this document |
| `0x8000`–`0xFFFF` | Private or Experimental Use | defined by the user | defined by the user | – |

Clients and servers MUST implement method `0x0002`. Section 5 specifies the key derivation of
each method. A later method defines the data it takes from the client in a request and the
data it carries in a response.

### 3.3. In a Request

The body is a list of one or more entries, most preferred first. Each entry names a method and
carries the data the client sends for it:

```
Body  = Entry || Entry || ...
Entry = Method ID (2 octets) || Data Length (2 octets) || Method Data (Data Length octets)
```

The entries MUST fill the body exactly. The Data Length lets a receiver skip an entry whose
method it does not know. A later method can therefore take data from the client, for instance
a contribution of the client to the keying material, without a new record type. Methods
`0x0001` and `0x0002` take no data from the client: their Data Length MUST be 0.

A request over SSH MUST carry exactly one SSH Key Binding record, with at least one entry.
Since every server implements method `0x0002`, a client MUST include it in every offer; it MAY
place other methods before it, including methods the server may not know.

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
   SSH Key Binding record, whose SSH Key Binding body holds no entry, or whose entries do not
   fill the body exactly.
2. MUST skip, by their Data Length, the entries whose Method ID it does not know. They are not
   an error.
3. MUST respond with Error code 1 (Bad Request) to a request with an entry for method `0x0001`
   or `0x0002` whose Data Length is not 0.
4. MUST select the first entry of the client's list whose method it supports, and MUST respond
   with Error code 1 (Bad Request) when it supports none of them.
5. MUST generate the Method Data of the selected method, `exporter_nonce` for method `0x0001`
   and `nts_ke_secret` for method `0x0002`, anew for every exchange, from a cryptographically
   secure random number generator, and MUST NOT use it for more than one exchange.
6. MUST derive the keys it seals into the cookies of the response as specified for the
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
  the exporter secret of TLS 1.3 [RFC9846]. Both peers therefore agree on it however re-keys
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

The offer, with the data of its entries, and the selection travel inside the encrypted and
authenticated SSH channel. An on-path attacker cannot remove methods from the offer, or change
their data, without breaking SSH.

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
- **[RFC7748]** Langley, A., Hamburg, M., and S. Turner, "Elliptic Curves for Security",
  RFC 7748, January 2016.
- **[RFC8731]** Adamantiadis, A., Josefsson, S., and M. Baushke, "Secure Shell (SSH) Key
  Exchange Method Using Curve25519 and Curve448", RFC 8731, February 2020.
- **[RFC9846]** Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3",
  RFC 9846, July 2026.


## Appendix A. Test Vectors

All vectors use HKDF with SHA-256, except the last vector of A.3.1, whose key exchange method
hashes with SHA-512.

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

#### A.3.1. From the Key Exchange

The inputs are those of the first key exchange of a connection, so `session_id` equals `H`.
`K` is encoded as the key exchange method encodes it for its own key derivation (Section 5.2).
The first vector takes the shared secret of Section 6.1 of [RFC7748] as `K` of
`curve25519-sha256` [RFC8731], which encodes it as mpint. The second takes the output of
Section 5.2 of [RFC7748], whose first octet `0xc3` gives the mpint a leading zero octet. The
last two encode `K` as string, as the hybrid methods `mlkem768x25519-sha256` and
`sntrup761x25519-sha512` do; their `K` is a pattern of the length of the hash. `H` counts
upwards, as it is treated as opaque octets. The last vector hashes with SHA-512, and so do
its HKDF-Extract and HKDF-Expand.

Every vector uses the same nonce, and `info` built as in A.1:

```
string("ssh-exporter@open.charging.cloud")
  00000020 7373682d6578706f72746572406f70656e2e6368617267696e672e636c6f7564

exporter_nonce = 1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
```

```
curve25519-sha256, HASH = SHA-256, K as an mpint
  K                000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  H = session_id   202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
  exporter_secret  ab559ef9a78c59a68f7be3063df264e2a7ccbe83a49f76ed2aed1327cf89776e
  PRK              a2d98772f94b8fb96dd30707c7c9ad0d278d0ff90a411ad709ce7069b1e4781f
  AEAD 15, L = 32
    C2S  ea9163026944be623b625a50b8f59aa1daf843949e0f98634f178af6e248330a
    S2C  d9376278448d5de12b0d3ebc3c06bf26c0ccc0c85ac869b6a23d10213b7fc402
  AEAD 30, L = 16
    C2S  339eabe19ea8469bbf993ac405a89417
    S2C  26823c8acd419d57fd901749dc6d5d76

curve25519-sha256, HASH = SHA-256, K as an mpint with a leading zero octet
  K                0000002100c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
  H = session_id   a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
  exporter_secret  8cd543f0ab53001f308b027ad13bd42ff218559a5d26d025a410a806ef7b9c77
  PRK              24e54cd9033daa7bb1e5047b90a6a0f53f24e62ad9b9e743a3dfb17a159e4ffb
  AEAD 15, L = 32
    C2S  6d38e2ff8aaaab4842eb4cb3d66712d93d8675efc0cea721f3828f8de3fce947
    S2C  3a177a3612e473add6c214cbdf858b59e7012e0e68676f57692998fb5192a208

mlkem768x25519-sha256, HASH = SHA-256, K as a string
  K                00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
  H = session_id   606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
  exporter_secret  2d7dce6143d5be80605b07662a01e4735b32202106be64c66f8392dc51d887f6
  PRK              d4a0a37898cd1bf17500c5c0a6c9285d66087742df355873f912dd058fc94027
  AEAD 15, L = 32
    C2S  10f3f639e505ca255ac1a51d235bac0d0ba15b078774e0c13f7f97a15b93df05
    S2C  8a1e71fceb65e99f0d171f6472e8c9bd7f92f20ad8a5085d3bf9b1d7fec9c28f

sntrup761x25519-sha512, HASH = SHA-512, K as a string
  K                00000040
                   808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                   a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
  H = session_id   c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                   e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  exporter_secret  2d3d49427d4a01a90e66867b65064c5ae726c4ceb833aa06cf03a8a54e1f667c
                   36289f14bfd84e15d4a6793e1bbc7532f3ab4bdc68bab34b0aa471a5068ff4dd
  PRK              ac0a32957f57e5f41866387c4d8313183a6d93b8995d2c84acfe5070af261894
                   80d5dd64e36838e2ac5af9ea77c5c5d8a6d8c207f556880fe5e6e251dbc31615
  AEAD 15, L = 32
    C2S  d8df38f63a6c606738f00b416ee530c2c5b8d54881a72a73e983eac1968bf5b5
    S2C  b611446e12a524681f9fd023eee1a57468a624a3f73b0dd7c6a6d45dd2297414
  AEAD 30, L = 16
    C2S  891071d4dcddf3ec6a2074d58ebe5059
    S2C  423acfe0d50b1c0e571835f70cb4fef0
```

#### A.3.2. From exporter_secret On

For an implementation that is handed `exporter_secret` (Section 5.2), with SHA-256 and every
algorithm. The `exporter_secret` is the `nts_ke_secret` of A.2, so the nonce is what makes the
keys differ:

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

A request that prefers the SSH Exporter and also offers the Transported Secret, neither with
data:

```
T  0008  0001 0000  0002 0000
```

A request that offers a method of the private range with two octets of data first, which a
server that does not know it skips by its Data Length:

```
T  000a  8001 0002 abcd  0002 0000
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
  server. Implements both methods, `0x0001` on the SSH exporter of
  [Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod), and the request entries of
  Section 3.3; its tests check the keys of Appendix A.2 and A.3.2, and those of Hermod its
  exporter against A.3.1. A Norn client offers `0x0001` only
  where its SSH stack gives it the exporter. Behind the `ssh -s` of OpenSSH it offers `0x0002`
  alone. A Norn server selects `0x0001` only on connections of Hermod's SSH server. As of
  2026-11-09: Norn 962d4c6, Hermod 57c6add.

Before the registration, Norn used the provisional value 16386 (`0x4002`) from the Private or
Experimental Use range. Implementations of this document use only the value assigned by IANA.
