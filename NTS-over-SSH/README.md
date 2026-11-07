White Paper

# NTS Key Establishment over SSH

This white paper proposes to run the [Network Time Security Key Establishment (NTS-KE)](https://datatracker.ietf.org/doc/html/rfc8915) protocol as a [Secure Shell (SSH)](https://datatracker.ietf.org/doc/html/rfc4251) subsystem. It addresses the managed networks of Charge Point Operators (CPOs), laboratories, test sites and other private infrastructures that want authenticated time, but run no X.509 PKI of their own. The paper describes:

- **An SSH transport for NTS-KE**: the subsystem `ntske/1@open.charging.cloud` carries the unchanged NTS-KE records of RFC 8915. The NTS-protected NTP that follows is not changed at all.
- **A special-purpose SSH listener in the NTS-KE server**: it serves the subsystem to time clients and a command line to administrators, and nothing else. A local controller or a CSMS that already accepts OCPP over SSH offers the subsystem on its existing listener instead, to the same station keys.
- **Key binding without TLS**: why the SSH session identifier must not be used as key material, an SSH keying material exporter, and a simpler in-band key transport that also works behind an unmodified OpenSSH server.
- **Trust anchors without X.509**: pinned host keys, SSH certificate authorities and SSHFP records, and client authorization through SSH public keys. Pinned host keys need no correct clock at all.
- **A mapping onto the OCPP v2.x Device Model** as an extension of the *NTP Client Controller* of the [Secure Time Synchronization](../SecureTimeSync/README.md) white paper.

*Status*: this is a draft for discussion. Nothing in it is implemented yet, and the subsystem name, the record type and the device model variables are provisional.
<!--  -->
<!--  -->


## 1. Motivation

In private networks NTS rarely fails because of its cryptography, but often because of the PKI it needs. RFC 8915 requires NTS-KE to run over TLS 1.3 with a server certificate the client can validate, and this has three practical consequences:

- **No internal CA**: many operators of OT networks, private APNs, laboratories and test sites run no X.509 certificate authority of their own, and public certificates do not fit internal names and addresses.
- **The bootstrapping problem**: certificates carry a *notBefore* and a *notAfter* date. A device without a battery-backed real-time clock cannot check them after a reboot, although this is exactly the moment it needs NTS. Implementations work around this with exceptions, e.g. by skipping the time checks for the first synchronization ([RFC 8915, section 8.5](https://www.rfc-editor.org/rfc/rfc8915.html#section-8.5); `NoCertTimeCheckAfterReboot` in section 3.2.4 of the [Secure Time Synchronization](../SecureTimeSync/README.md) white paper).
- **Anonymous clients**: NTS-KE over TLS hands out cookies to anybody who asks. In managed networks operators often want to know, and to limit, which devices use their time servers.

SSH, on the other hand, is present on almost every networked device and in every operator's toolbox. An SSH host key is a bare public key without a validity period: it is pinned, signed by a lightweight SSH certificate authority, or published in the DNS. Client authentication with public keys is the normal case, not the exception.

The goal is a second transport for the same NTS-KE logic, not a replacement of RFC 8915 on the public Internet (section 4.1 of [Critical Legal Time Services](../CriticalLegalTimeServices/README.md)). It is meant for the managed networks with trust zones of section 4.2 of that paper.


## 2. Background: NTS-KE according to RFC 8915

Section 2.1 of the [Secure Time Synchronization](../SecureTimeSync/README.md) white paper describes the NTS-KE phase in detail. Five of its properties matter here:

1. **Transport**: TCP port 4460, TLS 1.3, ALPN `ntske/1`. Exactly one request and one response per TLS connection; afterwards the server closes the connection and discards all state.
2. **Records**: a 16-bit type with a *critical* bit, a 16-bit body length, and the body. Records delimit themselves and can therefore be carried over any reliable byte stream.
3. **Keys**: the client-to-server (C2S) and server-to-client (S2C) keys are taken from the TLS exporter ([RFC 9846, section 7.5](https://www.rfc-editor.org/rfc/rfc9846.html#section-7.5), formerly RFC 8446) with the label `EXPORTER-network-time-security` and a context of five octets: the protocol id `0x0000` of NTPv4, the id of the negotiated AEAD algorithm, and `0x00` for C2S or `0x01` for S2C.
4. **Cookies**: the server encrypts C2S, S2C and the AEAD algorithm id with a master key into opaque cookies. The NTP server needs this master key, but no TLS state.
5. **Decoupling**: the NTS extension fields of NTPv4 depend on cookies and keys only. Where the keys came from does not matter to the NTP server.

Property 5 is the foundation of this paper: only the channel of property 1 and the source of the keys of property 3 are replaced.


## 3. Protocol Overview

### 3.1 Subsystem Name and Versioning

The subsystem name is **`ntske/1@open.charging.cloud`**. It mirrors the ALPN token `ntske/1` and carries the version in its local part.

- **Naming rules**: according to [RFC 4251, section 6](https://datatracker.ietf.org/doc/html/rfc4251#section-6) and [RFC 4250, section 4.6.1](https://datatracker.ietf.org/doc/html/rfc4250#section-4.6.1), names without an `@` are reserved for assignment through IANA. Private extensions use the form `name@domain`, where the domain must be controlled by whoever defines the name. Names are printable US-ASCII without commas or whitespace, case-sensitive, and at most 64 characters long; a `/` is allowed, so the name keeps the ALPN token of RFC 8915 unchanged.
- **Versioning**: an incompatible successor uses `ntske/2@open.charging.cloud`. A client can request several subsystems one after another without any change on the record level.
- **Registration**: once the mechanism is to be used beyond Open Charging Cloud, the domain part is dropped, and `ntske/1` is registered in the IANA registry *Connection Protocol Subsystem Names* ([RFC 4250, section 4.9.5](https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.5)), whose policy is *Expert Review* since [RFC 9519](https://datatracker.ietf.org/doc/html/rfc9519). This needs no RFC.
- **User name**: SSH requires a user name for authentication. The convention is `ntske`. On the shared listener of a charging infrastructure node the client logs in under its own identity instead (section 8.3).

Rejected alternatives:

- **A dedicated channel type** instead of a `session` channel with a `subsystem` request would be cleaner, as no terminal, environment or shell semantics apply. Generic SSH clients and libraries, however, can request subsystems but rarely open custom channel types, and OpenSSH cannot hand custom channel types to external programs (section 8.4).
- **An `exec` request with a fixed command** works, but mixes the protocol name with a path on the server and is harder to filter.
- **Tunneling NTS-KE over TLS through SSH** (`direct-tcpip`) solves nothing: inside the tunnel a verifiable certificate is still required.


### 3.2 Message Flow

One NTS-KE exchange over SSH runs through four phases. Only phase 3 carries NTS-KE, and within it only the *SSH Key Binding* record (section 5) is new. The flow shows the primary profile of section 8.1, an NTS-KE server with an SSH listener of its own, with option A of section 4.

```mermaid
sequenceDiagram
    participant C as Client (charging station)
    participant K as NTS-KE server with SSH listener
    participant N as NTP server

    Note over C,K: 1. SSH transport
    C->>K: version string, KEXINIT (strict KEX)
    K->>C: version string, KEXINIT (strict KEX)
    C->>K: KEX_ECDH_INIT (e.g. mlkem768x25519-sha256)
    K->>C: KEX_ECDH_REPLY (host key, signature over H)
    Note over C: verify the host key against a pin or an SSH CA
    Note over C,K: both compute exporter_secret from K and H (option A)
    C->>K: NEWKEYS
    K->>C: NEWKEYS

    Note over C,K: 2. Authentication and channel
    C->>K: USERAUTH_REQUEST publickey, user "ntske"
    K->>C: USERAUTH_SUCCESS
    C->>K: CHANNEL_OPEN "session"
    K->>C: CHANNEL_OPEN_CONFIRMATION
    C->>K: CHANNEL_REQUEST "subsystem" ntske/1@open.charging.cloud
    K->>C: CHANNEL_SUCCESS

    Note over C,K: 3. NTS-KE inside the subsystem
    C->>K: Next Protocol, AEAD, SSH Key Binding (0x0001, 0x0002), End of Message
    Note over K: derive C2S/S2C from the SSH exporter, encrypt the cookies
    K->>C: Next Protocol, AEAD, SSH Key Binding (0x0001), 8 × New Cookie, End of Message
    Note over C: derive C2S/S2C from the SSH exporter
    K->>C: CHANNEL_EOF, CHANNEL_CLOSE

    Note over C,N: 4. NTS-protected NTP, unchanged (UDP port 123)
    C->>N: NTPv4 request with NTS extension fields
    N->>C: NTPv4 response with NTS extension fields and a new cookie
```

- **Framing**: the records travel as `SSH_MSG_CHANNEL_DATA` in the byte stream of the channel. Their length fields delimit them just as over TLS; no additional framing is needed.
- **Closing**: after the *End of Message* record the server sends `SSH_MSG_CHANNEL_EOF` and `SSH_MSG_CHANNEL_CLOSE`, and the client disconnects.
- **Errors**: when the server refuses the subsystem (`SSH_MSG_CHANNEL_FAILURE`), the client gives up. It never falls back silently to another transport.
- **Option B**: the server answers with method `0x0002` and a fresh `nts_ke_secret`, from which both peers derive the keys instead. Behind an unmodified OpenSSH server (section 8.4), and for clients whose SSH library does not expose K and H, this is the only option.
- **Latency**: roughly 7 to 9 round trips instead of about 3 for TCP, TLS 1.3 and NTS-KE, and about 3 as a further channel of an existing connection (section 8.3). NTS-KE runs only after a start, when cookies run out, and about once a day (`MinRefresh` and `MaxRefresh` in the Secure Time Synchronization white paper), so the additional cost is negligible.


## 4. Key Binding

An SSH keying material exporter can be defined cleanly, but the security of NTS-KE over SSH does not depend on it. Both options below end in the same key derivation function; only its input secret differs.


### 4.1 Why RFC 8915 Uses an Exporter

The TLS exporter yields C2S and S2C without sending any key over the wire. Both peers contribute to the result through the (EC)DH exchange, and the keys are bound to exactly this TLS connection.

Channel binding in the strict sense protects against a relaying attacker when authentication and the channel live in different layers. With NTS-KE both live in TLS. There the exporter is an elegant design, but not the only line of defence.


### 4.2 Why the SSH Session Identifier Is Not Key Material

SSH offers a natural candidate: the session identifier, i.e. the exchange hash H of the first key exchange. It is signed in public key user authentication, it is used by the `session-bind@openssh.com` extension of the OpenSSH agent protocol, and an expired draft from 2007 proposed it as *the* channel binding of SSH ([draft-williams-sshv2-channel-bindings](https://datatracker.ietf.org/doc/html/draft-williams-sshv2-channel-bindings-00)).

A channel binding value, however, is not a secret. The session identifier is handed to the SSH agent, possibly via agent forwarding to other hosts, and it shows up in debug output. A key derived from it alone would be only as secret as its least careful holder. **The session identifier must never be the only input of key material.**


### 4.3 Option A: SSH Keying Material Exporter

The secret known only to both endpoints is the shared secret K of the key exchange. An exporter must therefore depend on K, just like the key derivation of [RFC 4253, section 7.2](https://datatracker.ietf.org/doc/html/rfc4253#section-7.2):

```text
exporter_secret = HASH( K || H || string("ssh-exporter@open.charging.cloud") || session_id )

SSH-Exporter(label, context, L) =
    HKDF-Expand( PRK  = exporter_secret,
                 info = string(label) || string(context),
                 L    = L )                    # HMAC with HASH
```

- **Encoding**: K and H exactly as encoded by the key derivation of the negotiated key exchange method: `mpint` for the classical methods, e.g. `curve25519-sha256` ([RFC 8731](https://datatracker.ietf.org/doc/html/rfc8731)), and `string` for the hybrid post-quantum ones, e.g. `mlkem768x25519-sha256` ([RFC 10042](https://datatracker.ietf.org/doc/html/rfc10042)). HASH is the hash function of the key exchange method, `string()` the SSH encoding with a 32-bit length prefix, and HKDF-Expand the one of [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
- **Time of computation**: once, during the first key exchange, together with the keys "A" to "F" of RFC 4253. K may be erased afterwards as usual. Re-keying does not change the exporter, just as `KeyUpdate` does not change the exporter of TLS 1.3.
- **A string label instead of a letter**: keeps the letters after "F" free for future use and separates the domains unambiguously.
- **Use for NTS**: C2S = `SSH-Exporter("EXPORTER-network-time-security", 0x0000 || AEAD id || 0x00, key length)`, and S2C likewise with `0x01`. Always with the context of RFC 8915, section 5.1: record type 1024 (*Compliant AES-128-GCM-SIV Exporter Context*), which works around a deployed deviation in TLS-based implementations, has no meaning over SSH.
- **Once per connection**: the exporter is constant for an SSH connection. Two NTS-KE exchanges over the same connection, e.g. through the connection multiplexing of OpenSSH (`ControlMaster`), would derive identical keys. With option A the server therefore refuses every further subsystem request for this name on the same connection, just as RFC 8915 allows one exchange per TLS connection. This matters most for long-lived connections that carry other subsystems as well, e.g. OCPP (section 8.3).
- **Cost**: the SSH implementation must hand the value to the application. An NTS-KE server with an SSH listener of its own (section 8.1), like a node with a shared listener (section 8.3), holds K and H anyway, so the exporter is a small addition to its key exchange. OpenSSH would need a patch that passes the value from the SSH session process to the subsystem process.


### 4.4 Option B: In-Band Key Transport

For every exchange the server generates a fresh 32-byte secret `nts_ke_secret` and sends it in the *SSH Key Binding* record of section 5. Both peers derive the keys from it with the same function:

```text
NTS-Exporter(label, context, L) =
    HKDF-Expand-SHA256( PRK  = nts_ke_secret,
                        info = string(label) || string(context),
                        L    = L )
```

Label and context are those of RFC 8915. Option B is thus option A with another PRK, and an implementation needs a single function `Exporter(label, context, L)` with three interchangeable sources: TLS, the SSH exporter, and the transported secret.

**Security argument**: the secret travels in the same SSH channel whose endpoint the client has authenticated through its host key. Whoever can read the secret can also read and forge the records and cookies, and has therefore broken SSH itself. Then option A fails as well. The gap between layers that channel binding protects against does not exist here.

**Drawbacks**: the secret is visible in plain text on the local pipe between the SSH server and the subsystem process, i.e. within the same trust domain. The keys depend on the random number generator of the server only, which generates the cookies anyway and loses nothing.


### 4.5 Comparison and Recommendation

| Criterion                              | A: SSH exporter               | B: In-band transport              |
|----------------------------------------|-------------------------------|-----------------------------------|
| Keys on the wire                       | never                         | encrypted inside the SSH channel  |
| Contribution of both peers             | yes, through K                | no, server randomness only        |
| Binding to the SSH connection          | cryptographic                 | implicit, through the channel     |
| NTS-KE server with SSH listener        | small addition to the KEX     | no change                         |
| Unmodified OpenSSH server              | no, needs a patch             | yes                               |
| Off-the-shelf SSH client library       | rarely exposes K and H        | yes                               |
| Several exchanges per connection       | forbidden                     | allowed                           |
| Key binding record in the response     | 6 bytes, without data         | 38 bytes, with the secret         |
| New specifications                     | SSH exporter and record       | record only                       |

**Recommendation**: option A is preferred wherever both ends terminate SSH themselves, as the NTS-KE server with an SSH listener of section 8.1 and a client on the same SSH stack do. Option B is mandatory to implement nevertheless: it is the common ground for clients with off-the-shelf SSH libraries and for servers behind an unmodified OpenSSH server, and the only option on a long-lived connection that is shared with other subsystems (section 8.3). The record of section 5 negotiates between both. The SSH exporter itself should be specified independently of NTS, as it would be useful for other protocols over SSH as well.


## 5. The SSH Key Binding Record

A single new NTS-KE record negotiates the source of the keys and carries the secret of option B. All other records remain as defined by RFC 8915.

| Field                | Value |
|----------------------|-------|
| Name                 | SSH Key Binding |
| Record type          | 16386 (provisional), from the *Private or Experimental Use* range 16384 … 32767 of the [NTS-KE record type registry](https://www.rfc-editor.org/rfc/rfc8915.html#section-7.6) |
| Critical bit         | set; the subsystem name implies that the server knows the record |
| Body of the request  | a list of 16-bit method ids, in order of preference |
| Body of the response | one 16-bit method id, followed by method-specific data |
| Method `0x0001`      | Exporter (option A), no data |
| Method `0x0002`      | Transport (option B), 32 bytes `nts_ke_secret` |

- The client sends exactly one such record and must offer `0x0002` (mandatory to implement).
- The server answers with exactly one such record and selects the first method of the list it supports. When the record is missing or no method fits, the server answers with the *Error* record *Bad Request*.
- Over TLS on port 4460 the record does not occur. A server according to RFC 8915 refuses it, as it is critical, with *Unrecognized Critical Record*.
- Values of the private range are not coordinated; 16384 and 16385 are already in experimental use elsewhere. A coordinated value is a type from the *Specification Required* range 1024 … 16383. It needs a stable, public specification and the approval of the designated experts, but no RFC.

Example: the client could use the exporter, but the server runs behind an unmodified OpenSSH server and selects the transport.

```text
Client → Server
  NTS Next Protocol Negotiation  [C]  0x0000 (NTPv4)
  AEAD Algorithm Negotiation          15, 30
  SSH Key Binding                [C]  0x0001, 0x0002
  End of Message                 [C]

Server → Client
  NTS Next Protocol Negotiation  [C]  0x0000
  AEAD Algorithm Negotiation          15
  SSH Key Binding                [C]  0x0002 || nts_ke_secret (32 bytes)
  New Cookie for NTPv4                × 8
  End of Message                 [C]
```


## 6. Authentication and Trust Anchors

The security of the whole mechanism stands and falls with the verification of the server's host key. A client must never accept an unknown host key silently.


### 6.1 Server Authentication

| Mechanism               | Trust anchor | Needs a correct clock | Suitable for |
|-------------------------|--------------|-----------------------|--------------|
| Pinned host key         | fingerprint in the client configuration, e.g. `SSHHostKeyPins` (section 7) | no | few servers, devices without a real-time clock |
| SSH host certificate    | one CA key (`@cert-authority`), signed with `ssh-keygen -s` | only with a limited validity; `-V always:forever` is possible | many servers, key rotation without touching the clients |
| SSHFP record in the DNS | DNSSEC ([RFC 4255](https://datatracker.ietf.org/doc/html/rfc4255), [RFC 6594](https://datatracker.ietf.org/doc/html/rfc6594), [RFC 7479](https://datatracker.ietf.org/doc/html/rfc7479)) | yes, for the validity of the RRSIG records | networks with a DNSSEC infrastructure |
| Trust on first use      | the first contact | no | laboratories only, never in operation |

For devices without a battery-backed real-time clock, the pinned host key and the host certificate without an expiry date are the only mechanisms without a bootstrapping problem. SSH certificates with a limited validity raise the same question as X.509 certificates.


### 6.2 Client Authentication and Authorization

- **`none`** ([RFC 4252, section 5.2](https://datatracker.ietf.org/doc/html/rfc4252#section-5.2)): for a public service on the SSH listener of section 8.1. This corresponds to anonymous NTS-KE over TLS; OpenSSH offers no clean way to configure it.
- **`publickey`**: the normal case in managed networks. Every client has a key pair of its own, and the server lists the public keys in the `authorized_keys` file of the account `ntske`. Access is withdrawn by deleting one line.
- **The OCPP key of a charging station**: on the shared listener of a charging infrastructure node (section 8.3) the key a station already uses for OCPP over SSH authorizes NTS-KE as well, once the subsystem is granted to the station.
- **SSH user certificates**: one CA line instead of many keys for large fleets, with revocation through a key revocation list (KRL).

What the client identity brings:

- Cookies are only handed out after a successful authentication. The cookies themselves remain anonymous, and the NTP server notices no difference.
- The NTS-KE server may name different NTP servers in the *NTPv4 Server Negotiation* record per client or group of clients. Over TLS it knows little more than the source address, which says little behind NAT or a private APN; over SSH it knows the identity. This serves:
  - **Reachability**: a charging station behind a local controller often reaches only the NTP server of that controller (section 8.3), a backend system the central one.
  - **Classes of time sources**: devices whose clock matters under legal metrology get the traceable servers of the legal time ([Critical Legal Time Services](../CriticalLegalTimeServices/README.md)), all others a general pool, which spares the scarce servers.
  - **Separation of tenants**: an operator serving several CPOs gives each of them NTP servers of its own with a cookie master key of its own, and the NTS-KE server keeps one master key per group. A compromised NTP server can then read the cookies of its own group only.
  - **Gradual migration**: one group of devices moves to a new NTP server first, the others later.
- Towards passive observers the unlinkability of cookies of RFC 8915 is preserved. The operator itself can now attribute the cookies it hands out to an identity instead of an IP address only, which is usually intended in managed networks.


## 7. Mapping onto the OCPP v2.x Device Model (Proposal)

The NTP Client Controller of section 3.2.4 of the [Secure Time Synchronization](../SecureTimeSync/README.md) white paper gets a fourth value of its variable `Mode`: `NTSv4SSH`. In this mode `ServerURL` names the SSH server that offers the NTS-KE subsystem. `NTSKEServerPort`, `RootCAs`, `CertificatePins`, `RootPins`, `NoCertTimeCheckAfterReboot` and `CertificateFingerprint` do not apply, and the following variables are added:

| Variable Name         | req/opt  | Mutability | Data Type | Default Value | Values List / Limits  | Description |
|-----------------------|----------|------------|-----------|---------------|-----------------------|-------------|
| SSHPort               | optional | rw         | integer   | 22            | 1 … 65535             | The SSH port of the NTS-KE server in mode *NTSv4SSH*. |
| SSHUserName           | optional | rw         | string    | `ntske`       | ≤ 32 characters       | The user name of the SSH user authentication. |
| SSHHostKeyPins        | optional | rw         | string    | ""            | comma separated, ≤ 16 | SHA-256 fingerprints of the host keys the server may show, in the notation `SHA256:<base64>` of `ssh-keygen -l`. |
| SSHHostCAs            | optional | rw         | string    | ""            | comma separated, ≤ 4  | SHA-256 fingerprints of the SSH CA keys that may sign the host certificate of the server. |
| SSHUseOCPPConnection  | optional | rw         | boolean   | false         | -                     | Open the subsystem as a channel of the SSH connection of OCPP (section 8.3). `SSHPort`, `SSHUserName`, `SSHHostKeyPins` and `SSHHostCAs` then do not apply, and `ServerURL` names the peer of that connection. Only option B is offered. |
| SSHClientPublicKey    | optional | ro         | string    | ""            | -                     | The public key the charging station authenticates with, in the `authorized_keys` format of OpenSSH. |
| SSHHostKeyFingerprint | optional | ro         | string    | ""            | -                     | The SHA-256 fingerprint of the host key the server showed at its last NTS-KE handshake. |

- **Client keys**: the charging station generates its Ed25519 key pair itself, and the private key never leaves the device. The CSMS reads `SSHClientPublicKey` and enters it into the `authorized_keys` of the NTS-KE server, or has it signed by the operator's SSH user CA.
- **Pins**: `OnPinMismatch` applies to `SSHHostKeyPins` and `SSHHostCAs` as it does to certificate pins. Whether `TrustOnFirstUse` needs a value `HostKey` of its own is open.
- **Fingerprints**: unlike the certificate pins of the Secure Time Synchronization white paper, which hash the whole certificate, an SSH fingerprint is the SHA-256 hash of the public key alone.
- **OCPP over SSH**: with `SSHUseOCPPConnection` the charging station needs no key pair, pin or account of its own for time. It uses those of its OCPP connection, and `SSHClientPublicKey` is its OCPP key. While that connection does not run over SSH, or is down, the client cannot reach its NTS-KE server and handles this like any unreachable server. The cookies it holds keep NTP running in the meantime.


## 8. Deployment Profiles

The primary profile is an NTS-KE server with an SSH listener of its own, which serves time clients and administrators alike. A charging infrastructure node that already runs an SSH listener, e.g. for OCPP over SSH, offers the subsystem next to its other ones. An unmodified OpenSSH server with a small helper program remains possible as an alternative.


### 8.1 NTS-KE Server with an SSH Listener of Its Own

The existing NTS-KE server gets a second listener next to TLS on port 4460. It is a special-purpose SSH server, not a general-purpose one, and offers exactly two things:

- the subsystem `ntske/1@open.charging.cloud` to time clients, and
- a command line to administrators (section 8.2).

Everything else a general-purpose SSH server offers is refused: no operating system shell, no `exec` requests, no SFTP, no port, agent or X11 forwarding.

- **Both options of section 4**: the SSH stack holds K and H anyway, so the SSH exporter of option A is a small addition to its key exchange. Option B works as well.
- **One configuration, one process**: the TLS and the SSH front end share the NTS-KE core, the cookie master key and the list of NTP servers to announce. There are no system accounts, no `sshd_config` and no helper program to maintain.
- **Key management of its own**: the server keeps the authorized client keys and the SSH CAs itself, and may receive them from the CSMS, e.g. the `SSHClientPublicKey` of section 7.
- **Public services**: the authentication method `none` can be offered where anonymous NTS-KE is intended.
- **Attack surface**: the SSH stack runs in the same process as the cookie master key, so a flaw in the SSH implementation can expose the master key. This calls for a mature SSH implementation that is tested against independent implementations and fuzzed, and for the usual rotation of the master key.

*Reference implementation (planned)*: the NTS server of [Vanaheimr Norn](https://github.com/Vanaheimr/Norn), which serves NTS-KE over TLS and NTP today, and the SSH stack of [Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod/tree/master/Hermod/SSH), which implements client and server once for both roles, including hybrid post-quantum key exchange, OpenSSH certificates and SSHFP. Its interoperability with independent SSH implementations is tested by the [SSH Conformance Tests](https://github.com/Vanaheimr/SSHConformanceTests). The work is planned in this order:

1. Norn derives C2S and S2C through the single function `Exporter(label, context, L)` of section 4.4, with the three sources TLS, SSH exporter and transported secret.
2. Norn parses and writes the *SSH Key Binding* record of section 5.
3. The NTS server of Norn gets the SSH listener of this section with the subsystem `ntske/1@open.charging.cloud`, with option B only at first.
4. Hermod adds the SSH exporter of section 4.3 to its key exchange, which enables option A.
5. The command line of section 8.2 joins the same listener, with separate accounts for time clients and administrators.
6. The nodes of Open Charging Cloud offer the subsystem on their shared listener (section 8.3). [WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node) already adds subsystems to that listener at run time and tells their handlers the authenticated identity of the client, which is enough for option B. Option A additionally needs the exporter of the connection from Hermod.


### 8.2 Administration over the Same Listener

An administrator who opens a secure shell to the NTS-KE server gets the server's own command line instead of an operating system shell, in the same way as other command line programs of Open Charging Cloud already offer theirs over SSH. Typical commands:

- **Status**: the clients served, the cookies handed out, the last handshakes, and the state of the NTP servers announced.
- **Client keys**: list, add and revoke authorized client keys, and the SSH CAs for client certificates.
- **Keys of the server**: rotate the cookie master key and the host key, and show the host key fingerprint for pinning.
- **Announcements**: which NTP servers and ports are named to which clients or groups of clients.

Access rules:

- **Separation by account**: client accounts get the subsystem only, administrator accounts the command line only. A client key never opens the command line.
- **Restricted reachability**: the command line is offered only on a management network, or on a port of its own that is filtered accordingly.
- **Strong authentication**: public keys, preferably hardware-backed, and optionally a second factor such as [time-based one-time passwords](../TimeBasedOneTimePasswords/README.md).
- **Evidence**: every change of the time configuration is logged together with the administrator who made it, in the same spirit as section 4.2 of [Critical Legal Time Services](../CriticalLegalTimeServices/README.md) records every change of the legal time configuration of a charging station.


### 8.3 Subsystem on the Shared SSH Listener of a Charging Infrastructure Node

A local controller or a CSMS often runs an SSH listener anyway: for its command line, for SFTP, and for OCPP itself when charging stations connect to `ssh://` instead of `wss://`. Each station then pins the host key of the node, and the node knows the public key of each station. This removes certificates from the station network for OCPP in the same way as this paper does for time. Open Charging Cloud carries OCPP and its own node protocol WWCP over SSH as the subsystems `ocpp@open.charging.cloud` and `wwcp@open.charging.cloud`. Such a node offers NTS-KE as one more subsystem of the same listener:

```text
SSH listener of a local controller (one port, one host key)
 ├─ shell                        administrators: the command line of the node
 ├─ sftp                         administrators
 ├─ ocpp@open.charging.cloud     charging stations
 ├─ wwcp@open.charging.cloud     neighbouring nodes
 └─ ntske/1@open.charging.cloud  charging stations and other time clients
```

- **One identity, one trust anchor**: the station authenticates with the key pair it already uses for OCPP, under its own login name, and verifies the host key it already pins for OCPP. There is no second key pair, no second pin and no account `ntske`.
- **Authorization per subsystem**: the login of a station is restricted to the subsystems it may use, e.g. `ocpp@…` and `ntske/1@…`, without shell, `exec`, SFTP or forwarding. NTS-KE is granted explicitly like any other subsystem, so that a key admitted for OCPP does not obtain cookies by itself, and vice versa. Rules by source network, or by the local address a connection arrived at, apply to NTS-KE as to the other subsystems.
- **A channel of the existing connection**: a station connected for OCPP opens NTS-KE as a further channel of the same connection. Key exchange and authentication are skipped, and an exchange costs the channel request, the subsystem request and the records, i.e. about 3 round trips instead of 7 to 9 (section 3.2). A short connection of its own with the same key remains possible.
- **Option A and long-lived connections**: an OCPP connection over SSH lasts days or weeks, while the exporter of option A is constant per connection (section 4.3). Only the first exchange of such a connection could use option A; every later one, e.g. when the cookies run out, would derive identical keys and is refused. On a shared connection the client therefore offers option B only, and uses option A on a short connection of its own.
- **Time server of the station network**: a local controller between the station network and its uplink is a natural time server for its stations. It synchronizes upstream itself, e.g. with NTS over TLS (section 4.1 of [Critical Legal Time Services](../CriticalLegalTimeServices/README.md)), runs the NTP server of the station network, and names itself in the *NTPv4 Server Negotiation* record. The stations then need neither a route to an external time server nor a certificate.
- **Administration**: the commands of section 8.2 become part of the command line of the node, under its existing accounts and permissions.
- **Attack surface**: the cookie master key now shares a process with OCPP, the command line, SFTP and the logins of all stations, which is more than in section 8.1. Where this is not acceptable, the node relays the records over a local socket to a separate NTS-KE server, as the helper program of section 8.4 does, and the master key stays there. Option A is then only possible if the node passes the exporter secret of the connection along with the records.
- **Limits**: NTS-KE on an existing connection adds no handshake load. Connection limits of the listener are kept separately for stations and administrators, so that a station network cannot lock out its administrators (section 9).

A subsystem handler for NTS-KE needs three things from the SSH stack of the node: the authenticated identity of the client, the SSH exporter of the connection for option A, and state per connection to refuse a second exchange with option A.


### 8.4 OpenSSH Subsystem (Alternative)

Operators who prefer to keep an unmodified OpenSSH server can run NTS-KE as an external subsystem. The SSH server takes care of the transport, the host key and the client authentication. A small helper program reads records from stdin, writes records to stdout, and relays both over a local socket to the NTS-KE server. The NTS-KE server generates `nts_ke_secret` and the cookies there; the master key never leaves it. Only option B is possible.

```text
# /etc/ssh/sshd_config (sketch)
Subsystem ntske/1@open.charging.cloud /usr/lib/ntske/ntske-ssh-helper

Match User ntske
    AuthenticationMethods       publickey
    ForceCommand                /usr/lib/ntske/ntske-ssh-helper
    PermitTTY                   no
    AllowTcpForwarding          no
    AllowStreamLocalForwarding  no
    X11Forwarding               no
    AllowAgentForwarding        no
    PermitUserRC                no
```

- **The account `ntske`**: OpenSSH starts external subsystems through the login shell of the account. The shell must therefore not be `nologin`; `ForceCommand` still prevents any use of the shell.
- **`ForceCommand` and subsystems**: `ForceCommand` applies to subsystem requests as well, but only to names defined by a `Subsystem` line; other names fail before. `SSH_ORIGINAL_COMMAND` then holds the command configured for the subsystem, not the subsystem name. A shell request leaves it unset, so the helper can at least refuse those.
- **`authorized_keys`**: additionally with the option `restrict` for every key, or a `@cert-authority` line for user certificates.
- **Port**: port 22 can be shared with administrative access to the host. A separate SSH server instance with a port and a host key of its own is cleaner, and keeps the load of NTS-KE away from administration.
- **Limit**: option A is not possible here, as the SSH server hands no exporter secret to subsystems.


### 8.5 Clients

A client needs an SSH library with support for subsystems and host key pinning, and for option A access to K and H. A client on the same SSH stack as the server of section 8.1 has both. Clients with off-the-shelf SSH libraries use option B. A charging station that already runs OCPP over SSH (section 8.3) has subsystems and pinning in place, and needs only the NTS-KE records and option B. For tests, `ssh -s` is sufficient to request the subsystem and to pass binary records through.


## 9. Security Considerations

The SSH profile is as secure as the verification of the host key and the negotiated SSH algorithms.

- **Host key verification**: mandatory, against a configured trust anchor: a pin, an SSH CA, or SSHFP with DNSSEC. No trust on first use in operation, and no fallback to an unauthenticated connection.
- **Terrapin ([CVE-2023-48795](https://terrapin-attack.com))**: the prefix truncation attack on `chacha20-poly1305@openssh.com` and on CBC ciphers with Encrypt-then-MAC is prevented by *strict KEX* (`kex-strict-c-v00@openssh.com` and `kex-strict-s-v00@openssh.com`, [draft-ietf-sshm-strict-kex](https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/), OpenSSH 9.6 and later). The profile requires strict KEX; when the server does not signal it, the client aborts.
- **Algorithms**: the key exchange prefers `mlkem768x25519-sha256` (the default of OpenSSH since 10.0) or `sntrup761x25519-sha512`, otherwise `curve25519-sha256`. Host keys are `ssh-ed25519` or `ecdsa-sha2-nistp256`. No `ssh-rsa` with SHA-1 and no SHA-1 based key exchange. Further requirements belong in the upcoming [Secure SSH Configuration](../SecureSSHConfiguration/README.md) white paper.
- **Post-quantum**: a hybrid key exchange only protects the confidentiality of old C2S and S2C keys. A recording decrypted years later allows no retroactive attack on a time synchronization long past. It is desirable, but not critical.
- **Uniqueness**: with option A exactly one NTS-KE exchange per SSH connection, as otherwise identical keys are derived. Option B generates a fresh secret for every exchange. On long-lived connections that carry other subsystems as well, clients therefore use option B (section 8.3).
- **Downgrade**: the SSH transport is configured explicitly per server, not negotiated automatically between TLS and SSH. The choice of method in the *SSH Key Binding* record is protected by the integrity of the channel, and even the weaker choice B remains secure.
- **Process isolation**: with the SSH listener of section 8.1 the SSH stack and the cookie master key share a process, and the master key is only as safe as the SSH implementation. In the OpenSSH profile of section 8.4 the helper program runs as the unprivileged user `ntske` and only relays records; whoever takes it over obtains cookies for sessions of their own, but not the master key. On the shared listener of section 8.3 the master key additionally shares its process with OCPP, the command line and the logins of all stations, unless the node relays the records to a separate NTS-KE server.
- **Administrative access**: an administrator key can change the time configuration of a whole network and is the most valuable key of the system. Separation by account, restricted reachability, strong authentication and logging (section 8.2) are therefore mandatory, not optional.
- **Authorization per subsystem**: on a shared listener (section 8.3) a key admitted for one subsystem must not reach another. NTS-KE is granted to each station explicitly, like OCPP, and a station login never opens a shell, `exec`, SFTP or forwarding.
- **Denial of service**: an SSH handshake costs the server about as much as a TLS handshake. OpenSSH limits it with `MaxStartups`, `LoginGraceTime` and `PerSourcePenalties` (since 9.8); the SSH listeners of sections 8.1 and 8.3 need equivalent limits, separately for time clients and administrators.
- **Forwarding**: the SSH listener of section 8.1 offers no agent, port or X11 forwarding at all, and a station login on the shared listener of section 8.3 gets none either; in the OpenSSH profile they are disabled for the account `ntske`. The session identifier thus reaches no foreign agent.


## 10. Alternatives without SSH

The problem of a missing internal PKI can partly be solved within TLS as well, and interoperably. The SSH transport must be measured against this.

| Approach                                    | Without CA | Without correct clock    | Client authentication usual | Interoperable today | Remarks |
|---------------------------------------------|------------|--------------------------|-----------------------------|---------------------|---------|
| NTS-KE over SSH (this paper)                | yes        | yes                      | yes                         | no                  | uses existing SSH tooling |
| TLS with a pinned self-signed certificate   | yes        | only with an exception   | no                          | yes                 | `CertificatePins`, `TrustOnFirstUse`, `NoCertTimeCheckAfterReboot` of Secure Time Synchronization; chrony: `ntstrustedcerts`, `nocerttimecheck` |
| TLS 1.3 with raw public keys ([RFC 7250](https://datatracker.ietf.org/doc/html/rfc7250)) | yes | yes        | possible                    | hardly              | hardly supported by NTS implementations |
| TLS with DANE-EE ([RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698)) | yes | no, RRSIG validity | no                       | hardly              | requires DNSSEC |
| TLS 1.3 with an external pre-shared key     | yes        | yes                      | implicit                    | no                  | symmetric keys, scales poorly |

- Whoever only needs **interoperable NTS without a CA** gets there fastest with a pinned self-signed certificate, as already described by the Secure Time Synchronization white paper.
- **NTS-KE over SSH** pays off where SSH key management already exists, where client authorization is wanted, and where devices without a real-time clock must start cleanly.
- Both approaches do not exclude each other. They share the same NTS-KE core and differ in the front end only.


## 11. Relation to Other White Papers

- [Secure Time Synchronization for OCPP](../SecureTimeSync/README.md): defines the NTS-KE and NTP phases used here (section 2), and the NTP Client Controller that section 7 extends by the mode `NTSv4SSH`.
- [Critical Legal Time Services](../CriticalLegalTimeServices/README.md): the managed networks with trust zones of its section 4.2 are the environment this paper is written for.
- [Secure Name Resolution for OCPP](../SecureDNS/README.md): pins, `OnPinMismatch` and trust on first use mean the same here. SSHFP records are only as trustworthy as the DNSSEC validation of the name resolution.
- [Secure SSH Configuration](../SecureSSHConfiguration/README.md) (upcoming): the hardening of the SSH servers and clients of this paper.


## References

- [RFC 8915: Network Time Security for the Network Time Protocol](https://datatracker.ietf.org/doc/html/rfc8915)
- [RFC 4251: The Secure Shell (SSH) Protocol Architecture](https://datatracker.ietf.org/doc/html/rfc4251)
- [RFC 4252: The Secure Shell (SSH) Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc4252)
- [RFC 4253: The Secure Shell (SSH) Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253)
- [RFC 4254: The Secure Shell (SSH) Connection Protocol](https://datatracker.ietf.org/doc/html/rfc4254)
- [RFC 4250: The Secure Shell (SSH) Protocol Assigned Numbers](https://datatracker.ietf.org/doc/html/rfc4250)
- [RFC 9519: Update to the IANA SSH Protocol Parameters Registry Requirements](https://datatracker.ietf.org/doc/html/rfc9519)
- [RFC 8731: Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448](https://datatracker.ietf.org/doc/html/rfc8731)
- [RFC 10042: Post-Quantum/Traditional Hybrid Key Exchange with the Module-Lattice-Based Key-Encapsulation Mechanism for Use in SSH](https://datatracker.ietf.org/doc/html/rfc10042)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)
- [RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc9846) (obsoletes RFC 8446)
- [draft-williams-sshv2-channel-bindings-00: Channel Binding Identifiers for Secure Shell Channel](https://datatracker.ietf.org/doc/html/draft-williams-sshv2-channel-bindings-00) (expired)
- [draft-ietf-sshm-strict-kex](https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/) (strict KEX, work in progress)
- [Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation](https://terrapin-attack.com)


## ToDo's

- The command set of the administrative command line of section 8.2, and how its accounts are separated from those of time clients.
- Whether the SSH stack and the cookie master key of section 8.1 should run in separate processes, as OpenSSH separates privileges.
- Test the OpenSSH profile of section 8.4 end to end.
- Configuration keys for OCPP v1.6+SE, in line with section 3.3 of the Secure Time Synchronization white paper.
- Key rotation for `SSHClientPublicKey`, and security events for host key mismatches.
- Test vectors for both options of section 4.
- Specify the SSH exporter of section 4.3 as an Internet-Draft of its own in the SSHM working group, independent of NTS. It is useful beyond NTS, and as cryptography of its own it needs an outside review most.
- Discovery: whether a client may learn from the DNS that a server offers NTS-KE over SSH, and on which port.
- Relation to the upcoming [NTS-over-OCPP](../NTS-over-OCPP/README.md) white paper.
- OCPP over SSH itself, which section 8.3 builds on, as a white paper of its own.
- Whether a variant of option A that mixes fresh values of both peers into the exporter would allow repeated exchanges on long-lived connections (section 8.3).
- Whether any scenario justifies a contribution of the client to the secret of option B, which adds nothing against outsiders (section 4.4).
- How the policies per client of section 6.2 are configured: groups of SSH identities, the NTP servers and cookie master keys of each group, and the commands of section 8.2 for them.
- The path to standardization of the subsystem and the record: an Internet-Draft in the NTP working group; a specification of our own with IANA registrations only, i.e. the subsystem name through *Expert Review* (section 3.1) and the record type through *Specification Required* (section 5), neither of which needs an RFC; or the private name and record type alone. Proposed: a specification of our own first, with an early registration of the record type.
