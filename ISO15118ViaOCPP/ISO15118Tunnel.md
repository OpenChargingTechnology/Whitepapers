# The ISO 15118 Tunnel

*Remote packet capture and frame injection for ISO 15118 SLAC, SDP and V2G TLS via OCPP*

An OCPP CSMS today is blind below the application layer of ISO 15118. It learns that a charging session did not start, but not why. The three layers that decide whether a session starts at all — SLAC on the Control Pilot, SECC Discovery on IPv6 link-local multicast, and the V2G TLS handshake — leave no trace in any OCPP message. When a vehicle fails to charge at a station 400 km away, the state of the art is to send an engineer with a laptop, a Green PHY sniffer and a cable, and hope the failure reproduces while they are standing there.

This paper describes how a charging station can capture these layers the way Wireshark does, forward them to the CSMS over the existing OCPP connection, and — in the other direction — accept frames from the CSMS and put them on a real network interface, so that behaviour such as SDP multicast handling can be tested remotely against the station's own SECC.

Two questions carry most of the weight:

- **Transport** (chapters 5–9): OCPP 2.1's new `SEND` message type is the deployable answer, binary WebSocket frames are the efficient answer, and HTTP/2 and HTTP/3 are the *correct* answer, because they are the only ones that stop a 4 MB capture dump from delaying a `RequestStartTransaction`.
- **The reverse path** (chapter 10): remote raw-frame injection into critical infrastructure is a weapon before it is a diagnostic tool. The constraints come first, the API second.

This paper is the packet-level counterpart to the controller proposals in [ISO 15118 via OCPP](README.md). That document retains the existing `ISO15118Ctrlr` as the umbrella controller and proposes `SLACCtrlr`, `SDPCtrlr`, `V2GTLSCtrlr`, `V2GEXICtrlr`, and `V2GPKICtrlr` for the currently unmanaged layers. This paper is about obtaining the evidence that the resulting configuration is actually being enforced.


## 1. Motivation

### 1.1 The blind spot below OCPP

OCPP 2.1 manages ISO 15118 as a set of use cases and device-model knobs: Plug & Charge authorization, certificate installation, smart charging schedules, bidirectional power transfer. Every one of them presumes that an EV and an SECC have already found each other and built a secure channel. The machinery that gets them there is invisible:

| Layer | Runs on | Visible in OCPP 2.1 |
|---|---|---|
| SLAC / HomePlug Green PHY | Control Pilot, layer 2, no IP | Nothing |
| SECC Discovery Protocol (SDP) | UDP over IPv6 link-local multicast | Nothing |
| V2G TLS handshake | TCP, TLS 1.2 (-2) / TLS 1.3 (-20) | Nothing |
| V2G application messages (EXI) | Inside the TLS channel | Only certificate installation and update, tunnelled as base64 EXI in `Get15118EVCertificate` |

The single existing tunnel is instructive. `Get15118EVCertificateRequest` carries `exiRequest` as `string[0..11000]`, base64-encoded, with `iso15118SchemaVersion` alongside so the CSMS can parse it, and a `CertificateActionEnumType` of `Install` or `Update` selecting between `CertificateInstallationReq`/`Res` and `CertificateUpdateReq`/`Res`. OCPP already accepts the principle that raw ISO 15118 bytes may travel to the CSMS. It just does so for one narrow family of messages, for a business reason (contract certificate provisioning) rather than a diagnostic one.

Everything else surfaces, if at all, as a `SecurityEventNotificationRequest` — `{ type[50], timestamp, techInfo[255] }`, with no `evseId`, no severity, no sequence number, and no session correlation. A field failure becomes 255 characters of free text.

### 1.2 Two directions

The problem splits cleanly, and the two halves have very different risk profiles:

**Observation.** The station captures what actually happened on the wire and ships it to the CSMS. Risk is confidentiality: captures contain EVCCIDs, MAC addresses, contract certificates and — if TLS secrets are exported — the plaintext of the V2G session.

**Stimulation.** The CSMS causes the station to emit a frame it would not otherwise have emitted. Risk is integrity and availability: this is a remotely triggerable layer-2 packet generator inside a NIS2 essential entity.

Observation without stimulation is still useful and is roughly two orders of magnitude less dangerous. A deployment may reasonably implement chapters 2–9 and permanently disable chapter 10.

### 1.3 What this is not

This is not a replacement for the ISO 15118 conformance and interoperability test suites, which need deterministic timing and a controlled EVCC. It is a mechanism for:

- **Post-mortem diagnosis** of failures that only occur in the field, with a specific vehicle, on a specific station.
- **Fleet-wide statistics** on where sessions die, across thousands of stations, which no bench test produces.
- **Verification** that a deployed security policy is enforced — for example that a station configured for `TLSRequired` really does refuse an SDP request asking for no transport-layer security.
- **Regression testing** after a firmware rollout, from the CSMS, without a site visit.

### 1.4 The smallest useful version needs no new OCPP messages

Most of the diagnostic value in this paper is reachable today, on an unmodified OCPP 2.1 stack, with no protocol extension at all. The station does everything locally and the CSMS collects the result with a message it already has:

1. **Capture into a ring** (§3.2): always-on, header-only by default, into a bounded in-memory buffer.
2. **Trigger** on a failure (§3.2): a SLAC match failure, an SDP timeout, a TLS alert, a `SecurityEventNotification`, or a failed transaction freezes the ring.
3. **Write a pcapng file** locally (chapter 4), including the custom blocks for PLC state and reconstructed SLAC events (§4.3).
4. **Upload it with `GetLogRequest`** using `LogEnumType = DiagnosticsLog`. The content of a diagnostics log is not fixed by OCPP, so a pcapng file (or a zip of pcapng files) needs no change to `LogEnumType`. One `SecurityEventNotification` per export records that it happened.

Everything after this, transport profiles and the reverse path, is optimization and new capability on top of this floor. What each OCPP generation can do:

| OCPP version | Capture upload today | Notes |
|---|---|---|
| 1.6 | `GetDiagnostics` to an operator URL | No Device Model; capture policy is firmware-configured |
| 2.0.1 | `GetLog(DiagnosticsLog)`; `DataTransfer` for control | Custom capture components possible via `DataTransfer` |
| 2.1 | `GetLog(DiagnosticsLog)` plus the `SEND` transport profile (chapter 5); custom components via `CustomizationCtrlr` | The first version with an unconfirmed message type suited to streaming |

The rest of this paper specifies the streaming lifecycle and transports that turn "upload a file after the fact" into "watch a station live and test it remotely". Steps 1 to 3 of the [companion paper](README.md)'s roadmap deliver the diagnostic value; the reverse path (chapter 10) is where the risk is.


## 2. What actually has to be captured

### 2.1 SLAC — layer 2, and possibly not on any interface at all

SLAC (*Signal Level Attenuation Characterization*, ISO 15118-3) runs as HomePlug AV/Green PHY management message entries (MMEs) directly over Ethernet, EtherType `0x88E1`. There is no IP layer. The sequence — parameter exchange, start of attenuation characterization, a burst of M-Sounds, the attenuation characterization result, optional validation, and the match that hands over the network membership key — decides which EVSE the vehicle believes it is plugged into.

Two properties matter for the capture design:

**It is not IP, so no IP-based capture sees it.** The tap must be at layer 2 or below.

**It may never reach the host processor.** This is the single most important architectural constraint in this paper. Green PHY modems fall into two camps:

- *Host-side SLAC*: the modem (e.g. a QCA7000-class device on SPI, bound by the `qcaspi` driver and appearing as an ordinary Ethernet interface) passes MMEs up, and the SLAC state machine runs in station firmware. A raw socket on that interface sees everything.
- *Modem-side SLAC*: the modem firmware terminates SLAC internally and only reports the outcome. The host sees the resulting IPv6 link coming up and nothing before it.

On a modem-side design, a packet capture on the host interface produces an empty file for the entire SLAC phase, and the station must instead export a *synthesised* record from whatever the modem's management interface reports. A capture framework that cannot express "this is reconstructed, not observed" will silently produce misleading evidence. See §4.3.

**Timing.** The sounding and matching phases run on timers measured in tens to hundreds of milliseconds. No capture, filter, buffer flush or transport decision may sit inside that path. This is also why closed-loop SLAC testing through the CSMS is impossible (§10.8).

### 2.2 PLC and PHY state that is not on the wire

Some of the most diagnostically valuable data has no frame representation at all:

- Per-M-Sound attenuation profiles, and the averaged profile the SECC used to decide the match
- Signal-to-noise ratio and tone map, before and after the match
- NID/NMK association state, and whether the modem is in an unassociated or associated network
- Transmit power and the AMP map applied
- Modem firmware version and PIB configuration

A capture format that only holds frames cannot carry these. This is a first-class requirement, not an afterthought — "the attenuation profile was implausible" is precisely the finding that distinguishes a bad cable from a relay attack.

### 2.3 SDP — IPv6 link-local multicast

Once the PLC link is up, the EVCC discovers the SECC with the SECC Discovery Protocol. The request goes to the IPv6 all-nodes link-local multicast address `FF02::1`, UDP port `15118`; the SECC answers **unicast** to the requester.

Both directions are wrapped in the V2GTP header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+-------------------------------+
| Version  0x01 | Inverse  0xFE |         Payload Type          |
+---------------+---------------+-------------------------------+
|                        Payload Length                         |
+---------------------------------------------------------------+
~                            Payload                            ~
+---------------------------------------------------------------+
```

`0x01` is the protocol version, `0xFE` its bitwise inverse — a sanity check that a surprising number of implementations get wrong on receive. Payload type `0x9000` is an SDP request, `0x9001` an SDP response, `0x8001` an EXI-encoded V2G message. ISO 15118-20 adds further payload types.

A complete SDP request is ten bytes on the wire:

```
01 FE 90 00 00 00 00 02 00 00
└┬┘ └┬┘ └──┬──┘ └────┬────┘ ││
 │   │     │         │      │└─ TransportProtocol: 0x00 = TCP, 0x10 = UDP
 │   │     │         │      └── Security: 0x00 = TLS, 0x10 = no transport layer security
 │   │     │         └───────── Payload length = 2
 │   │     └─────────────────── Payload type = SDP request
 │   └───────────────────────── Inverse protocol version
 └───────────────────────────── Protocol version
```

and the response twenty bytes of payload: the SECC's IPv6 address (16), TCP port (2), the security byte and the transport protocol byte.

Those two bytes are the entire ISO 15118-2 transport security negotiation, unauthenticated, on a multicast address any node on the link can reach. That is why the [companion paper](README.md) proposes an `SDPCtrlr` with a `SecurityPolicy`, enforced link-local source scoping, and a rate limiter — and why being able to *test* those settings remotely (§10.6) is worth the effort.

### 2.4 V2G TLS and EXI

After SDP the EVCC opens TCP to the announced port and starts TLS — 1.2 for ISO 15118-2, 1.3 for -20. ISO 15118-2 authenticates only the SECC at the TLS layer; the vehicle proves its contract at the application layer. ISO 15118-20 supports mutual authentication.

How much a handshake capture answers depends on the TLS version, and the two ISO 15118 namespaces differ exactly here:

- **ISO 15118-2 (TLS 1.2).** Offered and selected versions, cipher suites, the certificate chain the SECC presented, `signature_algorithms_cert`, whether OCSP was stapled, and the alert that ended the handshake are all in the clear. A handshake capture answers a great deal and **needs no secrets**.
- **ISO 15118-20 (TLS 1.3).** Only `ClientHello` and `ServerHello` are in the clear. Everything from `EncryptedExtensions` onward — the certificate chain, the stapled OCSP status, `CertificateVerify`, and most alerts — is encrypted under the handshake traffic secrets. A capture without secrets sees the versions and cipher suites and little else, precisely for the namespace that *mandates* TLS.

This is why secret export (§3.6) is not a single on/off decision but a tier, and why the default capture level differs by namespace: header-only is enough to diagnose most ISO 15118-2 handshakes, but a useful ISO 15118-20 handshake capture needs at least the handshake-traffic secrets.

Capturing the message *contents* requires the application-traffic secrets, and that is a different decision again (§3.6).

Above TLS, V2G messages are EXI-encoded against a schema. The protocol namespace/version and its session-local `schemaID` binding are negotiated in `SupportedAppProtocolReq`/`Res`, which is itself sent over the same channel. A decoder that missed the negotiation cannot reliably select the schema for the session — so a capture that starts mid-session is far less useful than one that starts at the TCP SYN. Ring-buffer sizing (§3.2) has to account for this.

The companion paper therefore proposes `V2GEXICtrlr` for low-volume codec and schema metadata: the agreed protocol, session-local `schemaID`, active schema-set digest, reason-coded encode/decode failures, safe bit/schema locations, sizes, timings, and resource-limit counters. This is complementary to packet capture. It normally reports no raw EXI and needs no TLS session secrets because it is instrumented at the SECC codec boundary.

### 2.5 Summary

| # | What | Encapsulation | Tap | Needs |
|---|---|---|---|---|
| 1 | SLAC MMEs | Ethernet, EtherType `0x88E1` | PLC-facing netdev, layer 2 | Raw frame access; may be unavailable (§2.1) |
| 2 | PLC/PHY state | none — modem management interface | Modem driver | Synthetic record type |
| 3 | SDP | UDP / IPv6 link-local, port 15118 | Same netdev | Full frame incl. L2 |
| 4 | V2G TLS handshake | TCP | Same netdev | Nothing extra |
| 5 | V2G application (EXI) | inside TLS | Same netdev + secrets | Session secrets, schema version |
| 6 | SECC-internal decisions | none | SECC application | Structured log, correlated by session |


## 3. Capture architecture inside the Charging Station

### 3.1 Tap points

```
        ┌──────────────────────────────────────────────────┐
        │                Charging Station                  │
        │                                                  │
   EV ══╪══ CP/PLC ──► Green PHY ──► netdev ──► SECC        │
        │              modem         (eth1)     process    │
        │                 │             │          │       │
        │                 │(2)          │(1)       │(3)    │
        │                 ▼             ▼          ▼       │
        │            ┌─────────────────────────────────┐   │
        │            │        Capture Agent            │   │
        │            │   ring buffer · filter · pcapng │   │
        │            └────────────────┬────────────────┘   │
        │                             │                    │
        │                    ┌────────▼────────┐           │
        │                    │  OCPP Client    │           │
        │                    └────────┬────────┘           │
        └─────────────────────────────┼────────────────────┘
                                      │  ◄── backhaul, eth0/LTE
                                      ▼
                                    CSMS
```

**(1) Layer-2 tap on the EV-facing interface.** `AF_PACKET` with a memory-mapped ring (`TPACKET_V3`) on Linux, BPF on BSD. Requires `CAP_NET_RAW`. This is the primary tap and covers items 1, 3, 4 and 5 of §2.5.

**(2) Modem management interface.** Covers item 2, and item 1 when the modem terminates SLAC itself.

**(3) SECC application instrumentation.** Covers item 6, and is the only place TLS secrets can be extracted (§3.6).

Two deployment realities complicate this. If the SECC runs on a separate SoC from the OCPP controller — common on multi-EVSE stations — the capture agent lives on the SECC side and needs an internal channel to the OCPP controller. And if the station bridges the EV-facing network and the backhaul network in any way, the capture agent must be pinned to the EV-facing side. *A capture agent that can be pointed at the backhaul interface is an exfiltration tool for the CPO's own network.* The set of tappable interfaces must be fixed in firmware, not configurable from the CSMS.

### 3.2 Always-on ring, triggered export

Streaming everything to the CSMS is not an option. A single charging session is small, but a station doing 30 sessions a day across 3000 stations is not, and the interesting sessions are a tiny minority.

The workable model is the one flight recorders use:

1. **Capture always**, at low cost, into a bounded in-memory ring (typically 1–16 MB per EVSE), with headers-only slicing by default.
2. **Trigger** on a condition: SLAC match failure, SDP response timeout, TLS alert, `SecurityEventNotification`, a failed transaction, an explicit CSMS command, or a device-model monitor firing.
3. **Freeze** the ring — stop overwriting — and **export** a window around the trigger: everything from *N* seconds before to *M* seconds after.
4. **Resume**.

The pre-trigger window is the entire point. By the time a TLS alert fires, the interesting frames are the SDP exchange 800 ms earlier. It also solves the EXI schema problem from §2.4: size the ring so that a session's `SupportedAppProtocolReq` is still in it when the failure at the end of the session triggers the export.

This maps onto an existing OCPP 2.1 concept. The `DataCollector` component samples measurands at sub-100 ms intervals into an internal log, retrieved in bulk with `GetLogRequest(DataCollectorLog)` and cleared afterwards. The precedent for "the station buffers high-rate data locally and the CSMS collects it" is already in the specification; what is missing is a packet-shaped version of it.

Live streaming remains useful for a *supervised* session — an engineer watching a specific station while a driver retries — but it should be a bounded, leased mode, not the default.

### 3.3 Filters, and why raw BPF from the CSMS is a bad idea

The obvious design is to let the CSMS push a BPF program. It is also a mistake. A BPF program is code, and accepting code from the network into a component holding `CAP_NET_RAW` on an embedded device turns a compromised or malicious CSMS into arbitrary execution inside the station's network stack. Classic BPF interpreters have a long history of out-of-bounds bugs, and cBPF-to-eBPF translation on Linux has had its own.

Use a **declarative filter** the station compiles itself:

```json
{
  "tapPoint":       "EVFacing",
  "etherTypes":     [ "0x88E1", "0x86DD" ],
  "ipProtocols":    [ "UDP", "TCP" ],
  "udpPorts":       [ 15118 ],
  "tcpPorts":       [ 15118, 61341 ],
  "snapLength":     128,
  "fullPacketFor":  [ "SLAC", "SDP", "TLSHandshake" ],
  "maxBytesPerSecond": 65536,
  "maxTotalBytes":  4194304
}
```

The station validates this against its own policy, compiles it to whatever its kernel accepts, and rejects anything outside the allow-list. The expressiveness lost is small; almost every real diagnostic filter for this problem is "SLAC, SDP, and the V2G TCP connection".

`snapLength` deserves emphasis. 128 bytes captures every Ethernet, IPv6, UDP, TCP and TLS record header, the entire V2GTP header, and the whole SDP payload in both directions — while capturing *no* application content. Header-only capture is the correct default and dramatically changes the privacy analysis in §3.5.

### 3.4 Timestamps

Capture timestamps must be:

- **Monotonic within a capture**, so ordering survives clock steps
- **Correlated to the OCPP clock**, so a captured frame can be aligned with a `TransactionEvent`
- **Explicit about their source and resolution**: a hardware timestamp from the MAC, a kernel timestamp, or a userspace timestamp taken after a scheduler delay are three very different things, and only the first is trustworthy at SLAC timescales.

pcapng covers resolution and offset with the per-interface `if_tsresol` and `if_tsoffset` options. It has **no standard way to record the timestamp's *source***: `epb_flags` carries direction, reception type, FCS length and link-layer errors, and nothing about provenance. That gap has to be closed by convention — either an `if_description` string per interface, or a custom block (§4.3) — and it is the reason §4.2 recommends a separate IDB per tap point rather than merging taps with different timestamp semantics onto one.

It matters: a capture that records microsecond-resolution userspace timestamps as if they were hardware timestamps will produce confidently wrong conclusions about SLAC timing, and nothing in the file format will contradict them.

Clock quality here depends on the same infrastructure as metering. See [Secure Time Synchronization for OCPP](../SecureTimeSync/README.md).

### 3.5 Slicing, redaction, and personal data

A full ISO 15118 capture contains, at minimum:

- The EV's MAC address, stable across sessions and therefore a durable vehicle identifier
- The EVCCID
- The eMAID and the contract certificate, which identify the *contract holder*
- Session timing precise enough to characterise an individual's charging behaviour

Under the GDPR this is personal data, and a station that captures it by default has changed its processing purpose without saying so. Under national wiretap law, capturing a communication between two parties may need a legal basis of its own even when the operator owns one endpoint.

Practical consequences for the design:

- **Header-only by default.** `snapLength: 128` collects almost everything diagnostically useful and almost nothing personal beyond identifiers.
- **Full-payload capture is a distinct, more privileged mode** with its own device-model variable and its own security event on activation.
- **Support pseudonymisation at the station**: consistent per-capture substitution of MAC addresses and EVCCIDs, so cross-session correlation is preserved for debugging without shipping the raw identifier. The mapping stays local.
- **Retention must be bounded at the station and at the CSMS**, and stated.
- **Every capture start is an auditable event**, not a silent config change.

### 3.6 TLS keying material

Secret export is not one capability but three tiers, and they carry very different risk. They map onto the `SSLKEYLOGFILE` labels, so a station never has to invent a format:

| Tier | Exports | Decodes | Risk |
|---|---|---|---|
| `None` | nothing | ClientHello/ServerHello only | none beyond the header capture |
| `HandshakeOnly` | the handshake traffic secrets (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`) | the certificate chain, stapled OCSP status, `CertificateVerify`, and alerts of a TLS 1.3 (ISO 15118-20) handshake | the identities and posture of the handshake, but no application data |
| `All` | the handshake **and** application traffic secrets (`CLIENT_RANDOM` for TLS 1.2, `*_TRAFFIC_SECRET_0` for TLS 1.3) | every V2G message on the session | full plaintext, including contract certificates |

`HandshakeOnly` exists specifically because of §2.4: for ISO 15118-20 the certificate chain and OCSP status are encrypted, so diagnosing a handshake failure needs the handshake secrets, but it does not need, and must not export, the application-traffic keys. Only the `TLSK` Decryption Secrets Block (§4.2) actually carried in a given capture distinguishes the tiers on the wire.

`All` is the single most dangerous capability in the paper, and it deserves to be stated bluntly. Exporting V2G application secrets to the CSMS means the CSMS can read every V2G session on that station. In a test environment that is exactly what is wanted. In production it means a CSMS compromise yields plaintext contract certificates fleet-wide.

It also interacts badly with a finding from the [companion paper](README.md): OCPP 2.1 A00.FR.428 permits the Charging Station Certificate and the ISO 15118 SECC certificate to be the same object, while A00.FR.514 recommends against Extended Key Usage. Where an implementation takes that invitation, the key whose sessions are being logged is also the station's OCPP identity.

Therefore, for both the `HandshakeOnly` and `All` tiers:

- Secret export is **off by default** and **not enabled by a normal `SetVariables`** — it requires a signed command (§10.4) or physical presence. `All` should require a stronger unlock than `HandshakeOnly`.
- It is **time-boxed by a lease that expires**, never a persistent setting.
- Enabling it **raises a security event** that cannot be suppressed, and the event names the tier.
- It **applies per session**, not to a whole interface.
- Deployments should be able to **disable the capability in firmware permanently**, and certification profiles should be able to require that.


## 4. Container format: pcapng

### 4.1 Why not plain pcap

Classic pcap has one global header, one link type, one timestamp resolution, and no metadata. This problem has at least three link types, needs TLS secrets in-band, needs per-interface timestamp semantics, and needs to carry PLC state that is not a packet at all.

pcapng solves all of it, is the native Wireshark format, and — decisively for this design — is **block-structured**, which makes it chunkable (§4.4).

### 4.2 Block mapping

| pcapng block | Type | Carries |
|---|---|---|
| Section Header Block (SHB) | `0x0A0D0D0A` | Station identity, firmware version, capture policy |
| Interface Description Block (IDB) | `0x00000001` | One per tap point: link type, snap length, `if_tsresol`, `if_name` |
| Enhanced Packet Block (EPB) | `0x00000006` | Every captured frame, with interface id and timestamp |
| Name Resolution Block (NRB) | `0x00000004` | Optional; pseudonym mapping is deliberately *not* put here |
| Interface Statistics Block (ISB) | `0x00000005` | Received / dropped counts — proof the capture was not silently lossy |
| Decryption Secrets Block (DSB) | `0x0000000A` | TLS secrets, secrets type `0x544C534B` ("TLSK") |
| Custom Block | `0x00000BAD` | PLC/PHY state, SECC decisions (§4.3) |

Link types: SLAC MMEs and SDP are both ordinary Ethernet frames, so `LINKTYPE_ETHERNET` (1) covers items 1, 3, 4 and 5 of §2.5 on a single IDB. A second IDB with a distinct name should be used for any tap point with different timestamp semantics, so that hardware-timestamped and userspace-timestamped frames are never silently mixed.

The Interface Statistics Block is not optional in practice. A capture that dropped 40 % of frames under load and does not say so is worse than no capture, because it produces a confident wrong answer about what the EV did or did not send.

### 4.3 Custom blocks for what is not a packet

pcapng Custom Blocks are keyed by an IANA Private Enterprise Number, which makes them safe to define outside a standards body and safe to ignore for a reader that does not know them. They are the right home for:

- **PLC/PHY records** (§2.2): attenuation profiles, tone maps, SNR, association state, modem firmware version.
- **Reconstructed SLAC events** on modem-side designs, explicitly flagged as reconstructed rather than observed. This is what stops §2.1's failure mode from producing misleading evidence.
- **SECC decision records** (§2.5 item 6): "SDP request rejected, reason: source not link-local", correlated to the EPB that triggered it.
- **Injection provenance** (§10): every frame the CSMS caused the station to emit is recorded with the lease id and the identity that authorised it.

A Wireshark dissector for these blocks is a small, self-contained piece of work and should be published alongside any implementation, or the format is only readable by the tool that wrote it.

### 4.4 Chunking on block boundaries

Because pcapng is a sequence of length-prefixed blocks, a capture can be cut at any block boundary and reassembled by concatenation. This is what makes every transport in chapters 5–8 viable:

```
   [SHB][IDB][IDB][EPB][EPB][EPB][DSB][EPB][CB][EPB][EPB][ISB]
   └────────── chunk 1 ─────────┘└──── chunk 2 ────┘└─ chunk 3 ─┘
```

Rules that make this work in practice:

- Every chunk starts and ends on a block boundary. **Never split a block across chunks**, even if that means a short chunk.
- The SHB and all IDBs go in chunk 1, so a partially received capture is still openable.
- A single block larger than the chunk budget (a jumbo frame, a large custom block) is either sliced at the *capture* layer or the chunk is allowed to exceed the soft budget. Whichever is chosen must be stated, because a receiver that assumes fixed-size chunks will corrupt the stream.
- The receiver writes chunks to a file in sequence order and gets a valid pcapng even if the stream is truncated mid-capture.

Chunk size is transport-dependent: a few kilobytes for OCPP `SEND`, tens of kilobytes for binary frames, and whatever the flow-control window allows on HTTP/2 and HTTP/3.


## 5. Transport A — OCPP `SEND` messages

### 5.1 What OCPP 2.1 gives us

`SEND` (MessageTypeId **6**) is new in OCPP 2.1 and is exactly the right message *type* for capture data: unconfirmed, no response, and — unlike `CALL` — sendable at any time without waiting for an outstanding response.

```
[6, "<MessageId>", "<Action>", {<Payload>}]
```

The specification's own note on `SEND` is the reason chapters 7 and 8 exist:

> Since SEND messages use the same websocket connection as CALL/CALLRESULT messages, the frequent sending of large SEND messages may cause a delay for other messages.

That is head-of-line blocking, acknowledged in the standard, in the sentence that introduces the mechanism.

### 5.2 Lifecycle modelled on the periodic event stream

OCPP 2.1 already has a streaming family — `OpenPeriodicEventStream`, `AdjustPeriodicEventStream`, `ClosePeriodicEventStream`, `GetPeriodicEventStream`, and `NotifyPeriodicEventStream` as the `SEND`-typed data carrier. Reusing that shape means implementers already know it and CSMS state machines already exist for it. One difference should be stated up front: in N11 the Charging Station opens the stream by sending `OpenPeriodicEventStreamRequest` to the CSMS, whereas a capture is opened by the CSMS. The Adjust and Close directions are the same as in OCPP.

```
CSMS                                              Charging Station
  │                                                       │
  │──── OpenPacketCaptureRequest(filter, params) ────────►│
  │◄─── OpenPacketCaptureResponse(Accepted, id, limits) ──│
  │                                                       │
  │◄─── NotifyPacketCaptureData (SEND, seqNo=0) ──────────│  ← SHB + IDBs
  │◄─── NotifyPacketCaptureData (SEND, seqNo=1) ──────────│
  │◄─── NotifyPacketCaptureData (SEND, seqNo=2) ──────────│
  │                                                       │
  │──── AdjustPacketCaptureRequest(id, rate) ────────────►│  ← backpressure
  │◄─── AdjustPacketCaptureResponse(Accepted) ────────────│
  │                                                       │
  │◄─── NotifyPacketCaptureStatus (RingOverflow) ─────────│
  │                                                       │
  │──── ClosePacketCaptureRequest(id) ───────────────────►│
  │◄─── ClosePacketCaptureResponse(Accepted, stats) ──────│
```

### 5.3 Message definitions

**`OpenPacketCaptureRequest`** (CALL)

| Field | Type | Card. | Description |
|---|---|---|---|
| `id` | integer | 1..1 | Capture id, assigned by CSMS, unique per station |
| `evseId` | integer | 0..1 | EVSE scope; absent means station-wide tap points only |
| `tapPoint` | TapPointEnumType | 1..1 | `EVFacing`, `PLCModem`, `SECCInternal` |
| `mode` | CaptureModeEnumType | 1..1 | `Live`, `RingWithTrigger`, `RingOnDemand` |
| `filter` | CaptureFilterType | 1..1 | Declarative filter, §3.3 |
| `trigger` | CaptureTriggerType | 0..1 | Required for `RingWithTrigger` |
| `params` | CaptureStreamParamsType | 1..1 | Chunk sizing and rate, mirroring `PeriodicEventStreamParamsType` |
| `expiryDateTime` | dateTime | 1..1 | Hard stop. **Not optional** — an unbounded capture is a bug |
| `includeSecrets` | boolean | 0..1 | Default `false`; requires a signed command (§3.6) |

**`OpenPacketCaptureResponse`** returns `status` (`Accepted`, `Rejected`, `NotSupported`, `TapPointUnavailable`, `Unauthorized`), plus the limits the station actually granted — `maxBytesPerSecond`, `maxTotalBytes`, `ringBytes`, `snapLength`. *The station always answers with what it will really do, never by echoing the request.* A station that silently truncates a 4 MB request to 512 kB produces captures whose gaps look like network failures.

**`NotifyPacketCaptureData`** (SEND) — deliberately close to `NotifyPeriodicEventStream`:

| Field | Type | Card. | Description |
|---|---|---|---|
| `id` | integer | 1..1 | Capture id |
| `seqNo` | integer | 1..1 | Sequence number, from 0 |
| `pending` | integer | 1..1 | Chunks still buffered at the station — the backpressure signal |
| `basetime` | dateTime | 1..1 | Anchor for the timestamps inside the chunk |
| `data` | string | 1..1 | Base64-encoded pcapng blocks, whole blocks only |
| `tbc` | boolean | 0..1 | "To be continued", as in `NotifyReport` |

**`NotifyPacketCaptureStatus`** (SEND) reports `RingOverflow`, `TriggerFired`, `RateLimited`, `Expired`, `TapPointLost`, with the drop counts. Overflow must be reported as an event and *also* reflected in an Interface Statistics Block, so it survives into the file a forensic analyst opens six months later.

### 5.4 Sizing

Base64 costs 33 %. A 1400-byte captured frame becomes ~1900 characters, plus JSON overhead. The relevant precedent is `Get15118EVCertificateRequest.exiRequest` at `string[0..11000]` — around 8 kB of binary, or roughly five full-size frames per message.

OCPP 2.1 provides the negotiation hook: `OCPPCommCtrlr.FieldLength[<message>.<field>]`, a read-only integer reporting the supported length of a field when it exceeds the schema's. So a station announces:

```
OCPPCommCtrlr.FieldLength["NotifyPacketCaptureData.data"] = 131072
```

and the CSMS sizes chunks accordingly. Without reading that variable a CSMS must assume the schema minimum.

RFC 7692 `permessage-deflate` is mandatory for the CSMS and optional for the station, and it recovers a useful part of the base64 penalty on header-only captures, which are highly repetitive. It recovers nothing on encrypted payloads and costs CPU and memory on a constrained device. A station capturing full TLS payloads should be able to disable compression per connection.

### 5.5 Flow control

The `pending` field is the only backpressure signal available, and it is advisory: the station reports its backlog, and the CSMS responds with `AdjustPacketCaptureRequest` to lower the rate. That is a full round-trip of feedback delay, during which the station either drops frames or keeps queueing.

There is no mechanism for the CSMS to say "stop sending until I catch up" other than closing the capture. This is not a flaw in the message design; it is the absence of transport-level flow control, and chapters 7 and 8 are where it gets fixed properly.

### 5.6 Verdict

`SEND`-based capture works, needs no changes to OCPP-J framing, and is the only option here deployable on an OCPP 2.1 stack today. Every station that implements OCPP 2.1 already has the message type.

It is also, structurally, the wrong shape. It base64-encodes binary into JSON, it multiplexes bulk data onto the same ordered channel as control messages, and its flow control is a round-trip behind reality. Use it as the compatibility profile, not as the target architecture.


## 6. Transport B — binary WebSocket frames

### 6.1 The unused opcode

OCPP-J requires that "the whole message consisting of wrapper and payload MUST be valid JSON encoded with the UTF-8 character encoding". Everything travels in WebSocket **text** frames (opcode `0x1`). RFC 6455's **binary** opcode (`0x2`) is unused by OCPP and unallocated.

That is a clean extension point, and it is backwards compatible in the useful direction: a CSMS that does not implement it simply never opens a binary capture stream, and the station never sends a binary frame. Nothing existing breaks.

### 6.2 Frame format

Control stays in JSON — `OpenPacketCaptureRequest` gains `transport: "BinaryFrame"` — and only the bulk data moves to binary. A 16-byte header keeps the frame self-describing:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|  Magic 'O'    |   Magic 'C'   |    Version    |  Payload Type |
+---------------+---------------+---------------+---------------+
|                          Stream Id                            |
+---------------------------------------------------------------+
|                        Sequence Number                        |
+---------------------------------------------------------------+
|     Flags     |                  Reserved                     |
+---------------+-----------------------------------------------+
~                    Payload — whole pcapng blocks              ~
+---------------------------------------------------------------+
```

- **Magic** `0x4F 0x43` lets a receiver reject binary frames that are not this protocol instead of misparsing them.
- **Version** allows the framing to evolve independently of OCPP-J.
- **Payload Type** distinguishes capture data from injection data (§10.5) and from future uses.
- **Stream Id** correlates to the `id` from the JSON `OpenPacketCaptureRequest`, so authorization and lifecycle stay in the audited JSON channel. *Nothing is ever created by a binary frame.*
- **Sequence Number** gives loss and reorder detection independent of the transport.
- **Flags** carry `LAST_CHUNK`, `TRUNCATED`, `DROPS_OCCURRED`.

Keeping stream creation in JSON is the important design decision. It means the entire authorization surface stays in the message type that CSMS operators already log, audit and rate-limit, and a binary frame referencing an unknown stream id is simply discarded.

### 6.3 Compression

`permessage-deflate` applies per WebSocket message regardless of opcode. For capture data:

- **Header-only captures compress well** — highly repetitive Ethernet/IPv6/TCP headers.
- **Full-payload TLS captures compress to nothing** and waste CPU and a 32 kB LZ77 window per direction on a device that may have 64 MB of RAM total.

A station should be able to negotiate `client_no_context_takeover` to bound memory, or disable compression for capture connections. Mixing attacker-influenceable plaintext with secrets in a shared compression context is the CRIME/BREACH pattern; it is much less exploitable here than in a browser, since the attacker has no way to inject chosen plaintext into the compression stream and observe lengths, but it is another reason not to compress capture payloads by default.

### 6.4 What this fixes, and what it does not

Fixed: the 33 % base64 penalty, JSON parsing cost on multi-megabyte payloads, and the need to escape binary into a text encoding at all.

**Not fixed: head-of-line blocking.** A WebSocket connection is a single ordered byte stream. A 64 kB binary capture frame occupies the connection for exactly as long as 64 kB of base64 would minus the encoding overhead. On a 1 Mbit/s uplink a 4 MB ring dump is still ~30 seconds during which a `RequestStopTransaction` cannot arrive.

WebSocket has no multiplexing. That is the actual problem, and it needs a different layer.


## 7. Transport C — HTTP/2

### 7.1 One connection, many streams

RFC 8441 defines the extended `CONNECT` method with the `:protocol` pseudo-header, which bootstraps a WebSocket connection **inside a single HTTP/2 stream**. The server advertises support with `SETTINGS_ENABLE_CONNECT_PROTOCOL`.

The consequence is exactly what this problem needs: one TCP connection, one TLS handshake, one set of firewall rules, one certificate — and *N* independent, concurrently active WebSocket connections over it.

```
                  ┌─────────────── one TCP + TLS connection ───────────────┐
                  │                                                        │
   Charging       │  stream 1 : ocpp2.1  — control (CALL/CALLRESULT/SEND)  │   CSMS
   Station    ════│  stream 3 : capture  — EVSE 1, EV-facing tap           │════
                  │  stream 5 : capture  — EVSE 2, EV-facing tap           │
                  │  stream 7 : injection — active test lease              │
                  └────────────────────────────────────────────────────────┘
```

### 7.2 Stream assignment

- **Stream 1: the OCPP control channel.** Unchanged `ocpp2.1` subprotocol, unchanged message set. An HTTP/2-unaware CSMS sees ordinary OCPP-J and nothing else exists.
- **One stream per capture**, opened with extended `CONNECT` and a distinct subprotocol name (`ocpp2.1-capture`), carrying raw pcapng chunks with no per-chunk header at all — HTTP/2 already frames and sequences them.
- **One stream per injection lease** (§10), so a burst of injected frames cannot delay control traffic and can be cancelled with `RST_STREAM` — which is a genuinely useful safety property: aborting an injection test becomes a single frame, not an application-level negotiation.

Authorization still happens on stream 1. The station opens a capture stream only after an `OpenPacketCaptureResponse(Accepted)`, and the CSMS rejects a `CONNECT` whose capture id it did not authorise.

### 7.3 Per-stream flow control — the real win

HTTP/2 has per-stream flow control via `WINDOW_UPDATE`. The CSMS advertises a small window on a capture stream and a large one on the control stream. When the CSMS falls behind on capture ingestion it simply stops sending `WINDOW_UPDATE` on that stream; the station's transport blocks; the capture agent sees backpressure immediately and can decide locally whether to drop, slice harder, or spill to the ring.

Compare with §5.5, where backpressure was `pending` in a `SEND` message plus a CSMS round-trip. Here it is a transport primitive with zero application involvement and no round-trip delay. **The `pending` field becomes advisory telemetry rather than the flow-control mechanism.**

One caveat, and it is the opposite of what it first looks like. HTTP/2 has a *connection-level* window in addition to the per-stream ones, and it is shared. A capture stream that fills the connection window blocks the control stream with it — the classic HTTP/2 starvation case. Withholding credit therefore has to be done precisely: the CSMS returns connection-level `WINDOW_UPDATE` normally while withholding *stream-level* credit from the capture stream. That is receiver behaviour the CSMS must implement deliberately, not a guarantee the protocol hands you. A CSMS that simply stops reading the capture stream's socket gets the starvation, not the isolation.

### 7.4 Prioritization

RFC 9218 (`Priority` header field and the `PRIORITY_UPDATE` frame) lets the control stream be marked urgent and non-incremental, and capture streams background and incremental:

```
stream 1 (control) :  priority = u=0, i=?0     ← highest urgency, not incremental
stream 3 (capture) :  priority = u=6, i=?1     ← background, deliver as it arrives
```

Two caveats, and the second is the one that bites.

*Prioritization is a hint.* Implementation quality varies, and RFC 7540's original priority tree was widely ignored and is deprecated by RFC 9113. Never rely on prioritization for a hard latency guarantee; rely on flow-control windows, which are mandatory.

*RFC 9218 is primarily about responses, and capture data is a request.* Capture flows station→CSMS, so it travels in the request direction, where the scheme asks nothing of the receiver — a client "MAY use priority values to make local processing or scheduling choices about the requests it initiates". So for capture, prioritization is something the **station's own** HTTP/2 stack must implement when deciding which of its outgoing streams to serve; the CSMS cannot grant it. Prioritization signalled *to* the CSMS only helps in the CSMS→station direction — control messages on stream 1 ahead of injection commands on stream 7 (§7.2).

The practical consequence: on the upload path, the mechanism that actually protects control latency is the station scheduling its own send queue, backed by the flow-control windows of §7.3. Treat RFC 9218 as useful on the downlink and as a station-local implementation requirement on the uplink.

### 7.5 The simpler alternative: plain HTTP/2 requests

WebSocket-over-HTTP/2 is not the only option, and for the capture use case it may not be the best one. A capture is a unidirectional byte stream from the station to the CSMS, which is exactly what an HTTP request body is:

```
POST /ocpp/capture/CS0042/17 HTTP/2
content-type: application/x-pcapng
```

with the body streamed for the life of the capture. This needs no RFC 8441 support at either end, works through more middleboxes, and gets per-stream flow control for free. The station remains the client, so the NAT story is unchanged. Upload scheduling remains the station's own responsibility, per §7.4.

The reverse direction (§10) is the mirror image: a long-lived `GET` whose *response* body streams injection commands, or a short `POST` per injected frame.

**Recommendation:** use plain HTTP/2 request streams for bulk capture, and reserve extended `CONNECT` for cases genuinely needing bidirectional framing on the same stream. It is less elegant on paper and considerably easier to deploy.

This also composes with the existing OCPP mechanism. `GetLogRequest` already uploads bulk data to a `remoteLocation` out of band; an HTTP/2 capture endpoint is the same pattern with a live stream instead of a completed file, and can reuse the same authentication.

### 7.6 What HTTP/2 does not fix

HTTP/2 removes *application-layer* head-of-line blocking. It does not remove *transport-layer* head-of-line blocking, because all streams share one TCP connection. **A single lost TCP segment stalls delivery of every stream behind it**, including the control stream, until it is retransmitted.

On a wired backhaul this is a footnote. On the LTE and NB-IoT links a large fraction of public charging infrastructure actually runs on, with double-digit millisecond RTTs and real packet loss, it is the dominant effect — and it gets *worse* with multiplexing, because a bulk capture stream keeps the connection's send buffer full, so any loss has more queued data behind it.

Multiplexing bulk capture onto the OCPP control connection over TCP can therefore make control latency worse than leaving capture on a separate connection. That is an argument for HTTP/3, not against multiplexing.


## 8. Transport D — HTTP/3 and QUIC

### 8.1 The same shape, without the shared byte stream

RFC 9220 extends RFC 8441's mechanism to HTTP/3, so the stream model of chapter 7 carries over unchanged. What changes is underneath: QUIC streams are **independently delivered**. Loss on a capture stream delays that capture stream and nothing else. The OCPP control stream is unaffected.

This is the decisive property. It converts §7.6's "multiplexing may hurt control latency" into "multiplexing cannot hurt control latency", which is what makes it acceptable to run a multi-megabyte forensic dump over the same connection that carries `RequestStopTransaction`.

### 8.2 Connection migration

QUIC identifies connections by connection ID rather than the 4-tuple. A station whose NAT binding is rebuilt, or which fails over from Ethernet to LTE, keeps the same QUIC connection — no TLS handshake, no OCPP `BootNotification`, no re-authentication, no gap.

This is worth having *independently of packet capture*. Charging stations on mobile networks lose their NAT bindings constantly, and every rebind today costs a full TCP+TLS+WebSocket+OCPP re-establishment. It complements the redundancy and pooling work in [Resilient, high-available and pooled parallel Connections](../AdvancedConnections/README.md).

### 8.3 Datagrams for the live view

RFC 9221 adds unreliable datagrams to QUIC, and capture has two genuinely different quality-of-service classes:

| Class | Requirement | Carrier |
|---|---|---|
| **Forensic export** — the ring dump around a failure | Complete, ordered, verifiable. A gap invalidates the evidence | Reliable QUIC stream |
| **Live view** — an engineer watching a station in real time | Timely. A dropped frame is an inconvenience, a 5-second retransmission stall is the actual problem | QUIC datagrams |

Today both would be forced onto the same reliable transport, and the live view inherits latency behaviour it does not want. Separating them costs nothing once the connection exists: same connection, same authentication, same lifecycle messages, different carrier per `NotifyPacketCaptureData` class.

Datagrams are bounded by the path MTU, so a chunk must fit in roughly 1200 bytes. That suits header-sliced live capture and rules out full-payload live capture — which is the correct trade anyway.

### 8.4 0-RTT

QUIC's 0-RTT resumption is attractive for a station reconnecting after a mobile outage. It is also **replayable by definition**: an attacker who captures a 0-RTT flight can replay it.

Rule: 0-RTT may carry idempotent data — a resumed capture stream, a status query. It **must never carry injection commands** (§10) or anything that changes station state. This should be enforced structurally by refusing to process injection messages that arrive in early data, not left to operator configuration.

### 8.5 Deployment reality

QUIC is UDP on port 443, and a meaningful fraction of CPO and enterprise firewalls block or heavily rate-limit outbound UDP/443. Any HTTP/3 profile needs a defined fallback to HTTP/2 and then to plain WebSocket, discovered by `Alt-Svc` or by explicit configuration in the network profile.

OCPP's own `OCPPTransportEnumType` currently offers `{ SOAP, JSON }`. Adding transports means extending that enumeration, or — better — decoupling "OCPP-J message encoding" from "the transport carrying it", which the current enumeration conflates.


## 9. Transport comparison

| | A: `SEND` + base64 | B: Binary WS frames | C: HTTP/2 | D: HTTP/3 |
|---|---|---|---|---|
| Deployable on OCPP 2.1 today | **Yes** | No — new framing | No | No |
| Wire overhead | +33 % base64 + JSON | ~16 bytes/chunk | 9-byte frame header | varint framing, ~2–5 bytes |
| Concurrent streams | No | No | **Yes** | **Yes** |
| Application HOL blocking | Severe | Severe | **None** | **None** |
| Transport HOL blocking | Yes (TCP) | Yes (TCP) | Yes (TCP) | **None** |
| Flow control | Advisory `pending`, 1 RTT late | Advisory `pending` | **`WINDOW_UPDATE`, immediate** | **Per-stream, immediate** |
| Prioritization | None | None | RFC 9218 (hint) | RFC 9218 (hint) |
| Cancel a running capture | Close message | Close message | `RST_STREAM` | `STOP_SENDING` |
| Survives NAT rebind | No | No | No | **Yes** |
| Unreliable live view | No | No | No | **Yes** (RFC 9221) |
| Firewall friendliness | **Best** | **Best** | Good | Poor (UDP/443) |
| Station complexity | Lowest | Low | Medium | High |

**Recommendation.** Specify the message set once — chapter 5's lifecycle and chapter 4's container — and treat the transport as a negotiated profile:

- **Profile 1 (`SEND` + base64)** is mandatory. It is the interoperability floor and needs no new framing.
- **Profile 2 (binary frames)** is optional and cheap: same connection, same lifecycle, better efficiency.
- **Profile 3 (HTTP/2)** is where the architecture actually wants to be, and is the first profile that makes bulk capture safe to run on a production station.
- **Profile 4 (HTTP/3)** is the target for stations on mobile links, with mandatory fallback to profile 3 or 1.

The capture content is identical across all four. Only the carrier changes.


## 10. The reverse path: injecting frames from the CSMS

### 10.1 The threat model comes first

Everything to this point is read-only. This chapter is not. What is being proposed is a facility by which a remote party causes a charging station to emit arbitrary frames on a physical network interface.

State it plainly: **this is a remote layer-2 packet injection primitive inside a device that is, under NIS2, part of an essential entity's infrastructure.** Built carelessly, a CSMS compromise becomes the ability to inject arbitrary frames on every EV-facing network in the fleet — and, if the interface allow-list is wrong, on the CPO's own operational network, using the charging station as a pivot into a network that is usually far less segmented than its owners believe.

The diagnostic value is real. So is the risk. The design must make the dangerous configurations impossible rather than merely discouraged.

### 10.2 Non-negotiable constraints

| # | Constraint | Rationale |
|---|---|---|
| 1 | Injection is **off by default** and requires a firmware build that includes it | A station that cannot inject cannot be made to inject |
| 2 | The interface allow-list is **fixed in firmware**, never settable from the CSMS | Otherwise the CSMS can point injection at the backhaul (§3.1) |
| 3 | Injection requires an **active lease**, time-boxed, with a hard expiry | Prevents a forgotten enable from becoming permanent |
| 4 | A lease requires a **signed command** (§10.4) | Survives CSMS compromise if signing keys are held elsewhere |
| 5 | **Operational interlock**: no active transaction, no vehicle connected, connector locked out for the lease duration | An injected SDP or SLAC frame reaching a real vehicle mid-session is a safety issue, not a test |
| 6 | **Egress filter**: an allow-list of EtherTypes, destination MAC/IP/port ranges | An injected DHCP, ARP or Router Advertisement frame is an attack, not a diagnostic |
| 7 | **Rate limit and total budget** per lease, enforced at the station | Bounds the blast radius of a compromised lease |
| 8 | Every injected frame is **captured on egress** and recorded with lease provenance in a Custom Block (§4.3) | The log is self-consistent and an injected frame is never mistaken for an observed one |
| 9 | Lease grant, denial, expiry and every filter rejection raise **security events** | NIS2 correlation, and a tripwire for abuse |
| 10 | Injection **never travels in QUIC 0-RTT** (§8.4) | Replay |

Constraint 8 is easy to overlook and matters more than it looks. Without it, an injected frame and the SECC's response appear in the capture as a genuine EVCC interaction, and six months later nobody can tell a test from an incident.

### 10.3 The injection ladder

Do not offer only raw frames. Offer a ladder of levels, named rather than numbered, with the safe one as the default. A bare integer for the most security-critical parameter in the paper invites the off-by-one where "highest level" and "lowest number" disagree; an enumeration with a stated order does not. Define:

```
InjectionLevelEnumType: Replay < Semantic < Transport < Raw
```

- `Replay` re-emits frames the station itself previously captured; no CSMS-authored bytes at all.
- `Semantic` is the default and covers most tests.
- `Transport` is the highest level most deployments should ever enable.
- `Raw` is the level at which every mistake becomes someone else's incident.

A lease grants a `maxLevel`, and a frame's `level` must not be higher in this order (`Semantic ≤ Transport`, but `Raw` is refused under a `Transport` lease). All are bodies of the same `InjectFrameRequest` (§10.5). Two fields are deliberately **not** per-frame, because they are fixed by the lease (§10.4) and must not be selectable per frame: the egress interface, and the **direction** (§10.4) — whether the frame leaves the station on the wire (`Egress`) or is delivered into the station's own stack as if received on the EV-facing interface (`LocalIngress`).

**`Semantic`.** The CSMS says *what* to send; the station encodes it.

```json
{
  "leaseId":  42,
  "level":    "Semantic",
  "semantic": {
    "kind":              "SdpRequest",
    "security":          "TLS",
    "transportProtocol": "TCP",
    "sourceMode":        "LinkLocalGenerated"
  }
}
```

The station builds the V2GTP header, the UDP and IPv6 headers, and the Ethernet frame. It is impossible to emit anything that is not a well-formed SDP request. This covers the majority of real tests and should be the default level.

**`Transport`.** The CSMS supplies a UDP or TCP payload plus a destination; the station builds L2/L3.

```json
{
  "leaseId":   42,
  "level":     "Transport",
  "transport": {
    "protocol":    "UDP",
    "destination": "[ff02::1]:15118",
    "sourceMode":  "LinkLocalGenerated",
    "hopLimit":    1,
    "payload":     "Af6QAAAAAAIAAA=="
  }
}
```

This permits malformed *payloads* — which is exactly what negative testing needs (§10.7) — while guaranteeing well-formed framing and a destination inside the allow-list. **This should be the highest level most deployments ever enable.**

**`Raw`.** The CSMS supplies the complete frame from the destination MAC onwards.

```json
{
  "leaseId": 42,
  "level":   "Raw",
  "raw":     "MzMAAAABAgAAAAABht0..."
}
```

Necessary for SLAC MMEs, which are not IP, and for tests requiring control of the source MAC. It must be gated behind a stronger unlock than `Transport` — a separate signing key or physical presence — and it should be permanently disablable in firmware. Because `Raw` is the top of the order, `MaxInjectionLevel = Raw` is the single gate; there is no separate Boolean that can disagree with it.

### 10.4 The lease model

```
CSMS                                                  Charging Station
  │                                                             │
  │─── OpenInjectionSession-Signed(JWS) ───────────────────────►│
  │                                          verify signature   │
  │                                          check interlock    │
  │                                          lock out connector │
  │◄── OpenInjectionSessionResponse(Accepted, lease, limits) ───│
  │                                                             │
  │─── OpenPacketCaptureRequest(same EVSE, EVFacing) ──────────►│   ← always capture
  │◄── OpenPacketCaptureResponse(Accepted) ─────────────────────│      before injecting
  │                                                             │
  │─── InjectFrameRequest(lease, Transport, SDP request) ──────►│
  │◄── InjectFrameResponse(Sent, egressTimestamp) ──────────────│
  │◄── NotifyPacketCaptureData(SEND) ───────────────────────────│   ← injected frame
  │◄── NotifyPacketCaptureData(SEND) ───────────────────────────│   ← SECC response
  │                                                             │
  │─── CloseInjectionSessionRequest(lease) ────────────────────►│
  │◄── CloseInjectionSessionResponse(stats) ────────────────────│
  │                                          unlock connector   │
```

The lease is granted by a **signed** request. OCPP 2.1 chapter 7 of Part 4 already defines this: an action `X` has a signed equivalent `X-Signed` whose payload is a Flattened JWS JSON Serialization, with `OCPPAction` and `OCPPMessageTypedId` (sic) in the protected header and `x5t#S256` identifying the signing certificate, using ES256, RS256 or RS384.

The specification notes that message signing is "redundant" when the connection is already secured by TLS. For ordinary messages that is fair. For this one it is exactly wrong, and the reason is the threat model: TLS authenticates *the CSMS*, and the whole point of signing an injection lease is to survive the case where the CSMS is the compromised party. Sign with a key that does not live on the CSMS — an operator hardware token, an offline approval service, a four-eyes authority — and a CSMS compromise no longer yields fleet-wide frame injection.

Lease fields:

| Field | Type | Description |
|---|---|---|
| `leaseId` | integer | Unique per station |
| `evseId` | integer | Scope |
| `interface` | string | Must be in the firmware allow-list |
| `direction` | InjectionDirectionEnumType | `Egress` or `LocalIngress` — fixed for the lease, not per frame |
| `maxLevel` | InjectionLevelEnumType | Highest permitted rung: `Replay`, `Semantic`, `Transport`, or `Raw` |
| `expiryDateTime` | dateTime | Hard stop, station-enforced against its own clock |
| `maxFrames` | integer | Total budget |
| `maxFramesPerSecond` | integer | Rate limit |
| `egressFilter` | EgressFilterType | Allowed EtherTypes, destinations, ports |
| `requireCapture` | boolean | Refuse to inject unless a capture is active on the path being injected |

`requireCapture` defaults to `true`. An injection you cannot see the result of is not a test.

Expiry is enforced by the station against its own clock, so a CSMS that stops responding cannot leave a lease open indefinitely. If the station's clock is not trusted, a monotonic duration cap applies in addition.

**Direction is not cosmetic.** A raw frame *transmitted* on the EV-facing interface (`Egress`) goes to the wire, i.e. to the PLC modem, and Linux does not loop it back into the local IPv6/UDP receive path; a Green PHY modem does not echo the host's transmissions either. So on a single-SoC station where the SECC listens on that same interface, an `Egress` SDP request never reaches the station's own SECC, and "no response" is indistinguishable from a broken SECC — the exact ambiguity this apparatus exists to remove. To test the station's own SECC, the frame must be *delivered inbound* on the EV-facing interface (`LocalIngress`, for example a `tc` ingress redirect from a tap device, or a modem loopback). A `LocalIngress` frame never leaves the station and cannot touch the CPO network, so it is also strictly safer than `Egress`. `Egress` is for stimulating something on the wire; the §10.6 and §10.7 tests against the local SECC require `LocalIngress` unless the SECC lives on a separate SoC and is reachable on the wire. Constraint 8 (capture with provenance) applies to both directions, and the capture tap must be placed where it sees both the injected request and the SECC's unicast reply.

### 10.5 Message definitions

**`InjectFrameRequest`** (CALL — a confirmation is wanted here, so `SEND` is wrong)

| Field | Type | Card. | Description |
|---|---|---|---|
| `leaseId` | integer | 1..1 | Must be active and unexpired |
| `level` | InjectionLevelEnumType | 1..1 | `Replay`, `Semantic`, `Transport`, or `Raw`; must not exceed the lease `maxLevel` in the ladder order |
| `repeat` | integer | 0..1 | For rate-limit testing; counts against `maxFrames` |
| `intervalMs` | integer | 0..1 | Spacing for `repeat` |
| `semantic` | SemanticFrameType | 0..1 | Present for `Semantic` |
| `transport` | TransportFrameType | 0..1 | Present for `Transport` |
| `raw` | string | 0..1 | Present for `Raw`, base64 |

**`InjectFrameResponse`** returns `status` (`Sent`, `RejectedByFilter`, `RateLimited`, `LeaseExpired`, `InterlockActive`, `NotSupported`, `Unauthorized`), the egress timestamp from the same clock domain as the capture, and — on rejection — *which* filter rule rejected it. A test framework that cannot tell "the SECC did not answer" from "the station never sent it" is useless.

For burst injection, a binary-framed or HTTP/2-streamed variant carries frames with payload type `Injection` on a dedicated stream, with the lease still established over the JSON channel. `RST_STREAM` then aborts a running burst immediately (§7.2).

### 10.6 Worked example: testing SDP multicast

This is the canonical test, and it exercises everything above.

**Goal.** Verify that the SECC answers an SDP request sent to `[ff02::1]:15118` on the EV-facing interface — that it answers at all, that it answers *unicast*, that it answers within the timeout, and that the security byte matches the configured policy.

**Setup.** Open a capture on the EV-facing tap with a filter for EtherType `0x86DD` and UDP port 15118, full packets (an SDP exchange is ~30 bytes of payload; there is no privacy argument for slicing it). Take a `Transport`-level injection lease on the same EVSE, with `direction: LocalIngress` so the request is delivered inbound to the station's own SECC rather than sent out on the wire (§10.4). The connector is locked out by the interlock, so no vehicle is involved.

**Inject.** A `Transport`-level request for a well-formed SDP request asking for TLS over TCP:

```json
{
  "leaseId":   42,
  "level":     "Transport",
  "transport": {
    "protocol":    "UDP",
    "destination": "[ff02::1]:15118",
    "sourceMode":  "LinkLocalGenerated",
    "hopLimit":    1,
    "payload":     "Af6QAAAAAAIAAA=="
  }
}
```

The payload decodes to `01 FE 90 00 00 00 00 02 00 00` — the ten-byte SDP request from §2.3. The EV-facing interface and the `LocalIngress` direction come from lease 42, not from this message.

The station builds around it:

```
Ethernet   dst 33:33:00:00:00:01     ← IPv6 multicast MAC for ff02::1
           src <generated test MAC>
           ethertype 0x86DD
IPv6       src fe80::<EUI-64 of test MAC>   ← link-local: must pass the SECC's source check
           dst ff02::1
           next header 17 (UDP)
           hop limit 1
UDP        src <ephemeral>  dst 15118
Payload    01 FE 90 00 00 00 00 02 00 00
```

The source address matters. The SECC replies **unicast to the source**, so a source address that is not a plausible link-local address either gets no reply or gets one the station's own stack discards before the capture sees it — indistinguishable, from the CSMS, from "the SECC is broken". `sourceMode: LinkLocalGenerated` makes the station derive a valid link-local address from the generated test MAC and, critically, ensure its own stack does not swallow the reply.

**Observe.** The capture stream carries both frames. The CSMS parses the response payload:

```
01 FE 90 01 00 00 00 14 <16-byte IPv6> <port> <sec> <tp>
                     └┬┘
                      └─ payload length 0x14 = 20
```

and checks, mechanically:

| Check | Pass condition | Failure means |
|---|---|---|
| Response present | An SDP response was captured | SECC not listening, or multicast not reaching it |
| Response is unicast | Destination MAC is the test MAC, not `33:33:...` | SECC multicasts its response — an information leak to every node on the link |
| Latency | Within the ISO 15118 SDP timeout, with margin | Marginal timing that will fail with a slower EVCC |
| Security byte | Matches the configured `SDPCtrlr.SecurityPolicy` | Policy not enforced |
| Announced address/port | Matches the SECC's actual listener | Misconfiguration that only manifests with real vehicles |
| V2GTP header | Version `0x01`, inverse `0xFE`, length exactly 20 | Malformed responder |

This is precisely the closing of the loop promised in §1.3: the [companion paper](README.md) proposes `SDPCtrlr.SecurityPolicy` as configuration and `SDPCtrlr.LinkLocalSourceEnforced` as effective state; this chapter is how the CSMS verifies that setting them had any effect.

### 10.7 Negative tests

The positive test above is the easy half. The interesting findings come from malformed input — which is why the `Transport` level permits arbitrary *payloads* inside well-formed framing.

| # | Injected | Correct SECC behaviour | Finding if it does otherwise |
|---|---|---|---|
| 1 | Source `2001:db8::1` — not link-local | Ignore; `SDPCtrlr.LinkLocalSourceEnforced` must be `true` in production | Off-link SDP spoofing is possible |
| 2 | `security = 0x10` (no TLS) with policy `TLSRequired` | Answer `0x00` or refuse | **Downgrade accepted** — the finding this whole apparatus exists to catch |
| 3 | `transportProtocol = 0x10` (UDP) | Refuse; ISO 15118-2 requires TCP | Undefined transport accepted |
| 4 | Inverse version byte `0x00` instead of `0xFE` | Drop | Header validation not implemented |
| 5 | Payload length field claims `0xFFFFFFFF`, 2 actual bytes | Drop without allocating | **Allocation from an unvalidated length field** — remote DoS, possibly worse |
| 6 | Payload length 2, one byte present | Drop | Truncation not handled; possible over-read |
| 7 | Payload length 2, 1400 bytes present | Drop or ignore trailing | Parser trusts the buffer over the header |
| 8 | *N* requests in one second | Rate limiter engages, `RejectedRequestCount` increments | No SDP rate limiting — trivial DoS on the discovery layer |
| 9 | Valid request during an active session | Per policy | Session hijack surface |
| 10 | Unicast request direct to the SECC address | Per `SDPCtrlr.RespondToUnicast` | Discovery reachable off-multicast |

Tests 5, 6 and 7 are the memory-safety trio. They are the ones most likely to find something exploitable, they are trivial to express at the `Transport` level, and they are essentially impossible to run against a deployed station today without physical access. Being able to run them remotely, from the CSMS, against the entire fleet after a firmware rollout, is the strongest argument in this paper for building any of it.

Each test is a lease, an injection, a capture window and an automated verdict — so the whole table becomes a CSMS-side regression suite that runs against a maintenance-mode station in under a minute.

### 10.8 What cannot be done this way

**Closed-loop timing-critical protocols.** SLAC's sounding and matching timers are tens to hundreds of milliseconds. A round-trip to a CSMS over LTE is a similar order of magnitude on a good day and an order of magnitude worse on a bad one. A CSMS-driven SLAC state machine will fail its timers, and the failures will be indistinguishable from genuine ones.

The same applies to any V2G exchange with a response deadline — which, per the [companion paper](README.md), includes the 60-second CSMS deadline for `ChargeParameterDiscoveryReq` under smart charging, and much tighter deadlines below it.

So: **remote injection is for open-loop stimulus, not for protocol state machines.** Send a frame, observe what comes back, form a verdict. Do not attempt to *be* the EVCC from 500 km away.

### 10.9 Local scenarios

For anything needing a closed loop, ship the loop to the station:

```
CSMS                                                Charging Station
  │                                                          │
  │── RunNetworkScenarioRequest-Signed(scenarioId, params) ─►│
  │◄─ RunNetworkScenarioResponse(Accepted, runId) ───────────│
  │                                    scenario runs locally │
  │                                    capture runs locally  │
  │◄─ NotifyPacketCaptureData(SEND) ×N ──────────────────────│
  │◄─ NotifyNetworkScenarioResult(runId, verdicts) ──────────│
```

A scenario is a **pre-installed, firmware-signed** routine — "SLAC negative test suite", "SDP policy conformance", "V2G TLS downgrade probe" — parameterised by the CSMS but not authored by it. The CSMS chooses which scenario and with what parameters; it does not supply the logic.

This is the same principle as §3.3's rejection of CSMS-supplied BPF, applied to control flow rather than filters: **parameters may come from the network, code may not.** It preserves the constraint of §10.2 while making closed-loop testing possible, and it fits the existing self-test framing in [Advanced Diagnostics](../AdvancedDiagnostics/README.md).


## 11. Device model

### 11.1 `PacketCaptureCtrlr` (per EVSE, plus a station-wide instance)

| Variable | Type | R/W | Purpose |
|---|---|---|---|
| `Enabled` | boolean | RW | Master switch |
| `AvailableTapPoints` | MemberList | RO | Capability: which taps this hardware actually has (§2.1) |
| `SupportedTransportProfiles` | MemberList | RO | `Send`, `BinaryFrame`, `HTTP2`, `HTTP3` (chapter 9) |
| `MaxRingBytes` | integer | RW | Per-EVSE ring size |
| `MaxConcurrentCaptures` | integer | RO | |
| `MaxBytesPerSecond` | integer | RW | Station-enforced ceiling, independent of what a capture requests |
| `DefaultSnapLength` | integer | RW | Default 128 (§3.3) |
| `FullPayloadCaptureAllowed` | boolean | RW | Gate on capturing application content (§3.5) |
| `SecretsExportAllowed` | OptionList | RW | TLS secret-export tier: `None`, `HandshakeOnly`, or `All` (§3.6); **signed command only**, and `All` needs a stronger unlock than `HandshakeOnly` |
| `PseudonymizationMode` | OptionList | RW | `None`, `PerCapture`, `PerStation` |
| `MaxRetentionSeconds` | integer | RW | Station-side retention bound |
| `DroppedFrameCount` | integer | RO, monitorable | Telemetry — must be exported, never silent |

### 11.2 `FrameInjectionCtrlr` (per EVSE)

| Variable | Type | R/W | Purpose |
|---|---|---|---|
| `Enabled` | boolean | RW | Master switch; default `false` |
| `AllowedInterfaces` | MemberList | **RO** | Fixed in firmware. Read-only is the security control (§10.2) |
| `MaxInjectionLevel` | InjectionLevelEnumType | RW | Highest permitted level: `Replay`, `Semantic`, `Transport`, or `Raw`; may not be more permissive than the firmware ceiling. `Raw` needs a stronger unlock (separate signing key or physical presence) than `Transport` |
| `AllowedEtherTypes` | MemberList | RW | Egress filter |
| `AllowedDestinations` | MemberList | RW | Egress filter — MAC/IP/port allow-list |
| `MaxLeaseSeconds` | integer | RW | Hard ceiling on lease duration |
| `MaxFramesPerLease` | integer | RW | Budget |
| `MaxFramesPerSecond` | integer | RW | Rate limit |
| `RequireSignedCommand` | boolean | RW | Default `true`; lowering it should itself require a signed command |
| `RequireNoActiveTransaction` | boolean | RW | Interlock |
| `RequireEgressCapture` | boolean | RW | Default `true` (§10.4) |
| `ActiveLeaseCount` | integer | RO, monitorable | |
| `RejectedFrameCount` | integer | RO, monitorable | Filter rejections — a tripwire |

The read-only `AllowedInterfaces` is the load-bearing entry in this table. Everything else in the constraint list can be re-derived if it is compromised; a writable interface list cannot.

### 11.3 New security event types

Extending the list proposed in the [companion paper](README.md):

| `type` | Criticality | Meaning |
|---|---|---|
| `PacketCaptureStarted` | low | Capture opened — id, tap point, filter digest |
| `PacketCaptureFullPayloadEnabled` | medium | Application content is now being captured (§3.5) |
| `TlsSecretsExportEnabled` | **high** | V2G session secrets are leaving the station (§3.6) |
| `PacketCaptureRingOverflow` | medium | Frames were dropped — evidence is incomplete |
| `FrameInjectionLeaseGranted` | **high** | Injection is now possible — lease id, level, interface, signer |
| `FrameInjectionLeaseDenied` | medium | Signature, interlock or policy refused a lease |
| `FrameInjectionRejectedByFilter` | **high** | Something tried to inject outside the allow-list — likely abuse |
| `FrameInjectionLeaseExpired` | low | Lease closed by timeout rather than by the CSMS |
| `RawFrameInjectionUsed` | **high** | A `Raw` (level 4) frame was injected |

Every one of these needs an `evseId`, which `SecurityEventNotificationRequest` does not have — reinforcing the argument in the [companion paper](README.md) that `evseId`, severity and a sequence number belong in that message. Smuggling them into 255 characters of `techInfo` is not a basis for NIS2 incident correlation.


## 12. Security and regulatory considerations

### 12.1 Capability summary

| Capability | Who is exposed | Mitigation |
|---|---|---|
| Header-only capture | EV MAC, EVCCID → vehicle tracking | Pseudonymisation, retention bounds, disclosure |
| Full-payload capture | Contract certificates, eMAID → contract holder identity | Separate gate, security event, off by default |
| `HandshakeOnly` secret export | Certificate chain and posture of a TLS 1.3 handshake | Signed command, lease-bound, firmware-disablable |
| `All` secret export | Every V2G session on the station | Stronger unlock, lease-bound, firmware-disablable |
| `Semantic`/`Transport` injection | The station's own SECC | Egress filter, interlock, lease, capture-on-path |
| `Raw` injection | Anything on the EV-facing link | Stronger unlock, firmware-disablable |
| Any injection with a wrong interface list | **The CPO's operational network** | Read-only `AllowedInterfaces` (§11.2) |

The last row is the one that turns a diagnostic feature into a fleet-wide incident, and it is prevented by a single design decision made early: the interface list is firmware, not configuration.

### 12.2 Interaction with certificate reuse

If an implementation follows A00.FR.428 and reuses the Charging Station Certificate as the ISO 15118 SECC certificate, and follows A00.FR.514 in omitting Extended Key Usage, then §3.6's secret export is logging sessions of a key that is simultaneously the station's OCPP identity. The [companion paper](README.md) argues that reuse should be prohibited rather than permitted; this chapter is a concrete reason why. Any station implementing secret export **should** refuse to do so while the SECC key is shared with the OCPP client identity.

### 12.3 Regulatory mapping

- **EU CRA.** Capture and injection are security-relevant functions. They belong in the threat model, in the SBOM (the capture agent's libraries), and in vulnerability handling. The ability to permanently disable injection in firmware is a design-for-security argument in its own right.
- **EU RED / EN 18031.** Access control (ACM) and authentication (AUM) on the lease mechanism; logging (LGM) on the security events of §11.3; resilience (RLM) on the rate limits and budgets; confidential cryptographic keys (CCK) on the TLS secret export path — which is the sharpest CCK question in this paper.
- **NIS2.** The security events in §11.3 are exactly the machine-readable signals incident correlation needs, and exactly what `SecurityEventNotificationRequest` cannot currently carry attributably.
- **GDPR.** §3.5. Capture is processing. Header-only default, bounded retention, pseudonymisation, and disclosure.
- **National interception law.** Capturing an ISO 15118 session captures a communication between the station and a third party's vehicle. Owning one endpoint is not automatically a legal basis in every jurisdiction.

### 12.4 Software separation

The capture agent needs raw socket access; the injection agent needs raw *write* access. Neither should share a fault domain with the OCPP client or the SECC. Separate processes, least privilege, no shared writable state, and independently updatable — which is the argument developed in [OCPP 2.x Firmware Updates with Software Separation](../FirmwareUpdateSeparation/README.md).

An injection agent that can be updated independently of the OCPP client is also an injection agent that can be *removed* independently, which is how a deployment turns "we shipped this for commissioning" into "this is not present in production firmware".


## 13. Recommended path

1. **Define the container first.** pcapng with a registered PEN and published custom block definitions, plus a Wireshark dissector. This is independent of OCPP and useful immediately — a station can write these files to local storage and have them retrieved with the existing `GetLogRequest`, with no protocol changes at all.
2. **Add the capture lifecycle messages** with transport profile 1 (`SEND` + base64). Deployable on OCPP 2.1 as it stands.
3. **Add `PacketCaptureCtrlr`**, with header-only capture and full-payload capture as distinct gates.
4. **Add transport profile 2** (binary WebSocket frames) as an optional efficiency improvement.
5. **Only then the reverse path**, starting at the `Semantic` injection level with `LocalIngress` direction, signed leases mandatory, `Raw` not implemented.
6. **Add the HTTP/2 profile.** This is where bulk capture stops competing with control traffic and becomes safe to run on a production station.
7. **HTTP/3 for stations on mobile links**, with fallback.
8. **`Transport`-level injection and the negative test suite** of §10.7, as a CSMS-side regression suite for maintenance-mode stations.

Steps 1–3 deliver most of the diagnostic value and carry almost none of the risk. Step 5 is where the review effort belongs.


-----------------

*ToDo's:*

- Which IANA Private Enterprise Number for the pcapng custom blocks, and who registers it?
- Exact custom block layouts for PLC/PHY state — needs input from Green PHY modem vendors on what the management interface actually exposes, and it differs per chipset.
- Is `LINKTYPE_ETHERNET` sufficient for HomePlug MMEs, or is a dedicated link type worth requesting from tcpdump.org so dissectors engage automatically without a heuristic on EtherType `0x88E1`?
- Should the capture lifecycle messages reuse `ConstantStreamDataType` and `PeriodicEventStreamParamsType`, or is a packet-specific parameter type cleaner? Reuse is friendlier to existing CSMS code; a separate type avoids overloading fields whose semantics do not fit.
- Does `OCPPTransportEnumType` get extended, or does OCPP separate message encoding from transport properly? The current `{ SOAP, JSON }` enumeration conflates the two, and adding `HTTP2`/`HTTP3` values to it would deepen the conflation rather than fix it.
- Interaction with Local Controllers: a Local Controller terminates the station's WebSocket and opens its own to the CSMS. Does it forward capture streams transparently, aggregate them, or terminate and re-originate? Aggregation at the Local Controller is attractive for bandwidth and terrible for evidence integrity.
- Chunk-level integrity: is a per-chunk hash chain worth it, so a truncated or tampered capture is detectable independently of TLS? Relevant if captures are ever used as evidence rather than diagnostics.
- Wireless ISO 15118 (WPT, ACD) has a different discovery path. How much of chapter 2 carries over?
- Should `SecurityEventNotification` for `TlsSecretsExportEnabled` be non-suppressible at the protocol level, or is that unenforceable in practice?
- The `Replay` level (the lowest rung of `InjectionLevelEnumType`): a mode where the station only re-emits frames from a pcapng it recorded itself, with no CSMS-authored bytes at all. Strictly less powerful than `Semantic` and possibly sufficient for regression testing. Worth implementing first, before any authored-byte level?
- How does an injection lease interact with a reservation or a queued remote start that arrives mid-lease?
- DTLS and QUIC for the V2G link itself (ISO 15118-20 and beyond) — out of scope here, but it changes §2.4 substantially.
