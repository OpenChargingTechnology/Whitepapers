# EV Charging Infrastructure ICT Whitepapers

<!-- description: Open technical whitepapers on EV charging cybersecurity, OCPP, OCPI, metrology, CRA compliance and secure protocols. -->

All white papers presented here are published under the [Creative Commons Attribution Share Alike 4.0 International (CC-BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/). This means you are free to share, adapt, and build upon the content, even for commercial purposes, as long as you give appropriate credit and distribute your work and contributions under the same license.

We actively encourage your collaboration and contributions. Whether you found a mistake, have suggestions for improvement, or want to extend a topic with new insights: *Pull Requests* are welcome and highly appreciated. Help us make these resources better, more accurate, and more useful for the entire e-mobility community.

Let’s advance the future of interoperable, secure, and open electric vehicle infrastructure... together.

## 1. EVQI Secure Transport

To reduce attack surfaces and meet cybersecurity requirements arising from regulations such as the *EU Cyber Resilience Act (EU CRA)* and *NIS2 Directive (EU NIS2)*, the EVQI project defines a wide range of modern transport protocols and protocol extensions to secure communication between all devices within the EV charging infrastructure eco system. Unlike many existing EV charging communication standards, EVQI emphasizes ***cryptographic agility***, giving charging infrastructure operators explicit control over the cryptographic algorithms and security policies deployed within their networks. This enables cryptographic mechanisms to evolve as security requirements change, without requiring fundamental protocol redesigns. ***Post-Quantum Cryptography (PQC)*** is therefore an integral part of the EVQI security architecture, with support designed into all relevant protocol layers rather than treated as a future add-on.

Today's EV charging infrastructure is often connected to the public Internet and public Cloud providers. However, growing cybersecurity threats and increasingly stringent security requirements are driving the adoption of restricted or isolated private networks. In such environments, relying on public infrastructure services such as the ***Web Public Key Infrastructure (Web PKI)***, *Domain Name Services (DNS)* and *Time Synchronization (NTP/NTS)* can be impractical, particularly when external services for certificate issuance, renewal, revocation checking, name resolution, or time synchronization are inaccessible or deliberately restricted.

There are three approaches for establishing authenticated and encrypted communication with a server or remote application _without_ depending on *Web Public Key Infrastructure (Web PKI)* services:
1. **Private PKI**: Deploying and maintaining a dedicated private X.509 Public Key Infrastructure, including certificate authorities, certificate lifecycle management, and trust distribution. This typically follows a hierarchical, top-down trust model, which becomes more complex when devices belonging to different administrative domains need to communicate securely, but do not share a common set of *Root CAs*.
2. **TLS v1.3 RAW Public Keys**: Using TLS with raw public keys instead of (self-signed) X.509 certificates, as specified in [RFC 7250](https://www.rfc-editor.org/info/rfc7250/), establishes trust through external key provisioning, public-key pinning, or another suitable trust mechanism. This preserves the TLS v1.3 security protocol while eliminating the need for X.509 certificate management.
3. **SSH-based trust**: Leveraging the Secure Shell (SSH) ecosystem, which traditionally follows a decentralized, bottom-up trust model based on explicitly trusted public keys. Host and application identities can be established through preconfigured public keys, secure provisioning/pairing, or *Trust on First Use (TOFU)* followed by an independent verification process. Once trusted, these keys are pinned to their respective hosts or applications, allowing subsequent connections to detect unexpected changes in host or application identity. For larger deployments SSH also supports a more centralized, CA-based trust model through OpenSSH certificates without introducing the complexity of a X.509 PKI.

The fundamental distinction for these three approaches is therefore not encryption strength, but how trust is established, distributed, and maintained. Hierarchical PKIs delegate trust through certificate authorities, whereas decentralized approaches establish trust directly between communicating peers. Both SSH and TLS can support different server trust models, depending on their configuration.

For ***Client Authentication***, HTTPS supports application-layer mechanisms such as **HTTP Basic Authentication**, as well as transport-layer authentication through **mutual TLS (mTLS)** via client certificates. SSH also provides built-in support for traditional username/password authentication and public-key authentication, with the latter being the preferred approach in almost all modern deployments.

Since reliable and authenticated time synchronization is already an important requirement in EV charging infrastructure, we propose a third option: ***Time-based One-Time Passwords (TOTP) Authentication***. It follows a similar approach to password based authentication, but replaces the static password with an automatically generated, short-lived authentication code that typically changes every 30 seconds. Consequently, a compromised one-time password can only be exploited within a limited time window, while the underlying shared secret will never be transmitted over the wire and thus remains secure.

An additional TOTP security feature is ***TOTP Authentication with Channel Binding***. By incorporating cryptographic keying material obtained through the ***TLS v1.3 or SSH Key Exporter*** into the TOTP generation process, authentication codes become bound not only to a specific time window but also to the individual TLS or SSH connection. This prevents an intercepted authentication code from being replayed over a different TLS or SSH connection. The result is a lightweight, time-dependent, and cryptographically channel-bound client authentication mechanism that avoids the complexity of client-side X.509 certificate management while providing stronger replay protection than conventional password-based authentication.


### 1.1 EVQI over HTTP/1.1, HTTP/2 and HTTP/3 WebSockets

***HTTP WebSockets over HTTP/1.1*** is the standard protocol for OCPP communication between *Charging Stations*, *Local Controllers*, *OCPP Gateways* and *Charging Station Management Systems (CSMS)*. It provides a low-latency, low-overhead communication channel, but is limited to a single transport pipeline and therefore suffers from head-of-the-line blocking, e.g. when large domain model transmissions delay the token real-time authorization. By allowing HTTP/2 and HTTP/3 as underlying WebSockets transport protocols opens up the possibility to use multiple independend communication channels which helps to reduce head-of-the-line blocking and opens up the possibility of priority queues for improved *Quality-of-Service (QoS)* in EV charging.

The transport security of HTTP WebSocket-based communication relies on the *Web Public Key Infrastructure (Web PKI)*. Its trust model is based on trusted third parties: *Certification Authorities (CAs)* issue certificates binding public keys to domain names, the *Domain Name System (DNS)* provides a globally coordinated namespace, and sufficiently accurate system clocks, typically synchronized via *Network Time Protocol/Network Time Security (NTP/NTS)*, enable trustworthy certificate validity checks.

Together with proper certificate chain validation and hostname verification, these mechanisms establish whether a remote endpoint is authorized to represent the expected service. Thus, when connecting to "example.org", a client can authenticate the server and detect attempts to impersonate it, even when the client has never seen the server before and even when an attacker controls parts of the network path.

- [Resilient, high-available and pooled parallel Connections](AdvancedConnections/README.md)
- [EVQI Transport: Multi-Channel Communication between Charging Stations and CSMS](EVQITransport/README.md) (EU RED/CRA, EU MID)
- [TLS Client/Server Configuration for OCPP v2.x](TLSConfiguration/README.md) (EU RED/CRA)

- [Time-Based One-Time Passwords (TOTP) for M2M Authentication](TimeBasedOneTimePasswords/README.md) (EU RED/CRA)
- [Alternative HTTP Authentication Methods for OCPP](HTTPAuthExtensions/README.md) (EU RED/CRA)
- [HTTP Basic Authentication with Time-Based One-Time Passwords](OCPP/OCPPwithHTTPBasicAuthPlusTOTP.md) (EU RED/CRA, OCPP)

- TLS Channel Binding


### 1.2 EVQI over SSH

SSH is widely known for *Secure Shell (SSH)*, *Secure File Transfer Protocol (SFTP)*, and encrypted *TCP Tunneling*. However, its extensible connection protocol also supports additional application-layer protocols through dedicated SSH channels and named subsystems. This makes SSH an interesting alternative transport and authentication framework for private EV charging infrastructure networks, particularly when decentralized trust relationships between known devices are desirable and operating a dedicated X.509 PKI would introduce unnecessary complexity.

- [DNS over SSH](DNS-over-SSH/README.md) (EU RED/CRA)
- [NTS Key Establishment over SSH](NTS-over-SSH/README.md) (EU RED/CRA)
- [OCPP over SSH](OCPP-over-SSH/README.md) (EU RED/CRA)

- [SFTP for Logfile Uploads and Firmware Downloads](SFTP-FileTransfers/README.md) (EU RED/CRA)
- [SSH Authentication Extensions for OCPP](SSHAuthExtensions/README.md) (EU RED/CRA)

- [Secure SSH Configuration](SecureSSHConfiguration/README.md)
- [SFTP for Logfile Uploads and Firmware Downloads](SFTP-FileTransfers/README.md) (EU RED/CRA)

- SSH Channel Binding *(WIP)*


### 1.3 Secure Domain Name Service (DNS)

- [Secure Name Resolution for OCPP v1.6 and v2.x](SecureDNS/README.md) (EU RED/CRA)
- [DNS over SSH](DNS-over-SSH/README.md) (EU RED/CRA)
- [DNS-over-OCPP](DNS-over-OCPP/README.md) *(Upcoming)*

- DNS Service Records for High-Availability *(Upcoming)*


### 1.4 Authenticated Time Synchronization (NTP/NTS)

- [Secure Time Synchronization for OCPP v1.6 and v2.x](SecureTimeSync/README.md) (EU RED/CRA, EU MID)
- [NTS Key Establishment over SSH](NTS-over-SSH/README.md) (EU RED/CRA)
- [NTS-over-OCPP](NTS-over-OCPP/README.md) *(Upcoming)*


### 1.5 Metrological Data Transport (mCBOR)

JSON has become the de facto standard for data representation within the EV charging ecosystem. However, its loosely defined semantics and implementation-dependent behavior introduce ambiguities that complicate the precise and interoperable exchange of metrological data, often requiring many additional conventions and workarounds.

A more expressive alternative is *Concise Binary Object Representation (CBOR)*, a compact, binary data format that extends the JSON data model with additional data types and more precise representations and extension points, addressing many of JSON's limitations. EVQI therefore builds upon CBOR, extending it with domain-specific data structures and semantics for the precise, interoperable, and verifiable exchange of metrological measurements and related information.

- [Metrological CBOR (CBOR Tag 44252)](MetrologicalCBOR/README.md) (EU MID)



### 2. EVQI End-to-End Security

EV charging infrastructure inherently relies on multi-hop communication, where data passes through multiple intermediaries across different administrative and security domains. In such environments, transport-layer security mechanisms such as TLS or SSH are insufficient to guarantee the end-to-end authenticity, integrity, and, where required, confidentiality of transmitted data. While they secure individual communication channels, intermediaries and internal attackers may still access, modify, or forge data.

Therefore, an additional layer of end-to-end digital signatures, encryption, and enforceable security policies is required to preserve data authenticity and confidentiality across communication boundaries, reduce the attack surface, and protect against compromised or malicious intermediaries, including internal attackers.

- [Signed OCPP Messages and Signer Roles](SignedMessages/README.md) (EU RED/CRA)
- [Safe & Secure OCPP v2.x Device Model Updates](SafeAndSecureDeviceModelUpdates/README.md)



## 3. EVQI Roaming Security

Beyond secure, authenticated machine-to-machine communication, the EV charging ecosystem still lacks comprehensive mechanisms to ensure the authenticity, integrity, and verifiability of charging station location data, real-time availability and status information, metrological energy measurements, and pricing information throughout the entire charging process.

At the same time, the past 15 years have exposed the practical limitations of traditional, centralized Public Key Infrastructure (PKI) approaches, such as those adopted by ISO 15118. The EV charging ecosystem spans numerous independent stakeholders and administrative domains, making it poorly suited to centralized trust models that concentrate authority in the hands of a few dominant actors.

Rather than relying on hierarchical, top-down trust structures with multiple Root CAs consolidated into centrally or politically governed certificate trust lists, **EVQI adopts a decentralized, graph-based PKI and trust model** that distributes authority among independent participants in the EV roaming ecosystem.

The goal is not merely to secure communication channels and implicitly trust whatever data arrives through them, but to establish **end-to-end verifiable authenticity and integrity of the EV charging data itself**, independently of the communication channels and intermediaries involved.

- [WWCP/POI Data Model](https://github.com/OpenChargingCloud/WWCP_POI)



## 4. Protocol Specific Extensions

## 4.1. Open Charge Point Protocol (OCPP)

- [Advanced Diagnostics with Self and Integration Tests for OCPP](AdvancedDiagnostics/README.md) (EU RED/CRA, EU NIS2)
- [Ad hoc Payments via Secure Dynamic QR-Codes for OCPP and OCPI](SecureDynamicQRCodes/README.md) (EU AFIR, EU RED/CRA)
- [OCPP 2.x Firmware Updates with Software Separation](FirmwareUpdateSeparation/README.md) (EU RED/CRA, EU MID)
- [ISO 15118 via OCPP 2.1](ISO15118ViaOCPP/README.md) (EU RED/CRA)
- [The ISO 15118 Tunnel](ISO15118ViaOCPP/ISO15118Tunnel.md) (EU RED/CRA, EU NIS2, GDPR)


*Upcoming:*

- [TCP/IP Networking Configuration](TCPIPNetworkingConfiguration/README.md)
- [Open Charge Context Protocol (OCCP)](OCCP/README.md)
- [Ad hoc payments via Bluetooth LE (BLE)](AdHocPaymentsBLE/README.md)
- [Ad hoc payments via Near Field Communication (NFC)](AdHocPaymentsNFC/README.md)


## 4.2 Open Charge Point Interface (OCPI)

*Upcoming:*

- [Time-Based One-Time Passwords as 2nd Factor Authentication](OCPI/OCPIwithTOTPAuth.md) (EU RED/CRA)


## 4.3 Open InterCharge Protocol (OICP)

*Upcoming:*

- [OICP v2.3 Peer-to-Peer Mode](OICP/OICPv2.3_P2PMode.md)


## 4.4 Open Automated Demand Response (OpenADR)

*Upcoming:*

- [OpenADR and OCPP v2.1 Interoperability](OpenADR-OCPPv2.1/README.md)


## 4.5 ISO 15118

*Upcoming:*

- [ISO 15118-Computer Science Edition](ISO15118-CSE/README.md)



## 5. Cybersecurity Regulations and Standards

- Measuring Instruments Directive (EU MID)
- Radio Equipment Directive (EU RED)
  - [EN 18031](RegulationsAndStandards/EN18031.md)
- [EU Cyber Resilience Act (EU CRA)](RegulationsAndStandards/EUCyberResilienceAct.md)
  - [EN 40000](RegulationsAndStandards/EN40000.md)
- Network and Information Security 2 (EU NIS2)
- General Data Protection Regulation (EU GDPR)
- Payment Services Directive 2 (EU PSD2)



## Acknowledgements

This work is partially funded by the [CyberStand.eu](https://cyberstand.eu) project under the [European Commission’s](https://commission.europa.eu) [Horizon Europe](https://research-and-innovation.ec.europa.eu/funding/funding-opportunities/funding-programmes-and-open-calls/horizon-europe_en) programme. The support of [CyberStand.eu](https://cyberstand.eu) in advancing cybersecurity standardization across critical digital infrastructures, including the e-mobility sector, is gratefully acknowledged.

This repository is part of an ***Open Access*** effort to document and structure ongoing work related to the *Information and Communication Technology (ICT)* and *Cybersecurity* aspects of *Electric Vehicle (EV) Charging Infrastructure*. Its contents may change at any time as new knowledge, regulatory requirements, or technical insights emerge. It reflects the author's and contributors' technical and editorial input and do not necessarily represent the official position of the [CyberStand.eu](https://cyberstand.eu) consortium or the [European Commission](https://commission.europa.eu).

Open Source implementations are partially funded by the [NGI Zero Commons Fund](https://nlnet.nl/commonsfund/) and is published within the [Open Charging Cloud](https://github.com/OpenChargingCloud) and [Open Charging Community](https://github.com/OpenChargingCommunity) GitHub repositories.


<p align="center">
    <img src="images/EN_FundedbytheEU_RGB_POS.png" alt="Funded by the European Union" height="40">
    <img src="images/NGI0_tag.svg" alt="Funded by NLnet NGI Zero Commons" height="40">
</p>
