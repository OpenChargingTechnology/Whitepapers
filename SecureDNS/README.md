White Paper

# Secure Name Resolution for OCPP

This white paper offers a technical guide for configuring electric vehicle (EV) charging stations compliant with [Open Charge Point Protocol (OCPP)](https://openchargealliance.org/protocols/open-charge-point-protocol/) v1.6 (+ [Security Whitepaper Edition 3+](https://openchargealliance.org/whitepapers/)) and OCPP v2.x to resolve domain names securely. Almost every connection a charging station makes starts with a [Domain Name System (DNS)](https://datatracker.ietf.org/doc/html/rfc1035) query, and classical DNS over UDP port 53 is neither authenticated nor confidential. The paper describes:

- **Encrypted transports**: [DNS-over-TLS (DoT)](https://datatracker.ietf.org/doc/html/rfc7858) and [DNS-over-HTTPS (DoH)](https://datatracker.ietf.org/doc/html/rfc8484) towards a small set of configured, CPO-controlled or otherwise trusted recursive resolvers, using the *strict* usage profile of [RFC 8310](https://datatracker.ietf.org/doc/html/rfc8310): a resolver that cannot be authenticated is not used.
- **Server authentication beyond the Web PKI**: dedicated root CAs for name servers, certificate and root CA *pinning* per server, *trust on first use* and change detection for server certificates.
- **A mapping onto the OCPP v2.x Device Model** with two new logical components, `DNSClientController` and `DNSServerController`, and onto OCPP v1.6+SE configuration keys, together with a small extension of *InstallCertificateRequest* for name server root CAs.

The paper also includes operational guidance for firewalls, private APNs and CPO-operated resolvers, and concludes with test criteria for validating an implementation. All statements about *the reference implementation* refer to the open source C# implementation in [WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node) and [Vanaheimr Hermod](https://github.com/Vanaheimr/Hermod/tree/master/Hermod/DNS), which runs on charging stations, OCPP Local Controllers, energy meters and vehicles alike.
<!--  -->
<!--  -->
## 1. Introduction

A charging station resolves names all the time: the WebSocket URL of its Charging Station Management System (CSMS), the NTS-KE servers of its legal time source (see [Secure Time Synchronization for OCPP](../SecureTimeSync/README.md)), the URLs of firmware updates and diagnostics uploads, OCSP responders and CRL distribution points, payment and web portal URLs, and the hosts of vendor specific services. Classical DNS sends these questions in clear text over UDP port 53 and accepts the first answer that matches the query id and port. An attacker on the path — in a mobile network, behind a misconfigured APN, on a shared site network, or on any router between the station and its resolver — can therefore read and forge every answer.

TLS protects the *content* of most of these connections, so a forged answer does not automatically lead to a forged CSMS. The remaining risks are nevertheless substantial:

- **Availability**: A forged or suppressed answer for the CSMS name disconnects the charging station from its backend. A forged answer for the NTS-KE servers makes the station lose its legal time, which may disable dynamic tariffs (see *MaxErrors* within the Secure Time Synchronization paper). Neither attack requires breaking any cryptography.
- **Weak transport security**: OCPP still permits security profile 1 (HTTP Basic Authentication without TLS), and firmware and log URLs may use plain `http://` or `ftp://`. Wherever TLS is missing, a redirected name means credentials or files in the hands of the attacker.
- **Overly broad trust**: Charging stations that validate TLS servers against the complete Web PKI root bundle accept any certificate a public CA issued for the name. Redirecting the name is the first step of every attack that relies on a mis-issued or fraudulently obtained certificate.
- **Discovery**: Mechanisms that publish security relevant data in the DNS — [SRV](https://datatracker.ietf.org/doc/html/rfc2782) and [SVCB](https://datatracker.ietf.org/doc/html/rfc9460) records for service discovery, [TLSA](https://datatracker.ietf.org/doc/html/rfc6698) records for DANE, TXT records for policies as proposed in [Critical Legal Time Services](../CriticalLegalTimeServices/) — are only as trustworthy as the channel and the resolver they are fetched from.
- **Privacy**: Clear text DNS reveals which backends, payment providers and update servers a station talks to, and when. For stations installed at private homes, this is personal data.

Regulations reflect this. The cybersecurity requirements of the [EU Radio Equipment Directive (RED)](https://single-market-economy.ec.europa.eu/sectors/electrical-and-electronic-engineering-industries-eei/radio-equipment-directive-red_en) and its harmonised standard [EN 18031](../RegulationsAndStandards/EN18031.md), and the upcoming [EU Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act), ask for protection of network communication and for resilience against denial of service. Name resolution is part of that communication, even though it is rarely listed explicitly.

This paper therefore treats the name servers of a charging station like any other security critical backend: they are configured explicitly, reached over an encrypted transport, authenticated by their certificates, and every change of their configuration or their certificates is logged. Because CPOs manage their fleets via OCPP, all of this must be configurable via OCPP as well.


## 2. Secure DNS Process Flow

### 2.1 Transports

| Transport | Standard | Default Port | Encrypted | Notes |
|-----------|----------|--------------|-----------|-------|
| `UDP`     | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) | 53 | no | Classical DNS. Must not be used for security relevant names unless the network path is trusted. |
| `TCP`     | [RFC 7766](https://datatracker.ietf.org/doc/html/rfc7766) | 53 | no | Same security as UDP, but without truncation and fragmentation issues. |
| `TLS`     | [RFC 7858](https://datatracker.ietf.org/doc/html/rfc7858) | 853 | yes | DNS-over-TLS (DoT). Recommended default for charging stations: a dedicated port is easy to allow in firewalls. |
| `HTTPS`   | [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) | 443 | yes | DNS-over-HTTPS (DoH) using `POST` and `application/dns-message`. Useful where only port 443 is reachable. |
| `HTTPS_GET` | [RFC 8484 §4.1](https://datatracker.ietf.org/doc/html/rfc8484#section-4.1) | 443 | yes | DoH using `GET` with a base64url encoded query. |
| `HTTPS_JSON` | *(proprietary)* | 443 | yes | The JSON APIs of some public resolvers (`application/dns-json`). Not standardized, should only be used for diagnostics. |

DNS-over-QUIC ([RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250)) is out of scope of this version of the paper. `HTTPS_JSON` should not be offered via OCPP. The reference implementation also knows unencrypted `HTTP` variants of DoH, which exist for tests, and `HTTPS_Binary`, a second name for `HTTPS`; neither should be offered via OCPP either.

Encrypted connections are kept open between queries ([RFC 7858 §3.4](https://datatracker.ietf.org/doc/html/rfc7858#section-3.4), [RFC 7828](https://datatracker.ietf.org/doc/html/rfc7828)), so the TLS handshake — and the certificate validation described below — happens once per connection, not once per query.


### 2.2 Usage Profile

[RFC 8310](https://datatracker.ietf.org/doc/html/rfc8310) distinguishes an *opportunistic* profile, which falls back to unauthenticated or clear text DNS when the encrypted resolver cannot be authenticated, from a *strict* profile, which does not. Charging stations shall use the **strict profile**: a name server reached over `TLS` or `HTTPS` whose certificate is refused is not used, and the station never silently falls back to UDP. A downgrade that an attacker can trigger by blocking port 853 is no protection at all.


### 2.3 Server Authentication

At every TLS handshake with an encrypted name server, the charging station asks three questions, in this order. A *no* to any of them ends the handshake.

1. **Is the certificate issued for the server?** The certificate must be issued for the name or the IP address the server is dialled at. This check is never relaxed, neither by a pin nor by any other configuration option: a certificate for another host is a certificate for another host. When a name server is configured by its IP address, its certificate therefore needs an IP address *Subject Alternative Name*. Many public DoT resolvers have one; CPO-operated resolvers must be issued one.
2. **Does its chain end at a trusted root?** Either at a root CA of the operating system, or at a root CA that was installed specifically for name servers (see `NameServerRootCertificate` in section 3.1.3), or at a root CA the server is pinned to (see below) that is known to the station. Root CAs installed for other purposes, e.g. for NTS-KE servers or for the CSMS, do not vouch for name servers. On most systems the root CAs of the operating system are the complete Web PKI bundle, i.e. the overly broad trust of section 1, so a server whose chain ends there should be held to root pins (section 4.3). *(Reference implementation: a root CA of the station's own store that was installed without a purpose vouches for every purpose, name servers included.)*
3. **Is it a certificate, and a root, the server is held to?** Each server can be held to
   - one or more **certificate pins**: SHA-256 fingerprints of the DER encoded server certificates it may show, e.g. the current one and an announced successor, and/or
   - one or more **root pins**: SHA-256 fingerprints of the DER encoded root CA certificates its chain may end at, e.g. the current root CA and its announced successor.

   A pin only ever *narrows* what is accepted. A pinned certificate that chains to no trusted root is still refused. Fingerprints are taken over the whole certificate, which is what certificate authorities, browsers and `openssl x509 -fingerprint -sha256` display. (DANE users will recognise the equivalents of the TLSA selectors `3 0 1` and `2 0 1`.) They are not the SPKI pins of the out-of-band key-pinned privacy profile of [RFC 7858 §4.2](https://datatracker.ietf.org/doc/html/rfc7858#section-4.2), which are base64 encoded SHA-256 hashes of the *SubjectPublicKeyInfo* as in [RFC 7469](https://datatracker.ietf.org/doc/html/rfc7469): a pin set published in that format cannot be used as it is. A certificate pin no longer matches once the server certificate is renewed, even with the same key; root pins survive such renewals.

What a pin mismatch leads to is configurable per server:

| OnPinMismatch | Result | Logging |
|---------------|--------|---------|
| `Refuse` *(default)* | The connection is refused. | Security log. |
| `Record` | The server is used all the same. | Security log **and** secure metrological log, as evidence. |
| `Accept` | The server is used all the same. | Security log. |

`Record` and `Accept` exist for planned transitions and for the first weeks of rolling out pins in a large fleet. Both must be reported as a security relevant event.

**Trust on first use.** Instead of being given a pin, a server can be told to *learn* one: `TrustOnFirstUse = Root` or `Certificate`. The first time its certificate is accepted without any mismatch, the fingerprint of its root CA (or of the certificate itself) is written into the persistent configuration of the server, exactly as if somebody had typed it, and from then on the server is held to it. Nothing is learned from a certificate that was only tolerated by `Record` or `Accept`. Learning a pin is a configuration change and therefore logged and, via OCPP, reported (section 3.1.4).

**Change detection.** Independent of pins, the station remembers per server the certificate and root CA it was last believed with, and since when, across reboots. A server showing another certificate than before is logged as a warning, even if no pin forbids it. This turns the silent replacement of a resolver — or of its certificate — into an auditable event.

**Time servers.** The [Secure Time Synchronization](../SecureTimeSync/README.md) paper holds NTS-KE and NTP-over-TLS servers to pins, `OnPinMismatch` and trust on first use that mean the same as here (its section 3.2.4), and reports a changed certificate in the same way (its section 3.2.6).

**Revocation.** Revocation should be checked where an OCSP responder or CRL is reachable. A root CA of one's own often has no revocation infrastructure; a status that cannot be obtained should not be held against the certificate, but a certificate that is known to be revoked must be refused. *(Reference implementation: so for chains that end at a root CA of the station's own store. Chains to root CAs of the operating system are currently not checked for revocation.)*


### 2.4 Multiple Name Servers

A charging station may be configured with several name servers (the reference implementation allows up to 16). The reference implementation sends every query to **all** configured servers in parallel and uses the **first valid answer**; a server answering `SERVFAIL` is asked again up to `MaxRetries` times, and every server has its own query timeout. This gives the best latency and resilience, but it has a security consequence:

> The security of name resolution is the security of the **weakest** configured server.

When one encrypted and one clear text server are configured, an on-path attacker simply answers faster on the clear text path. Mixed sets must therefore be avoided. A charging station *should* warn about a configuration that mixes encrypted and unencrypted transports, and *may* offer to refuse unencrypted servers altogether (`DNSClientController.EncryptedOnly`, section 3.1.1). Priority bands as known from the Secure Time Synchronization paper (servers with lower priority values are asked first, servers with equal values in parallel) are an optional extension for deployments that need a fallback resolver.

*Reference implementation*: A set that mixes them is warned about in the log, tagged `security`, at the start and whenever the servers change, and above the list of servers on the web interface. `EncryptedOnly` is implemented as section 3.1.1 describes it.


### 2.5 Bootstrapping

A name server configured by its domain name is a name that has to be resolved first — by a resolver that is not yet authenticated. RFC 8310 §7 discusses this bootstrap problem. Charging stations should therefore configure their name servers **by IP address**, and authenticate them by a certificate issued for that address, narrowed by pins where possible. A pin never replaces the name check of section 2.3: without an authentication domain name, a server dialled by its address needs that address in its certificate. An optional *authentication domain name* (ADN) as defined by RFC 8310 — the name the certificate is checked against when the server is dialled by its address — is described as an optional variable in section 3.1.2.

Networks can also announce encrypted resolvers, via DHCP and IPv6 router advertisements ([RFC 9463, DNR](https://datatracker.ietf.org/doc/html/rfc9463)) or via the resolver itself ([RFC 9462, DDR](https://datatracker.ietf.org/doc/html/rfc9462)). Whether a charging station may accept such announcements is a policy decision of the CPO; the safe default is to use only resolvers configured via OCPP or by the manufacturer.


### 2.6 DNSSEC

Encrypted transports authenticate the *resolver*, not the *data*: a compromised or misconfigured resolver can still return wrong answers. [DNSSEC](https://datatracker.ietf.org/doc/html/rfc4033) authenticates the data itself, from the root zone down.

- A charging station can set the *DNSSEC OK* (DO) bit ([RFC 3225](https://datatracker.ietf.org/doc/html/rfc3225), [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891)) to receive the signatures together with the answers (`DNSClientController.DNSSECOK`).
- The *Authenticated Data* (AD) bit of an answer is only meaningful when the channel to a validating resolver is itself authenticated ([RFC 6840 §5.8](https://datatracker.ietf.org/doc/html/rfc6840#section-5.8)), i.e. over DoT or DoH with strict authentication.
- Local validation on the charging station, including the automated trust anchor rollover of [RFC 5011](https://datatracker.ietf.org/doc/html/rfc5011), is required before DANE (TLSA) or DNS-published policies can be trusted.

*Reference implementation*: The DO bit is configurable and the DNSSEC status of an answer is shown in the diagnostic look-up. Hermod contains a DNSSEC validator, but resolution does not validate inline yet; aggressive NSEC caching ([RFC 8198](https://datatracker.ietf.org/doc/html/rfc8198)) stays dormant until it does.


### 2.7 Robustness and Privacy

- **Caching** of positive answers for their TTL and of negative answers ([RFC 2308](https://datatracker.ietf.org/doc/html/rfc2308)) reduces the attack surface and the load on the resolvers.
- **CNAME and DNAME chains** ([RFC 6672](https://datatracker.ietf.org/doc/html/rfc6672)) are followed up to a configurable depth (default: 8), with loop detection.
- **DNS Cookies** ([RFC 7873](https://datatracker.ietf.org/doc/html/rfc7873)) are sent with every query and make off-path spoofing of UDP answers harder.
- **EDNS Client Subnet** ([RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871)) leaks the station's network to the resolver and to authoritative servers. It shall be disabled by default.
- **Padding** ([RFC 7830](https://datatracker.ietf.org/doc/html/rfc7830), [RFC 8467](https://datatracker.ietf.org/doc/html/rfc8467)) hides the length of queries and answers on encrypted transports.

*Reference implementation*: All of the above. Queries are padded on TCP, TLS and HTTPS, and connections follow the `edns-tcp-keepalive` option of [RFC 7828](https://datatracker.ietf.org/doc/html/rfc7828).


### 2.8 Logging

- Every change of the DNS configuration — whoever made it, locally, via a web interface or via OCPP — shall be logged in the **security log**, naming what changed and who changed it.
- Every refused name server certificate, every certificate used despite a pin mismatch, every learned pin and every changed server certificate shall be logged in the **security log**. Repeating the same verdict at every connection attempt should be logged only once, until the verdict changes, and the recovery of a refused server should be logged as well.
- Entries are additionally written into the **secure metrological log** where a server is configured with `OnPinMismatch = Record`. Name servers do not bear on measured values or on time directly, so by default they do not belong in the metrological log; a CPO that wants evidence of its name resolution can opt in per server.

*Reference implementation*: All of the above. Changes are written as one line listing every changed setting, e.g. `DNS configuration changed: servers = tls://192.0.2.53:853, DNSSEC OK = True.`, and the web interface adds who made the change. Certificate verdicts are tagged `dns`, `certificates` and `security`.


## 3. Secure DNS OCPP Client Configuration

As with time synchronization, OCPP v1.6+SE and v2.x differ fundamentally in how a charging station is configured: OCPP v1.6 uses a flat key-value store, OCPP v2.x its Device Model. Both are covered. The reference implementation keeps one configuration section (`dns`, see section 3.4) and maps both OCPP variants onto it, so the web interface, the configuration file and OCPP can never disagree.

OCPP v2.x does not define any component for name resolution, and the `NetworkConnectionProfile` of *SetNetworkProfileRequest* has no DNS settings. This paper therefore defines two new logical components. Their names end in `…Controller`, like those of the [Secure Time Synchronization](../SecureTimeSync/README.md) paper, so that both extensions are named alike.


### 3.1 OCPP v2.x Client Configuration

#### 3.1.1 DNS Client Controller

The component `DNSClientController` has no instance. It holds what applies to name resolution as a whole.

| Variable Name      | req/opt  | Mutability | Data Type  | Default Value | Values List / Limits | Description | Reference Implementation |
|--------------------|----------|------------|------------|---------------|----------------------|-------------|--------------------------|
| Enabled            | required | rw         | boolean    | true          | -                    | Whether the charging station resolves names at all. While `false`, no name server is asked and no name is resolved, the name of the CSMS included (section 3.1.3); the configured servers are kept and used again when switched back on. | `dns.enabled` |
| QueryTimeout       | optional | rw         | decimal    | *(system)*    | 0.1 … 120 (s)        | How long one query may take, unless a server has a timeout of its own. Unit: `s`. | `dns.queryTimeoutSeconds`, 10 s when not set |
| MaxRetries         | optional | rw         | integer    | 1             | 0 … 255              | How often a server that did not answer, or answered `SERVFAIL`, is asked again. | `dns.maxRetries` |
| RecursionDesired   | optional | rw         | OptionList | `Set`         | `Set`, `Unset`, `Default` | Whether the RD bit is set (`Set`), cleared (`Unset`), or left to the implementation (`Default`). | `dns.recursionDesired` (`true` / `false` / `null`) |
| UseCache           | optional | rw         | boolean    | true          | -                    | Whether answers are cached for their time to live. | `dns.useCache` |
| DNSSECOK           | optional | rw         | boolean    | false         | -                    | Whether the *DNSSEC OK* (DO) bit is set, i.e. whether signatures are requested. | `dns.dnssecOK` |
| FollowCNAMEs       | optional | rw         | boolean    | true          | -                    | Whether CNAME and DNAME chains are followed. | `dns.followCNAMEs` |
| MaxCNAMEFollows    | optional | rw         | integer    | 8             | 0 … 255              | The maximal length of a followed alias chain. | `dns.maxCNAMEFollows` |
| Servers            | required | rw         | string     | -             | comma separated ids, ≤ `MaxServers` | The ids of the `DNSServerController` instances, in the order the name servers are kept. A new id adds a name server, which needs its `Address` in the same request, with the *DataConsistencyModel* `ACID` or `BASE` (section 3.1.3). An id taken out removes the server. The order is not a priority: all servers are asked in parallel (section 2.4). Empty is `Rejected` (section 3.1.3). | the `id`s of `dns.servers`, in its order |
| MaxServers         | optional | ro         | integer    | 16            | -                    | The most `DNSServerController` instances this charging station takes. | constant, 16 |
| UDPPayloadSize     | optional | ro         | integer    | -             | -                    | The EDNS(0) UDP payload size advertised in queries. | fixed at start |
| ClientSubnet       | optional | ro         | string     | ""            | -                    | The EDNS Client Subnet sent with every query, e.g. `"203.0.113.0/24"`; empty when none is sent. | fixed at start |
| EncryptedOnly      | optional | rw         | boolean    | false         | -                    | When `true`, only the servers with an encrypted transport are asked. Servers already configured with an unencrypted transport (`UDP`, `TCP`) stay and are no longer asked; configuring one is `Rejected` (section 3.1.3). See section 2.4. | `dns.encryptedOnly`. Unencrypted is also the plain `HTTP` the node knows for tests. `ServerSource` `System` is `Rejected` while it is `true` and the servers of the operating system are asked unencrypted, as over UDP. |
| ServerSource       | optional | rw         | OptionList | `System`      | `System`, `Manual`   | `System`: the name servers of the operating system or the network configuration (e.g. DHCP), comparable to `ClockCtrlr.NtpSource`. `Manual`: the servers of the `DNSServerController` instances. | `System`: the servers the station was started with, those of the operating system, held to nothing; `dns.servers` is taken out of the file. `Manual`: the servers asked are written into the file, as any change of a `DNSServerController` does. `System` cannot be one change with a `DNSServerController` entry, and is checked against the names of the CSMS first (section 3.1.3). |

Changing `Enabled`, `QueryTimeout` or any other setting takes effect immediately, without a reboot, for every service of the charging station that resolves names.

See also: [C# Reference Implementation](https://github.com/OpenChargingCloud/WWCP_Node/blob/master/WWCP_Node/Configuration/DNSConfiguration.cs)


#### 3.1.2 DNS Server Controller

The *Instance* of the component `DNSServerController` is the id of one name server. A server keeps its id whatever its address becomes and whichever servers are added or taken away around it, so an id refers to the same server across requests. Ids are case-insensitive strings of at most 50 characters, the length of a component instance in OCPP. An id should not be derived from the address of its server, because a new address would then rename the instance.

**Creating and removing instances.** The Device Model has no way to create component instances via *SetVariablesRequest*. Name servers therefore come into existence through the list variable `DNSClientController.Servers`, as the clients of a group of time servers do through `NTPClientGroupController.Clients` in the [Secure Time Synchronization](../SecureTimeSync/README.md) paper (its section 3.2): a new id in the list adds a server, and an id taken out of it removes the server. A *GetBaseReportRequest* afterwards reports the new instances. All servers are asked in parallel (section 2.4); the order of `Servers` is not a priority.

*Reference implementation*: A server is an entry of `dns.servers`, identified by its `id`: lower case letters, digits and hyphens, beginning with a letter, at most 50 characters, as for a time server. An entry without one is `dns-<n>` for its place n, or the next number not taken. Whatever names the servers to somebody else — the web interface saving the list, a change via OCPP — writes the ids into the file, where they stay.

| Variable Name      | req/opt  | Mutability | Data Type  | Default Value | Values List / Limits | Description | Reference Implementation |
|--------------------|----------|------------|------------|---------------|----------------------|-------------|--------------------------|
| Address            | required | rw         | string     | -             | ≤ 253 characters     | The IP address (IPv4 or IPv6) or the domain name of the name server. It cannot be empty: a server is removed through `DNSClientController.Servers`. IP addresses are recommended (section 2.5). | `dns.servers[n].address` |
| Port               | optional | rw         | integer    | *(by transport)* | 1 … 65535         | The port of the name server. When not set: 53 for `UDP`/`TCP`, 853 for `TLS`, 443 for `HTTPS*`. | `dns.servers[n].port` |
| Transport          | optional | rw         | OptionList | `UDP`         | `UDP`, `TCP`, `TLS`, `HTTPS`, `HTTPS_GET` | The transport, see section 2.1. The `valuesList` shall list only what the charging station supports. | `dns.servers[n].transport` |
| QueryTimeout       | optional | rw         | decimal    | *(DNSClientController.QueryTimeout)* | 0.1 … 120 (s) | How long a query to this server may take. Unit: `s`. | `dns.servers[n].queryTimeoutSeconds` |
| CertificatePins    | optional | rw         | string     | ""            | comma separated, ≤ 16 | SHA-256 fingerprints (64 hexadecimal digits, with or without colons) of the certificates this server may show. Only allowed for `TLS` and `HTTPS*`. | `certificateFingerprint(s)` |
| RootPins           | optional | rw         | string     | ""            | comma separated, ≤ 16 | SHA-256 fingerprints of the root CA certificates this server's chain may end at. Only allowed for `TLS` and `HTTPS*`. | `rootFingerprint(s)` |
| OnPinMismatch      | optional | rw         | OptionList | `Refuse`      | `Refuse`, `Record`, `Accept` | What a pin mismatch leads to, see section 2.3. Only allowed when the server is held to a pin or learns one. | `onMismatch` |
| TrustOnFirstUse    | optional | rw         | OptionList | `None`        | `None`, `Root`, `Certificate` | Whether the server learns a root pin or a certificate pin from the first certificate it is believed with. When a pin of that kind is set already, nothing is learned. Only allowed for `TLS` and `HTTPS*`. | `trustOnFirstUse` |
| AuthenticationName | optional | rw         | string     | ""            | ≤ 253 characters     | The authentication domain name of RFC 8310: the name the certificate is checked against and sent as SNI, when the server is dialled by its IP address. | *not implemented* |
| RootCAs            | optional | rw         | string     | ""            | ≤ 50 characters      | The `certificateGroup` of `NameServerRootCertificate` root CAs this server's chain must end at (section 3.1.3). Compatible with `NTPClientController.RootCAs` of the Secure Time Synchronization paper. | Up to 24 letters, digits, `-` or `_` (section 3.1.3) |
| Enabled            | optional | rw         | boolean    | true          | -                    | Whether this server is asked. A disabled server keeps its configuration. | *not implemented* |
| Priority           | optional | rw         | integer    | 0             | 0 … 255              | Servers with lower values are asked first, servers with the same value in parallel (section 2.4). | *not implemented* |
| Problem            | optional | ro         | boolean    | false         | -                    | `true` while the last TLS handshake with this server was refused. Standardized variable name of OCPP; can be monitored. | last verdict |
| CertificateStatus  | optional | ro         | OptionList | ""            | `Accepted`, `Recorded`, `Tolerated`, `PinMismatch`, `Untrusted`, `WrongName`, `NoCertificate` | The verdict of the last TLS handshake. Empty before the first one and for unencrypted transports. | last verdict |
| CertificateFingerprint | optional | ro     | string     | ""            | -                    | The SHA-256 fingerprint of the certificate the server showed at its last handshake. | last verdict |
| RootFingerprint    | optional | ro         | string     | ""            | -                    | The SHA-256 fingerprint of the root CA the chain ended at. | last verdict |
| KnownSince         | optional | ro         | dateTime   | -             | -                    | Since when the server is believed with its current certificate (change detection, section 2.3). | known servers |

The value of `DNSClientController.Servers` is a comma separated list of ids, and that of `CertificatePins` and `RootPins` one of fingerprints, and not a `MemberList`, because a `MemberList` only takes values of the `valuesList`. Writing a list is limited by `SetVariableData.attributeValue`, 1000 characters in OCPP 2.0.1 and 2500 in OCPP 2.1, or less (see `DeviceDataCtrlr.ConfigurationValueSize`). In OCPP 2.0.1 at most 15 fingerprints without colons fit; in OCPP 2.1 all 16 fit, with colons as well. Reading is limited by `ReportingValueSize`: 16 fingerprints without colons take 1039 characters. The [Secure Time Synchronization](../SecureTimeSync/README.md) paper writes its lists in the same way, for the same reason (its section 3.2).

When *trust on first use* learns a pin, the value of `CertificatePins` or `RootPins` changes without any request of the CSMS. A CSMS that wants to know can set a `Delta` monitor on these variables.

See also: [C# Reference Implementation](https://github.com/OpenChargingCloud/WWCP_Node/blob/master/WWCP_Node/Configuration/ServerPins.cs)


#### 3.1.3 OCPP v2.x Command Extensions

*SetVariablesRequest*

Several variables of one name server depend on each other: a pin is only allowed for an encrypted transport, the default port depends on the transport, and `OnPinMismatch` only makes sense with a pin. Applied one by one, a change from `UDP` to `TLS` with a root pin succeeds or fails depending on the order of the *SetVariableData* entries. Therefore:

- **`IndependentRequests`** (standard OCPP, and the default): the entries are applied one by one, in the order of the request, each validated against the configuration as it is after the entries before it, each with its own result. A CSMS has to order them: set the transport before the pins, and remove the pins before switching a server to an unencrypted transport. A new server cannot be added this way, because it cannot exist without its `Address`: a `Servers` entry that names a new id, and every entry of that new server, are `Rejected` with `reasonCode` `InvalidValue`, and their `additionalInfo` says to use `ACID` or `BASE`. This is the rule of the Secure Time Synchronization paper for a new client (its section 3.2.5), and it also means that adding an encrypted server never passes through a clear text one.
- **`ACID`** (the *DataConsistencyModel* of [Safe & Secure Device Model Updates](../SafeAndSecureDeviceModelUpdates/README.md)): all entries of the request that address `DNSClientController` or `DNSServerController` are validated and applied as **one change**: either all of them are accepted, persisted and put into effect together, or none is. The entries that caused the refusal are `Rejected`, all others `Rolledback`. A new server needs its `Address` in the same change; a server that `Servers` removes cannot be set in it.
- **`BASE`**: like `ACID`, but each server the charging station has is one change of its own, and `DNSClientController` is one change together with the servers its `Servers` adds.
- A refused entry is `Rejected`; its `statusInfo.additionalInfo` (at most 512 characters in OCPP 2.0.1, 1024 in OCPP 2.1) says what is wrong, e.g. *"'DNSServerController[dns-2]' is held to a certificate and asked over UDP, which shows none."*. Entries that are wrong by themselves get the usual results: `UnknownComponent` for an instance that is neither a server of the charging station nor named anew in the request's `Servers`, `UnknownVariable`, `NotSupportedAttributeType` for anything but `Actual`, `Rejected` for a read-only variable, `Rejected` with `reasonCode` `InvalidValue` for a value that cannot be parsed (e.g. `"yes"` for a boolean, an id named twice in `Servers`) and `ValueOutOfRange` for one out of range (e.g. more ids than `MaxServers`).
- *SetVariableData* of other components in the same request are not affected.
- A change that could not be persisted SHALL be rejected with `reasonCode` `InternalError`, and SHALL NOT be put into effect: what is in effect must survive a reboot.
- `Servers` naming no server SHALL be rejected: a charging station without name servers cannot reach its CSMS by name.
- While `DNSClientController.EncryptedOnly` is `true` after a change, a server with an unencrypted transport that the charging station does not have SHALL be rejected with `reasonCode` `InvalidValue`: a new one, or one whose `Address`, `Port` or `Transport` changes. So SHALL a change after which no server with an encrypted transport is left, as a list without servers is. Servers with an unencrypted transport that the charging station has already are kept, and not asked, so that `EncryptedOnly` can be switched on without removing them, and switched off to ask them again.
- Switching name resolution off (`DNSClientController.Enabled = false`) SHALL be rejected while a CSMS connection of the charging station is dialled by a domain name. It has the same effect.
- No switch withholds name resolution from the CSMS: it may change every writable variable of both components. What protects the charging station is the rule below and the security log (section 2.8), which records every change and who made it.
- **A CSMS must not cut itself off.** Name servers that cannot answer, or whose certificates are refused, disconnect the charging station from its CSMS. This does not happen at once, because the open WebSocket connection stays up, but at the next reconnect, possibly days later. Before a change via OCPP is put into effect, the charging station SHALL therefore resolve the host names of its configured CSMS connections through the configuration as it would be after the change, within a bounded time (e.g. 10 seconds). When a name that resolves now would no longer resolve, the change SHALL be rejected: all its entries are `Rejected` with `reasonCode` `CSMSUnreachable`, and `additionalInfo` names the host and what each name server came to, e.g. *"'csms.example.com' would not resolve: tls://192.0.2.53:853 untrusted."*. Names that do not resolve now do not block a change, so that a CSMS can repair a broken configuration. *SetNetworkProfileRequest* has a fallback for the same risk (`NetworkConfigurationPriority`); name resolution has none.

*InstallCertificateRequest*

The *InstallCertificateUseEnumType* is extended by `"NameServerRootCertificate"`, analogous to the `"NetworkTimeRootCertificate"` of the Secure Time Synchronization paper, and uses the same optional `certificateGroup` property. A root CA of this type vouches for name servers only, not for the CSMS, not for NTS-KE servers. *GetInstalledCertificateIdsRequest* and *DeleteCertificateRequest* accept the new type as well. Deleting a root CA that the chain of a configured name server ends at is subject to the same check as a change of the configuration (section 3.1.3, "A CSMS must not cut itself off"), and is answered `Failed` when the check fails.

```
{
    "$schema": "http://json-schema.org/draft-06/schema#",
    "$id": "urn:OCPP:Cp:2:2025:1:InstallCertificateRequest",
    "comment": "OCPP 2.1 Edition 1 (c) OCA, Creative Commons Attribution-NoDerivatives 4.0 International Public License",
    "definitions": {
        "InstallCertificateUseEnumType": {
            "description": "Indicates the certificate type that is sent.",
            "javaType": "InstallCertificateUseEnum",
            "type": "string",
            "additionalProperties": false,
            "enum": [
                "V2GRootCertificate",
                "MORootCertificate",
                "ManufacturerRootCertificate",
                "CSMSRootCertificate",
                "OEMRootCertificate",
                "NetworkTimeRootCertificate",
                "NameServerRootCertificate"
            ]
        },
        ...
    },
    "type": "object",
    "additionalProperties": false,
    "properties": {
        "certificateType": {
            "$ref": "#/definitions/InstallCertificateUseEnumType"
        },
        "certificateGroup": {
          "description": "A X.509 certificate group.",
          "type": "string",
          "maxLength": 50
        },
        "certificate": {
            "description": "A PEM encoded X.509 certificate.",
            "type": "string",
            "maxLength": 10000
        },
        "customData": {
            "$ref": "#/definitions/CustomDataType"
        }
    },
    "required": [
        "certificateType",
        "certificate"
    ]
}
```

*Reference implementation*: Root CAs for name servers are TLS roots of the node's certificate store with the usage `dns`. One installed with a `certificateGroup` is marked `dnsca-<group>` as well; a group has up to 24 letters, digits, `-` or `_`. A server whose `RootCAs` names a group is anchored at the root CAs of that group alone: not at a root CA of the operating system, not at one installed without a purpose, and not at a pinned root CA outside the group. Root pins narrow that further. For a server without a group, a pinned root CA that is in the store is a trust anchor even when it was not installed for name servers.

*GetInstalledCertificateIdsRequest* lists the root CAs for `dns` and those installed without a purpose. One installed without a purpose is not deleted via OCPP (`Failed`), because it would be gone for every purpose. *DeleteCertificateRequest* names a certificate, not a type, so a root CA installed for name servers and for time servers is deleted for both. Before a root CA is deleted, the host names of the CSMS connections are resolved without it, and the deletion is `Failed` with `reasonCode` `CSMSUnreachable` when one of them would no longer resolve. Once a root CA is gone, or no longer for `dns` or a server's group, the connections to the name servers that were believed through it are closed.


#### 3.1.4 Security Events

The following *SecurityEventNotificationRequest* types are used. `ReconfigurationOfSecurityParameters` is a security event of OCPP 2.x; the others are proposed by this paper. The `techInfo` names the server, e.g. `tls://192.0.2.53:853`, and the fingerprints involved.

| Type | When |
|------|------|
| `ReconfigurationOfSecurityParameters` | The DNS configuration was changed by anybody but the CSMS itself, e.g. locally or via a web interface — or a pin was learned by trust on first use. |
| `InvalidNameServerCertificate` | A TLS handshake with a name server was refused: wrong name, untrusted chain, no certificate, or a pin mismatch with `OnPinMismatch = Refuse`. Sent once per change of the verdict, not at every attempt. |
| `NameServerPinMismatchTolerated` | A server was used despite a pin mismatch (`Record` or `Accept`). |
| `NameServerCertificateChanged` | A server was believed with another certificate or root CA than before. |

The [Secure Time Synchronization](../SecureTimeSync/README.md) paper proposes the same events for time servers, `InvalidTimeServerCertificate` and `TimeServerCertificateChanged` (its section 3.2.6). It has no counterpart of `NameServerPinMismatchTolerated`.

*Reference implementation*: All four, to every OCPP version a CSMS connection is configured for. They wait in a queue kept on disk while the CSMS is out of reach, which with name resolution broken is precisely when they matter. A change made through OCPP is not sent back to the CSMS that made it. A pin learned on first use is sent once, as `ReconfigurationOfSecurityParameters` naming the server and the pin, and not again as a certificate event. A server believed again after it was refused is logged only. The `techInfo` is cut at 255 characters; the log keeps all of it. Every variable of section 3.1.1 and 3.1.2 supports monitoring.


### 3.2 OCPP v1.6+SE Client Configuration

The following configuration keys map the same configuration onto OCPP v1.6+SE. Comma separated lists (CSL) follow the rules of the Secure Time Synchronization paper, with two exceptions: an empty or missing entry of `dns.ports` means the default port **of that server's transport**, because a port repeated from a previous server would be the wrong port as soon as the transports differ; and an empty or missing entry of `dns.queryTimeouts` means `dns.queryTimeout`, so that one server can be given a timeout of its own without giving one to all servers after it.

Pin lists cannot be written as entries of a comma separated list of servers, so they have one key per server, numbered from 1 in the order of `dns.servers`. OCPP v1.6 limits a configuration value to 500 characters, so at most 7 fingerprints fit into one key.

| Key Name | req/opt | Accessibility | Type | Default Value | Example | Description |
|----------|---------|---------------|------|---------------|---------|-------------|
| dns.enabled             | required | rw | Boolean    | true      | -                                   | See `DNSClientController.Enabled`. |
| dns.servers             | optional | rw | CSL String | ""        | "192.0.2.53, 198.51.100.53"         | The name servers, see `DNSServerController.Address`. |
| dns.ports               | optional | rw | CSL String | ""        | "853, 853"                          | See `DNSServerController.Port`. |
| dns.transports          | optional | rw | CSL String | "UDP"     | "TLS, TLS"                          | See `DNSServerController.Transport`. |
| dns.queryTimeouts       | optional | rw | CSL String | ""        | "2, 3"                              | Per server, in seconds; empty: `dns.queryTimeout`. |
| dns.queryTimeout        | optional | rw | Decimal    | *(system)* | 3                                  | See `DNSClientController.QueryTimeout`. |
| dns.maxRetries          | optional | rw | Integer    | 1         | -                                   | See `DNSClientController.MaxRetries`. |
| dns.recursionDesired    | optional | rw | String     | "Set"     | "Default"                           | See `DNSClientController.RecursionDesired`. |
| dns.useCache            | optional | rw | Boolean    | true      | -                                   | See `DNSClientController.UseCache`. |
| dns.dnssecOK            | optional | rw | Boolean    | false     | -                                   | See `DNSClientController.DNSSECOK`. |
| dns.followCNAMEs        | optional | rw | Boolean    | true      | -                                   | See `DNSClientController.FollowCNAMEs`. |
| dns.maxCNAMEFollows     | optional | rw | Integer    | 8         | -                                   | See `DNSClientController.MaxCNAMEFollows`. |
| dns.encryptedOnly       | optional | rw | Boolean    | false     | -                                   | See `DNSClientController.EncryptedOnly`. |
| dns.onPinMismatch       | optional | rw | CSL String | "Refuse"  | "Refuse, Record"                    | See `DNSServerController.OnPinMismatch`. |
| dns.trustOnFirstUse     | optional | rw | CSL String | "None"    | "Root, None"                        | See `DNSServerController.TrustOnFirstUse`. |
| dns.rootCAs             | optional | rw | CSL String | ""        | "cpo, cpo"                          | See `DNSServerController.RootCAs`: the `certificateGroup` of *InstallCertificate.req* each server's chain must end at. |
| dns.certificatePins.*n* | optional | rw | CSL String | ""        | "41C7…3F61"                         | The certificate pins of the *n*-th server. |
| dns.rootPins.*n*        | optional | rw | CSL String | ""        | "9D2E…D8E"                          | The root pins of the *n*-th server. |

A *ChangeConfiguration.req* changes one key at a time, so the order-dependency described in section 3.1.3 cannot be avoided by a transaction. A charging station SHALL therefore validate each key against the configuration as it would be after the change, and SHALL answer `Rejected` when the result would be inconsistent (e.g. a pin for a server that is still asked over UDP). A CSMS has to change the transports before it sets pins, and remove pins before it switches a server back to an unencrypted transport. The rules of section 3.1.3 for emptying the list of servers, for switching name resolution off and for the host names of the CSMS apply as well; in OCPP v1.6 `Rejected` carries no reason.

*InstallCertificate.req* of the OCPP v1.6 Security Extensions is extended by `"NameServerRootCertificate"` and `certificateGroup` in the same way as shown for the Secure Time Synchronization paper.

*Reference implementation*: Every key. A key is checked and applied as the *SetVariablesRequest* of the `DNSClientController` and `DNSServerController` variables it stands for, with `ACID` where it stands for several, so OCPP v1.6 and v2.x accept and refuse the same changes and are logged alike. The *n*-th entry of a list, and the key `dns.rootPins.`*n*, stands for the server of the *n*-th id of `DNSClientController.Servers`. `dns.servers` changes the address of a server at its place, keeping its id and its pins; a server added at the end takes the next free id, the last entry of the lists that repeat it (`dns.transports`, `dns.onPinMismatch`, `dns.trustOnFirstUse`, `dns.rootCAs`), the default port and timeout, and no pins; servers beyond the end of the list are removed. Both go through `DNSClientController.Servers`, as in OCPP v2.x. There is no key for `ServerSource`: the servers of the operating system come back through OCPP v2.x, or through the station's JSON API with `"servers": null`.


### 3.3 Example

Two CPO-operated resolvers reached over DNS-over-TLS, both issued certificates for their IP addresses by the CPO's own root CA, which was installed as `NameServerRootCertificate`. The first is pinned to that root CA, the second learns its root on first use; signatures are requested. The charging station had the servers `dns-1`, `dns-2` and `dns-3`: `dns-1` is given another address, `cpo-2` is added and the other two are removed, as one change.

*OCPP v2.x SetVariablesRequest* with `"dataConsistencyModel": "ACID"`:

```json
{
  "setVariableData": [
    { "component": { "name": "DNSClientController" },                      "variable": { "name": "Servers"         }, "attributeValue": "dns-1,cpo-2" },
    { "component": { "name": "DNSServerController", "instance": "dns-1" }, "variable": { "name": "Address"         }, "attributeValue": "192.0.2.53" },
    { "component": { "name": "DNSServerController", "instance": "dns-1" }, "variable": { "name": "Transport"       }, "attributeValue": "TLS" },
    { "component": { "name": "DNSServerController", "instance": "dns-1" }, "variable": { "name": "RootPins"        }, "attributeValue": "9D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B3C5D7E9F1A2B4C6D8E" },
    { "component": { "name": "DNSServerController", "instance": "cpo-2" }, "variable": { "name": "Address"         }, "attributeValue": "198.51.100.53" },
    { "component": { "name": "DNSServerController", "instance": "cpo-2" }, "variable": { "name": "Transport"       }, "attributeValue": "TLS" },
    { "component": { "name": "DNSServerController", "instance": "cpo-2" }, "variable": { "name": "TrustOnFirstUse" }, "attributeValue": "Root" },
    { "component": { "name": "DNSClientController" },                      "variable": { "name": "DNSSECOK"        }, "attributeValue": "true" },
    { "component": { "name": "DNSClientController" },                      "variable": { "name": "QueryTimeout"    }, "attributeValue": "3" }
  ]
}
```

*OCPP v1.6+SE:*

```
dns.servers     = "192.0.2.53, 198.51.100.53"
dns.transports  = "TLS"
dns.rootPins.1  = "9D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B3C5D7E9F1A2B4C6D8E"
dns.trustOnFirstUse = "None, Root"
dns.dnssecOK    = true
dns.queryTimeout = 3
```


### 3.4 Reference Implementation Configuration

The section of the configuration file the reference implementation keeps — and which its web interface and its HTTP API read and write in exactly this shape — for the example above:

```json
"dns": {
  "enabled": true,
  "servers": [
    { "id": "dns-1", "address": "192.0.2.53",    "transport": "TLS",
      "rootFingerprint": "9D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B3C5D7E9F1A2B4C6D8E" },
    { "id": "cpo-2", "address": "198.51.100.53", "transport": "TLS", "trustOnFirstUse": "root" }
  ],
  "queryTimeoutSeconds": 3,
  "dnssecOK": true
}
```

Every key is optional; what the section does not mention is left as the charging station was built with, and a station built with nothing uses the name servers of its operating system. A server may also be written as a plain string (`"192.0.2.53"`), meaning UDP on port 53, and without an `id`, meaning `dns-<n>` by its place (section 3.1.2). Several pins of a kind are written as a list (`"rootFingerprints": [ … ]`). After the first handshake with the second server, the station has added the learned `"rootFingerprint"` to its entry.


### 3.5 Example Configuration Using systemd-resolved or Unbound

For Linux based charging stations that use the resolver of the operating system, the following configurations implement the strict profile. Neither supports pinning. Unbound validates against the CA bundle given as `tls-cert-bundle`, which should contain only the root CAs of the configured resolvers; systemd-resolved validates against the CA bundle of the operating system, which cannot be narrowed per resolver.

```
# /etc/systemd/resolved.conf
[Resolve]
DNS=192.0.2.53#resolver1.cpo.example 198.51.100.53#resolver2.cpo.example
DNSOverTLS=yes
# No compiled-in public fallback resolvers
FallbackDNS=
Domains=~.
```

```
# /etc/unbound/unbound.conf
server:
    tls-cert-bundle: /etc/unbound/cpo-resolver-roots.pem
    auto-trust-anchor-file: /var/lib/unbound/root.key

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 192.0.2.53@853#resolver1.cpo.example
    forward-addr: 198.51.100.53@853#resolver2.cpo.example
```

The name after `#` is the authentication domain name of RFC 8310 (`DNSServerController.AuthenticationName`). Unbound additionally validates DNSSEC locally, with an RFC 5011 managed trust anchor.


## 4. Operational Guide

CPOs must configure not only their charging stations, but also the networks they are connected to: private APNs, VPNs, site networks and firewalls.

### 4.1 Firewall Rules

- Allow outbound **TCP port 853** (DoT) and/or **TCP port 443** (DoH) from the charging stations to the configured resolvers — and only to those.
- Block outbound **UDP and TCP port 53** from the charging stations to anything but explicitly configured clear text resolvers. A station that cannot reach a clear text resolver cannot be tricked into using one, e.g. after a factory reset.
- Encrypted DNS connections are kept open for a long time between queries. Stateful firewalls and carrier-grade NAT with short idle timeouts silently drop them; the station then waits for its query timeout before it reconnects. Idle timeouts for port 853 should be at least a few minutes, or the resolvers should announce a shorter keepalive via [RFC 7828](https://datatracker.ietf.org/doc/html/rfc7828).
- When clear text UDP is used at all, answers with DNSSEC signatures can exceed common MTUs. Fragmented UDP is often dropped; TCP port 53 must then be allowed as well.

### 4.2 CPO-Operated Resolvers

For larger fleets, CPOs should operate their own recursive resolvers, reachable from their private APNs or VPNs, and issue their certificates from a CPO root CA dedicated to that purpose:

- The certificates must contain the **IP addresses** the stations dial as Subject Alternative Names (section 2.5).
- The root CA is installed on the stations as `NameServerRootCertificate`, and the servers are pinned to it via `RootPins`. Public root CAs then no longer vouch for the CPO's resolvers.
- Resolvers should validate DNSSEC and refuse to resolve names of internal zones for anybody outside the CPO network (split horizon).
- A change of the resolver root CA is announced by adding the new root's fingerprint to `RootPins` before the switch, and removing the old one afterwards.

### 4.3 Public Resolvers

Public DoT/DoH resolvers are acceptable where no CPO resolver is reachable. They should be pinned by their root CA (not by their leaf certificate, which changes frequently), and the CPO should monitor `NameServerCertificateChanged` events to learn about changes before pins become a problem.

### 4.4 Failure Behaviour

When no name server can be reached or authenticated, a charging station cannot reach its CSMS by name. Charging must continue as defined for an offline CSMS connection. The charging station should keep trying, log the start and the end of the outage, and report it once the CSMS is reachable again. Section 3.1.3 keeps a CSMS from causing such an outage by a change of the configuration.


## 5. Test Criteria

| # | Test | Expected result |
|---|------|-----------------|
| T1  | `ACID`: `Transport = UDP` and `RootPins` on the same server in one *SetVariablesRequest*. | The causing entry `Rejected`, all other DNS entries `Rolledback`; configuration unchanged. |
| T2  | `IndependentRequests`: on an existing UDP server, `RootPins` before `Transport = TLS`; then the opposite order. | First order: `RootPins` `Rejected`, `Transport` `Accepted`. Opposite order: both `Accepted`. With `ACID`: both orders `Accepted`. |
| T2a | `Servers` with a new id, then `RootPins`, `Transport = TLS` and `Address` of that new server, in this order: first with `IndependentRequests`, then with `ACID`. | `IndependentRequests`: all `Rejected` with `InvalidValue`, naming `ACID` or `BASE`; nothing changed. `ACID`: all `Accepted`; the log shows one change, and no clear text server was ever configured. |
| T3  | DoT server presents a certificate for another name or address. | Refused, even when it matches a pin; `InvalidNameServerCertificate`; `Problem = true`, `CertificateStatus = WrongName`. |
| T4  | DoT server's chain ends at a root installed only as `NetworkTimeRootCertificate` or `CSMSRootCertificate`. | Refused (`Untrusted`). |
| T5  | Same server, root installed as `NameServerRootCertificate`. | Accepted. |
| T6  | Pin mismatch with `OnPinMismatch` = `Refuse` / `Record` / `Accept`. | Refused / used and logged in security and metrological log / used and logged in security log. |
| T7  | `TrustOnFirstUse = Root`, first handshake. | `RootPins` contains the root's fingerprint, also after a reboot; security log entry; `ReconfigurationOfSecurityParameters`. |
| T8  | `TrustOnFirstUse = Root`, server already holds a root pin. | Nothing learned. |
| T9  | The server certificate is replaced by another one that is equally valid. | Accepted; `NameServerCertificateChanged`; `KnownSince` updated. |
| T10 | The same refused server, 100 connection attempts. | One security log entry and one security event, not 100. |
| T11 | Pins of a server are changed while a DoT connection to it is open. | The connection is closed; the next query makes a new handshake judged by the new pins. |
| T12 | One encrypted and one clear text server; attacker answers on UDP first. Then `EncryptedOnly = true`, then a new server over UDP, and the encrypted server moved to `TCP`. | Documented weakness (section 2.4), warned about. With `EncryptedOnly = true` the clear text server stays and is no longer asked; the new server and the move to `TCP` are `Rejected` with `InvalidValue`, and nothing is changed. |
| T13 | Block TCP port 853. | No fallback to UDP port 53. |
| T14 | `Servers` naming no server, once with `Enabled = true` and once with `Enabled = false`. | Rejected both times; the servers are kept. |
| T14a | `IndependentRequests`: `Servers` without the first server, then a variable of the second. | Both `Accepted`; the second server keeps its id, and no other server is changed. |
| T15 | More than `MaxServers` servers, more than 16 pins, timeouts out of range. | Rejected with `ValueOutOfRange`. |
| T16 | Configuration change via the local web interface. | Security log names who changed what; `ReconfigurationOfSecurityParameters` to the CSMS. |
| T17 | Persistence fails (e.g. read-only file system). | `InternalError`; nothing changed in effect. |
| T18 | *GetBaseReport(FullInventory)*, after a server was added via the local web interface. | `DNSClientController`, with `Servers` naming every server, and one instance of `DNSServerController` per server, the new one included, with characteristics and value lists. |
| T19 | `Enabled = false` while the CSMS is dialled by its domain name. | Rejected. |
| T20 | Via OCPP, replace the name servers by one whose certificate is untrusted, while the CSMS is dialled by its domain name. Then the same with a server that works. | First: all entries `Rejected` with `reasonCode` `CSMSUnreachable`, configuration unchanged. Then: `Accepted`. |
| T21 | *DeleteCertificate* of the `NameServerRootCertificate` that every configured server's chain ends at, while the CSMS is dialled by its domain name. | `Failed`; the root CA is kept. |


## 6. Relation to Other White Papers

- [Secure Time Synchronization for OCPP](../SecureTimeSync/README.md): NTS-KE servers are found by name. The `NetworkTimeRootCertificate` and the `certificateGroup` extension are reused here. Its components are named alike, its NTP Client Controller (section 3.2.4) holds time servers to pins, `OnPinMismatch` and trust on first use that mean the same as in section 2.3, and its `InvalidTimeServerCertificate` and `TimeServerCertificateChanged` (section 3.2.6) are the twins of the events of section 3.1.4.
- [Critical Legal Time Services](../CriticalLegalTimeServices/): SRV, SVCB, TXT and TLSA based discovery of time servers requires authenticated name resolution and, for TLSA, DNSSEC validation (section 2.6).
- [TLS Configuration for OCPP](../TLSConfiguration/README.md): the questions raised there about root CA groups, pinning and notifications on certificate changes are answered here for name servers, and could be answered the same way for every other TLS server a charging station connects to.


## ToDo's

- Define DNS-over-QUIC (RFC 9250) as a further transport.
- Local DNSSEC validation in the reference implementation, and a variable that requires it (`DNSClientController.RequireDNSSEC`?) for names used by DANE or by DNS-published policies.
- Revocation checks for chains to root CAs of the operating system in the reference implementation (section 2.3).
- A variable that leaves the root CAs of the operating system out for name servers, so that only `NameServerRootCertificate` root CAs and pinned roots vouch for them.
- SPKI pins of RFC 7858 §4.2 as a second notation for pins.
- Decide whether `Priority` bands (section 2.4) become required, and whether a station may then fall back from an encrypted band to a clear text band at all.
- Whether name servers should be configurable per `NetworkConnectionProfile` (e.g. a resolver reachable only through a VPN).
- Accepting encrypted resolvers announced by the network (RFC 9462, RFC 9463) — under which conditions.
