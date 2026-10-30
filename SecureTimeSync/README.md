White Paper

# Secure Time Synchronization for OCPP

This white paper offers a technical guide for configuring electric vehicle (EV) charging stations compliant with [Open Charge Point Protocol (OCPP)](https://openchargealliance.org/protocols/open-charge-point-protocol/) v1.6 (+ [Security Whitepaper Edition 3+](https://openchargealliance.org/whitepapers/)) and OCPP v2.x to enable secure and accurate time synchronization — an essential requirement for compliance with emerging time-based and dynamic tariff regulations. Two implementation strategies are detailed:
- **Direct NTS Integration**: Direct synchronization with legal [Network Time Security (NTS)](https://datatracker.ietf.org/doc/html/rfc8915) servers, such as those operated by Germany’s National Metrology Institute, using Network Time Security Key Establishment (NTS-KE) and Network Time Security (NTS) protected Network Time Protocol (NTPv4). This approach supports multiple prioritized time sources with parallel querying to ensure high performance and resilience.
- **NTP-over-TLS via SMGW**: Technical Guideline [TR-03109-1](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Smart-metering/Smart-Meter-Gateway/TechnRichtlinie/TR_03109-1_node.html) of the [German Federal Office for Information Security](https://www.bsi.bund.de) outlines a Germany-specific option for using NTP-over-TLS in combination with a local Smart Meter Gateway (SMGW). As SMGWs already provide legal time based on operational security, this approach is suitable for existing smart metering infrastructures, but comes with technical and legal limitations.

The paper also includes operational guidance on configuring internal network components—such as firewalls, NAT, and IP addressing—for secure backend communication within Charge Point Operator (CPO) environments. It concludes with test criteria and recommended parameters for validating the correct and compliant implementation of time synchronization mechanisms.
<!--  -->
<!--  -->
## 1. Introduction

Precise and secure time synchronization is vital for electric vehicle (EV) charging stations to ensure accurate transaction logging, reliable billing, and adherence to regulatory mandates, particularly with the rise of ***time-based*** and ***dynamic charging tariffs***. The Open Charge Point Protocol (OCPP) v1.6 (+ Security Whitepaper Edition 3+) and OCPP v2.x facilitate communication between charging stations and Charging Station Management Systems (CSMS), relying on consistent timekeeping for secure operations, such as validating TLS certificates, scheduling smart charging profiles and billing. Traditionally, OCPP heartbeats and the [Network Time Protocol (NTP)](https://datatracker.ietf.org/doc/html/rfc5905) have been employed for time synchronization. However, OCPP heartbeats lack the precision required for high-latency mobile networks, and NTP’s inherent lack of security exposes it to vulnerabilities like [man-in-the-middle (MITM)](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attacks. Securing NTP with [Virtual Private Networks (VPNs)](https://en.wikipedia.org/wiki/Virtual_private_network) or [Datagram Transport Layer Security (DTLS)](https://www.rfc-editor.org/rfc/rfc9147) introduces additional latency and jitter, which can significantly degrade time precision for time-sensitive applications.

Network Time Security (NTS), as defined in [RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915), addresses these shortcomings by providing authenticated and encrypted time synchronization with minimal delay, making it an ideal solution for modern EV charging infrastructure. NTS combines NTS Key Establishment (NTS-KE) for secure key exchange with NTS-protected NTP for robust time queries, ensuring both security and accuracy. This white paper provides a comprehensive guide for configuring OCPP v1.6 and v2.x compliant charging stations to implement NTS, enabling Charge Point Operators (CPOs) to meet emerging regulatory requirements, such as those for time-based and dynamic tariffs in markets. It details the setup of NTS-KE and NTS-protected NTP, including support for multiple prioritized servers with parallel querying to optimize performance and reliability.

The use of [AEAD symmetric authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) complicates the authenticity gurantees of NTS responses, as local attackers with access to the server-to-client crypto keys could still fake responses. An optional extension is presented to add a digital signature to a second NTS response. This does not disturb the normal time synchronization and provides a ***digital signed proof*** that can be added to the secure metrological log book whenever a larger time discrepancy was detected and corrected.

When multiple charging stations are colocated at a single charging location, maintaining a consistent time across all units may be more critical — such as for load balancing applications — than strict synchronization with legal time sources. To address this, we also present an approach where **OCPP Local Controllers** act as *"auxiliary NTS servers"*. This setup enables charging stations to maintain a highly consistent shared time reference, while still receiving cryptographic proofs that the legal time source does not significantly deviate, even if precise alignment is not guaranteed.

Additionally, the paper includes a comprehensive **operational guide** tailored for network operators, detailing precise configurations required to support secure and reliable time synchronization within private IP network environments commonly found in Charge Point Operator (CPO) backends. This includes explicit recommendations for firewall rules, port allowances, and protocol whitelisting necessary to enable outbound communication with public NTS time sources, while preserving network segmentation and security. Special attention is given to handling stateful firewalls and connection tracking mechanisms, which can interfere with NTS session establishment or unexpected NTP packet sizes if improperly configured.

An alternative approach centers on integrating charging infrastructure with a local Smart Meter Gateway (SMGW) using NTP-over-TLS. This method is particularly relevant within the German regulatory framework, where compliance with the Mess- und Eichrecht (calibration law) requires metrologically traceable and verifiable time sources. By leveraging the SMGW — which already synchronizes time via operationally trusted channels and is subject to strict regulatory controls — charging stations can obtain a secure and regulation-compliant time reference without needing direct access to public NTS servers. However, this approach comes with certain limitations. First, it introduces a single-point-of-failure by making the system dependent on the availability and correct configuration of a single SMGW, which may not be practical in heterogeneous or non-residential deployment scenarios. Second, it imposes additional legal restrictions on how the system can be used.

Why time has to be treated as legal evidence, why a charging station must rather refuse time than accept wrong time, and what a provider of legal time should publish for its clients is the subject of the companion white paper [Critical Legal Time Services](../CriticalLegalTimeServices/README.md). This paper is its counterpart on the side of the charging station: how the requirements found there are configured via OCPP.

The paper concludes with recommended testing parameters to validate these configurations, ensuring robust and compliant time synchronization.


## 2. Network Time Security Process Flow

Network Time Security (NTS), as specified in [RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915), enhances the Network Time Protocol (NTP) by adding authentication and encryption, ensuring secure and accurate time synchronization with minimal latency which is not possible with normal TLS connections (TCP+TLS handshakes) or digital signatures using asymmetric cryptography (UDP+DTLS). NTS operates in two distinct phases: the NTS Key Establishment (NTS-KE) phase, which securely negotiates cryptographic keys over TLS-protected TCP connections, and the NTS-protected NTP phase, which uses these keys to secure classical time synchronization NTPv4 queries over UDP. This section outlines the NTS-KE request and response process, the NTS-protected NTP request and response, and how the client processes the results, providing a clear understanding of NTS’s operational mechanics.

### 2.1 NTS Key Establishment (NTS-KE) Phase

The NTS-KE phase establishes a secure channel to derive cryptographic keys and parameters for the subsequent NTP communication. This phase uses TLS 1.3 (or higher) over TCP port 4460 to ensure confidentiality and authenticity.


#### NTS-KE Request:
The client, an OCPP Charging Station or an OCPP Local Controller, initiates a TLS v1.3 connection to the NTS-KE server and ensures the server’s identity by validating its certificate, mitigating MITM risks. Which root certification authorities (root CAs) are used to validate the server certificate is a configuration option. For security reasons this should not be the entire World Wide Web root CA bundle used within web browsers.

Then the client sends an NTS-KE request message, which includes:
- The protocol it wants keys for, NTPv4 (NTS Next Protocol Negotiation).
- Supported cryptographic algorithms (e.g., AES-SIV-CMAC for message authentication).
- Optionally the NTP server and port it would prefer (NTPv4 Server Negotiation and NTPv4 Port Negotiation, [RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915) §4.1.7 and §4.1.8).
- Optional parameters, such as a request for an additional digital signed NTP response.

The NTS-KE request carries no nonce. Protection against replay belongs to the NTS-protected NTP phase, where every request carries a Unique Identifier extension field (RFC 8915 §5.3).

#### Key Derivation
A set of cryptographic keys for Client-to-Server (C2S) and Server-to-Client (S2C) encryption will be derived from the key material of the TLS connection and later be used to encrypt and authenticate the NTP communication via an [Authenticated Encryption with Associated Data (AEAD)](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) algorithm. This method is based on TLS 1.3 exporter mechanism, as defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446), using `EXPORTER-network-time-security` as constant.

Some NTS-KE servers also support a non-standardized way to generate both keys at the server and include them in the NTS-KE response. Supporting this feature can be an option for TLS libraries that do not support the key-exporter functions.


#### NTS-KE Response:
The server responds with:
- Confirmation of the selected cryptographic algorithm.
- Multiple opaque NTS-KE cookies, which encapsulates server state as the NTS-KE server discards all state after the TLS session closes and all further communication
relies purely on the client to store cookies containing key material or references to it.
- The NTS client stores these cookies within a secure storage.

The NTS-KE response may also name the NTP server and port that will accept the cookies (NTPv4 Server Negotiation and NTPv4 Port Negotiation records, RFC 8915 §4.1.7 and §4.1.8). Both records are part of the standard. Without them, the client uses the NTP service at the address of the NTS-KE server, on port 123.
 

### 2.2 NTS-Protected NTP Phase

The NTS-protected NTP phase uses the keys and cookies obtained from NTS-KE to secure time synchronization queries over UDP port 123, maintaining low latency.


#### NTS-Protected NTP Request

The client sends an NTP packet to the specified NTP server, augmented with NTS extensions:
- The packet includes a standard NTPv4 header with timestamp fields.
- An unique identifier extensions to prevent replay attacks.
- An NTS cookie, which allows the server to retrieve session state without maintaining per-client data.
- An NTS authenticator extension, using the C2S key to compute a message authentication code (MAC) via authenticated encryption (e.g., AES-SIV-CMAC).


#### NTS-Protected NTP Response

The server verifies the cookie and the AEAD MAC, ensuring the request’s authenticity and integrity and responds with:
- A standard NTPv4 response containing timestamps (origin, receive, transmit, and reference).
- A new cookie to replace the used one, ensuring continued stateless operation.
- An NTS authenticator extension, using the S2C key to authenticate the response.


#### Client Processing of NTS Results

Upon receiving the NTS-protected NTP response, the client performs several steps to validate and utilize the time data:
- Authentication: The client verifies the response’s MAC using the S2C key, ensuring the response originates from the trusted server and has not been altered.
- Timestamp Extraction: If authenticated, the client extracts the timestamps to calculate the network delay and clock offset. The standard NTP algorithm
computes the round-trip time and adjusts the local clock based on the server’s reference time.
- Cookie Management: The client stores the new cookie from the response, using it for subsequent NTS requests to maintain session continuity without
repeated NTS-KE negotiations.
- Clock Adjustment: The client applies the calculated offset to its local clock, either gradually (slewing) for small corrections or immediately (stepping) for large discrepancies, depending on configuration (e.g., Chrony’s makestep setting).

**Error Handling**: If the response fails authentication or contains invalid data (e.g., high jitter or stratum), the client discards it and may query another server from its configured pool, leveraging prioritized parallel querying for reliability.

**Setting or Verifying the Clock**: A charging station may also leave the discipline of its clock to the operating system, e.g. to chrony (section 3.4), and use NTS only to *verify* it. At every check it then measures the offset of its own clock against the servers of a group and decides whether its time is legal time (section 3.2.3), without setting the clock itself. This is an admissible variant of the process above, and a well auditable one: the metrological log records not what the clock was set to, but how far the clock was from the legal time sources, measured with authenticated responses. The thresholds below then apply to the measured offset instead of to a correction. *Reference implementation*: verifies; the clock is set by the operating system.

**Logging and Compliance**: For OCPP charging stations, the client logs synchronization events (e.g., successful updates or failures) to support regulatory audits, particularly for time-based or dynamic tariffs requiring traceable time sources. Three quantities must be kept apart:
- The **correction** of the station's clock or, where the clock is only verified, its measured **offset**. One equal to or greater than a threshold (e.g. 5 seconds) shall be logged as a security critical event and appended to the metrological log book. In OCPP v2.x this threshold is the standard variable `ClockCtrlr.TimeAdjustmentReportingThreshold`, and such a correction or offset is reported as the security event `SettingSystemTime` (sections 3.2.1 and 3.2.6).
- The **spread** between the servers of a group in one round: how far their answers are apart (`MaxDeviation`, section 3.2.3).
- The **tolerance**: how far the station's own clock may be from the time of the legal group and still count as legal time (`LegalTimeTolerance`, section 3.2.3).

**Notes**
- On 8 February 2036 the NTP era 1 begins. Converting NTP timestamps into system time and back needs particular care then.
- On 19 January 2038 at 03:14:08 UTC, implementations that count seconds in signed 32 bit integers overflow.
- Where leap second announcements are evaluated when converting into system time, the synchronization with the system time needs particular care.
- [RFC 5905](https://datatracker.ietf.org/doc/html/rfc5905) Appendix A.5.1 and A.5.1.1 give hints on checking received messages for plausibility before they are used for time synchronization.


## 3. Network Time Security OCPP Client Configuration

OCPP v1.6+SE and v2.x are very different in the way a charging station is configured. While OCPP v1.x uses a simple Key-Value-Store for configuration data OCPP v2.x provides its own Device Model. At the time of writing this white paper OCPP v1.6 still has by far the largest market share, so we have to provide solutions for both.

Since OCPP time synchronization serves two main use cases: ***legal time*** for billing and ***local time*** for load balancing, many settings are organized around these purposes and can differ significantly. In practice, it is often beneficial to synchronize local time every few seconds, whereas legal time may only need to be synchronized once or twice per hour, or on demand, e.g. shortly before scheduled dynamic tariff changes will be applied.

**Logging.** Each group of time servers (section 3.2.3) writes to one log: the **secure metrological log** (section 4) for the legal group, the **security log** for every other group. This applies to
- every change of the configuration of the group, naming what changed and who changed it: the CSMS via OCPP, a local web interface, a service technician,
- every new, changed or refused certificate of one of its servers, and every pin mismatch (section 3.2.4),
- the start and the end of a run of failed measurements (`ErrorLogging`, `MaxErrors`), and every spread equal to or greater than `MaxDeviation`.

Changes of the root CA certificates for time servers (`NetworkTimeRootCertificate`, section 3.2.5) are always written to the secure metrological log, because they decide which servers can vouch for the legal time.

**Who may change the legal group.** The CSMS may change the legal group via OCPP like any other group; there is no switch that locks it. What protects legal time is not a lock but the record: every change of the legal group is an entry in the metrological log that names who made it, and changes made by anybody but the CSMS are reported to the CSMS (section 3.2.6).



### 3.1 OCPP vNext Client Configuration

### 3.2 OCPP v2.x Client Configuration

OCPP v2.x already has the standard component `ClockCtrlr`, with one list of NTP servers. This paper adds three logical components for groups of time servers, and relates `ClockCtrlr` to them:

| Component | Instance | What it holds | How instances come and go |
|-----------|----------|---------------|---------------------------|
| `ClockCtrlr` *(OCPP standard)* | none | The clock of the charging station, and the legal group as a CSMS sees it that does not know this paper. | fixed |
| `NTPController` | none | Time synchronization as a whole: which groups exist, and whether the time is legal time. | fixed |
| `NTPClientGroupController` | the group id, e.g. `legal`, `local` | One group of time servers: its quorum, its schedule, its error handling. | via `NTPController.ClientGroups` |
| `NTPClientController` | the client id | One time server of exactly one group. | via `NTPClientGroupController.Clients` |

The names of the new components end in `…Controller` rather than in the `…Ctrlr` of the standard components, as in earlier versions of this paper and in its reference implementation. The components of the [Secure Name Resolution](../SecureDNS/README.md) white paper are named alike.

**Creating and removing instances.** The Device Model has no way to create component instances via *SetVariablesRequest*. Groups and clients therefore come into existence through a list variable of the component above them: a new id in `NTPController.ClientGroups` creates a group, a new id in `NTPClientGroupController.Clients` creates a client of that group, and an id taken out of such a list removes the instance. A *GetBaseReportRequest* afterwards reports the new instances. Ids are case-insensitive strings of at most 50 characters, the length of a component instance in OCPP. A client id is unique across all groups. It should not be derived from the host name of its server, because a new host name would then rename the instance.

**A client belongs to exactly one group.** In earlier versions of this paper groups could share clients. But the priorities of clients are only meaningful within one group, and the quorum and the error counters belong to the group, so a client shared by two groups would have to mean two things at once. When two groups are to ask the same server, each of them gets a client of its own for it.

**Lists.** The value of a list variable of this paper (`ClientGroups`, `Clients`, `CertificatePins`, `RootPins`) is a comma separated list and not a `MemberList`, because a `MemberList` only takes values of its `valuesList`. Writing a list is limited by `SetVariableData.attributeValue` (1000 characters in OCPP 2.0.1, 2500 in OCPP 2.1), reading it by `ReportingValueSize`.

*Reference implementation*: The column *Reference Implementation* of the following tables names the key of the configuration section `nts.groups.<group id>` of [WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node/blob/master/WWCP_Node/Configuration/NTSConfiguration.cs) that a variable is read from and written to. The web interface, the HTTP API and OCPP all change this one section, so they can never disagree. Group ids are lower case letters, digits and hyphens, beginning with a letter, at most 32 characters. A client is an entry of the group's `servers` list, identified by its `id` (*not implemented yet*: by its host name). Two clients with the same host name share their NTS-KE state: cookies, keys and certificate judgements.


#### 3.2.1 Clock Controller

A CSMS that does not know this paper knows only the standard component `ClockCtrlr`. The charging station fills it from the legal group, so that every CSMS sees where the legal time comes from, and it takes changes of `NtpServerUri` into the legal group.

| Variable Name | Relation to this paper |
|---------------|------------------------|
| DateTime | The clock of the charging station. |
| TimeSource | Contains `NTP` while the legal group is enabled. The source is decided by the groups of this paper, so a value other than the current one may be `Rejected`. |
| NtpSource | `manual`: the servers are those of the legal group, not ones received via DHCP. |
| NtpServerUri | The enabled clients of the legal group, by position (see below). |
| TimeAdjustmentReportingThreshold | The threshold of section 2.2: a correction of the clock, or a measured offset, equal to or greater than this many seconds is logged in the metrological log and reported as the security event `SettingSystemTime` (section 3.2.6). |
| TimeOffset, TimeZone, NextTimeOffsetTransitionDateTime | Local time; not affected by this paper. |

**Writing `NtpServerUri`.** In OCPP the instance of `NtpServerUri` is a single digit, the NTP priority (1 = highest). A group, however, asks the clients of one `Priority` together, and their answers must reach the quorum `MinServers` on their own (section 3.2.3). A priority of its own for every server would make sets of one server, which never reach a quorum of two. The instance therefore stands for the position in the order in which the legal group asks its clients: by `Priority`, then in the order of `Clients`.

- `NtpServerUri[k]` is the k-th enabled client of the legal group, written as `nts://` and its `ServerURL`, followed by `:` and its `NTSKEServerPort` when that is not 4460. Up to nine clients are shown. When fewer than nine are enabled, the next instance is reported with an empty value, so that a CSMS sees where a server can be added.
- Setting `[k]` of an existing client replaces its `ServerURL`, and its `NTSKEServerPort` when the value names a port. The client keeps its id, its `Priority`, its `RootCAs` and `RootPins`, `OnPinMismatch` and `TrustOnFirstUse`. It loses its `CertificatePins`, which name a certificate of the old server.
- Setting the first empty instance adds an enabled client with that server, in mode `NTSv4`, with the default ports and with the `Priority` of the last client, so that it counts towards the same quorum. Setting an instance beyond it is `Rejected`.
- Setting `[k]` to `""` removes the k-th client; the clients behind it move up one position.
- Values are host names, IP addresses, or `nts://` followed by one of them and an optional `:port`. `ntp://` and every other scheme are `Rejected` with `reasonCode` `InvalidValue`: the legal group must not use NTP without NTS (`Mode`, section 3.2.4).
- Every change of `NtpServerUri` is applied on its own, so a CSMS can use `IndependentRequests`. A change is `Rejected` when it would leave fewer enabled clients than `MinServers`.

What `NtpServerUri` cannot express, such as further priorities, the NTP port, pins, the quorum or more than nine servers, is changed via the components of this paper.


#### 3.2.2 NTP Controller

The component `NTPController` has no instance. It holds what applies to time synchronization as a whole.

| Variable Name     | req/opt  | Mutability | Data Type  | Default Value | Values List / Limits | Description | Reference Implementation |
|-------------------|----------|------------|------------|---------------|----------------------|-------------|--------------------------|
| ClientGroups      | required | rw         | string     | "legal"       | comma separated ids, each ≤ 50 characters | The ids of the `NTPClientGroupController` instances. A new id creates a group, disabled and without clients. An id taken out removes the group; this is `Rejected` while the group is enabled. | the groups of `nts.groups` |
| SuggestedGroups   | optional | ro         | string     | "local"       | comma separated ids  | Group ids the charging station knows a meaning for and does not have yet. | `legal`, `local` and `grid`, minus the existing groups |
| LegalTime         | optional | ro         | boolean    | false         | -                    | Whether the time of the charging station is legal time now (section 3.2.3). Can be monitored. | `legal` of the clock |
| LegalTimeReason   | optional | ro         | OptionList | ""            | `NotClaimed`, `Disabled`, `NeverChecked`, `Stale`, `OffBy` | Why the time is not legal time: the legal group names no `LegalTimeAuthority`, it is disabled, it was never checked, its last check is older than `LegalTimeMaxAge`, or the clock was further than `LegalTimeTolerance` from it. Empty while the time is legal time. | `why` of the clock: `notClaimed`, `ntsOff`, `neverChecked`, `stale`, `offBy` |


#### 3.2.3 NTP Client Group Controller

The *Instance* of the component is the group id. Well-known ids are:
- `legal`: the group whose time is legal time, e.g. the time servers of a national metrology institute. Dynamic tariffs and everything else calibration law rests on use its time.
- `local`: servers on site, e.g. OCPP Local Controllers acting as auxiliary NTS servers, for a time that is consistent across the charging stations of a location, e.g. for local load management.

Further groups may be defined, e.g. `grid` for the time source of a grid operator.

**Rounds.** The clients of a group are asked together, in rounds. A round asks the enabled clients of the lowest `Priority` in parallel. When fewer than `MinServers` of them answer, the clients of the next priority are asked, and so on. The time of the round is that of the first priority whose answers reach the quorum. When none does, the round fails, and counts as a measurement error for `ErrorLogging` and `MaxErrors`.

**Legal time.** The time of the charging station is legal time only while all of the following hold; otherwise it is not, and `NTPController.LegalTimeReason` says why:
- the legal group names a `LegalTimeAuthority`: the operator states who stands behind its servers, which the charging station cannot find out by itself;
- the legal group is enabled;
- its last round that produced a time is no older than `LegalTimeMaxAge`;
- in that round, the clock of the charging station was no further than `LegalTimeTolerance` from the time of the group.

A time that is not legal time must not be used for anything calibration law rests on: correctness takes precedence over continuity (*fail closed*, [Critical Legal Time Services](../CriticalLegalTimeServices/README.md) section 1.4).

The variables marked *legal only* exist only in the instance `legal`; in any other instance they are `UnknownVariable`.

| Variable Name      | req/opt  | Mutability | Data Type  | Default Value | Values List / Limits | Description | Reference Implementation |
|--------------------|----------|------------|------------|---------------|----------------------|-------------|--------------------------|
| Enabled            | optional | rw         | boolean    | true          | -                    | Whether the group is asked. A disabled group keeps its clients. A group created via `NTPController.ClientGroups` starts disabled, and a group must be disabled before it is removed. | `enabled` |
| Clients            | required | rw         | string     | ""            | comma separated client ids | The ids of the `NTPClientController` instances of this group. A new id creates a client, which needs its `ServerURL` in the same request (section 3.2.5). An id taken out removes the client. The order is the order in which clients of the same `Priority` are listed (section 3.2.1); it is not a priority. | the entries of `servers` |
| MinServers         | optional | rw         | integer    | 2             | 1 … 255              | The quorum: how many clients of one priority must answer in a round for its time to count. A change that leaves an enabled group with fewer enabled clients is `Rejected`. | `minServers`; when not set, lowered to the number of enabled clients |
| MaxDeviation       | optional | rw         | decimal    | 60            | 0.001 … 3600 (s)     | The spread between the answers of one round that is accepted silently: the difference between the largest and the smallest offset the clients of the deciding priority gave. A spread equal to or greater than it is recorded in the log of the group. It is not the offset of the station's own clock, which is held to `LegalTimeTolerance`. Unit: `s`. | `maxDeviationSeconds` |
| MinInterval        | optional | rw         | integer    | -             | 10 … 86400 (s)       | The shortest time between the start of two rounds. Unit: `s`. | `checkEverySeconds` (see `MaxInterval`) |
| MaxInterval        | optional | rw         | integer    | -             | 10 … 86400 (s)       | The longest time between the start of two rounds. Each round is due at a random time between `MinInterval` and `MaxInterval` after the last one, so that many charging stations do not ask the same servers at the same moment. For the legal group, `MaxInterval` shall be shorter than `LegalTimeMaxAge`, or the time ceases to be legal time between two rounds. Unit: `s`. | `checkEverySeconds`, 900 s when not set: one fixed period. Both variables are reported as it, and only the same value can be written to both, in one `ACID` request. |
| Preflight          | optional | rw         | integer    | -             | 1 … 86400 (s)        | Occasional requests to an NTP/NTS server may be delayed by network caching effects such as ARP or DNS resolution, firewall state establishment or TLS tunnel setup. After this long without a round, every client is first sent a *preflight* NTP packet whose response is ignored, so that these delays stay out of the measurement. Not set: no preflight packets. Unit: `s`. | *not implemented* |
| Timeout            | optional | rw         | decimal    | -             | 0.1 … 3600 (s)       | How long one exchange with a client may take. Unit: `s`. | `timeoutSeconds`, 10 s when not set |
| ErrorLogging       | optional | rw         | integer    | 5             | 1 … 65535            | The number of consecutive failed rounds that leads to an entry in the log of the group (section 3). When a round produces a time again, another entry is added. | `errorLogging` |
| MaxErrors          | optional | rw         | integer    | 10; 50 for `local` | 1 … 65535       | The number of consecutive failed rounds after which what rests on the time of the group is limited, until a round produces a time again: dynamic tariff changes for the legal group, load management for the local group. The start and the end are entered in the log of the group, shown by `Limited` and reported as security events (section 3.2.6). | `maxErrors` |
| Limited            | optional | ro         | boolean    | false         | -                    | `true` from the moment `MaxErrors` is reached until a round produces a time again. Can be monitored. | `limited` |
| ErrorsInARow       | optional | ro         | integer    | 0             | -                    | The number of consecutive failed rounds so far. | `errorsInARow` |
| LastCheck          | optional | ro         | dateTime   | -             | -                    | When the last round that produced a time took place. | `checkedAt` |
| LastOffset         | optional | ro         | decimal    | -             | -                    | The offset of the station's clock against the time of that round. Unit: `s`. | `offset_ms`, in milliseconds |
| LegalTimeAuthority | optional, *legal only* | rw | string | ""        | ≤ 80 characters      | Who stands behind the time of the group, e.g. `"PTB"`. Without it the time is not legal time. An empty value removes it. | `legalTimeAuthority` |
| LegalTimeTolerance | optional, *legal only* | rw | decimal | 1        | 0.001 … 60 (s)       | How far the station's own clock may be from the time of the group and still be legal time. Unit: `s`. | `legalTimeToleranceSeconds` |
| LegalTimeMaxAge    | optional, *legal only* | rw | integer | 3600     | 10 … 86400 (s)       | How old the last round that produced a time may be and still be legal time. PTB-A 50.7, section 3.1.7, recommends connecting to the PTB time servers hourly. Unit: `s`. | `legalTimeMaxAgeSeconds` |

See also: [C# Reference Implementation](https://github.com/OpenChargingCloud/WWCP_OCPP/blob/master/WWCP_OCPPv2.1/Components/Logical/NTPClientGroupController.cs)


#### 3.2.4 NTP Client Controller

The *Instance* of the component is the client id (section 3.2). A client is one time server of exactly one group, and is listed in that group's `Clients`.

| Variable Name     | req/opt  | Mutability | Data Type  | Default Value | Values List / Limits | Description | Reference Implementation |
|-------------------|----------|------------|------------|---------------|----------------------|-------------|--------------------------|
| Enabled           | optional | rw         | boolean    | true          | -                    | Whether the client is asked. A disabled client keeps its configuration. | `servers[n].enabled` |
| ServerURL         | required | rw         | string     | ""            | ≤ 253 characters     | The server to ask, as a host name or an IP address, not a URL. In mode *NTSv4* this is the NTS-KE server, unless *NTSKEServerURL* names another one. The NTP server is then the one the NTS-KE response names (NTPv4 Server Negotiation, RFC 8915 §4.1.7), or the address of the NTS-KE server when the response names none. In modes *NTPv4* and *NTPv4TLS* it is the NTP server. May depend on the device’s country or location. | `servers[n].hostname`, the NTS-KE server |
| ServerPort        | optional | rw         | integer    | 123           | 1 … 65535            | The NTP port. In mode *NTSv4* the port the NTS-KE response names (NTPv4 Port Negotiation, RFC 8915 §4.1.8) takes precedence, and this value is only what the client asks for. | `servers[n].ntpPort` |
| Mode              | optional | rw         | OptionList | `NTSv4`       | `NTPv4`, `NTSv4`, `NTPv4TLS` | `NTSv4`: NTS ([RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915)). `NTPv4TLS`: NTP over TLS to a smart meter gateway (section 6). `NTPv4`: NTP without any authentication. Clients of the legal group MUST NOT use `NTPv4`; other clients should not, unless further security measures protect it. The `valuesList` shall list only what the charging station supports. | `NTSv4` only |
| Priority          | optional | rw         | integer    | 0             | 0 … 255              | Clients with lower values are asked first. Clients with the same value are asked in parallel, and their answers must reach the quorum of the group on their own (section 3.2.3). | `servers[n].priority` |
| DelayAsymmetry    | optional | rw         | decimal    | 0             | -                    | A correction applied to the offsets measured with this server, to compensate known stable asymmetries in network or processing delays. For example, if packets sent to the server were on average delayed by 100 microseconds more than packets sent back, the correction would be -0.05 (-50 microseconds). Unit: `ms`. | *not implemented* |
| DelayVarAsymmetry | optional | rw         | decimal    | 0             | -                    | Fine-tunes the offset calculation when the variability of network delays is greater in one direction than in the other. Use only if the network is known to have a consistent asymmetry. | *not implemented* |
| NTSKEServerURL    | optional | rw         | string     | ""            | ≤ 253 characters     | An NTS-KE server other than *ServerURL*, as a host name or an IP address. When it is set in mode *NTSv4*, the client asks this server for the keys and cookies, and asks for *ServerURL* as its NTP server (NTPv4 Server Negotiation in the request). The NTP server it then uses is still the one the NTS-KE response names, or the address of this NTS-KE server when the response names none (RFC 8915 §4.1.7). When it is empty, *ServerURL* is the NTS-KE server. | *not implemented*: the NTS-KE server is `hostname` |
| NTSKEServerPort   | optional | rw         | integer    | 4460          | 1 … 65535            | The NTS-KE port. | `servers[n].ntsKEPort` |
| RootCAs           | optional | rw         | string     | ""            | ≤ 50 characters      | The `certificateGroup` of `NetworkTimeRootCertificate` root CAs (section 3.2.5) the certificate of the NTS-KE or NTP-over-TLS server must chain to. When it is not set, every `NetworkTimeRootCertificate` root CA may vouch for the server, and when there are none, the root CAs of the system (not recommended). | *not implemented*: root pins instead |
| CertificatePins   | optional | rw         | string     | ""            | comma separated, ≤ 16 | SHA-256 fingerprints (64 hexadecimal digits, with or without colons) of the certificates the server may show. Only for *NTSv4* and *NTPv4TLS*. | `servers[n].certificates` |
| RootPins          | optional | rw         | string     | ""            | comma separated, ≤ 16 | SHA-256 fingerprints of the root CA certificates the server's chain may end at. Only for *NTSv4* and *NTPv4TLS*. | `servers[n].roots` |
| OnPinMismatch     | optional | rw         | OptionList | `Refuse`      | `Refuse`, `Record`, `Accept` | What a pin mismatch leads to. `Refuse`: the server is not used. `Record`: it is used, and the mismatch is entered in the secure metrological log as evidence. `Accept`: it is used, and the mismatch is entered in the log of the group. | `servers[n].onMismatch`; every mismatch of a time server is entered in the metrological log |
| TrustOnFirstUse   | optional | rw         | OptionList | `None`        | `None`, `Root`, `Certificate` | Whether the client learns a root pin or a certificate pin from the first certificate the server is believed with. When a pin of that kind is set already, nothing is learned. | `servers[n].trustOnFirstUse` |
| NoCertTimeCheckAfterReboot | optional | rw | boolean  | false         | -                    | Whether the *notBefore* and *notAfter* checks of NTS-KE and NTP-over-TLS server certificates can be skipped for the first time sync request per server immediately after a reboot, as the device might have started with a wrong internal time, e.g. due to not having an RTC or backup battery. | *not implemented* |
| MinRefresh        | optional | rw         | integer    | 43200         | ≥ 60 (s)             | The time since the last NTS-KE handshake after which a new one is started, at a random time between `MinRefresh` and `MaxRefresh`. Unit: `s`. | 1800 s, fixed |
| MaxRefresh        | optional | rw         | integer    | 86400         | ≥ `MinRefresh` (s)   | The time since the last NTS-KE handshake within which a new one must have succeeded. Unit: `s`. | 1800 s, fixed |
| AEADAlgorithm     | optional | rw         | OptionList | `AES-SIV-CMAC-256` | `AES-SIV-CMAC-256`, `AES-128-GCM-SIV` | The Authenticated Encryption with Associated Data (AEAD) algorithm the client offers for NTS authentication of NTP messages. | *read-only*: the algorithm the server chose, from both offered |
| SignedResponses   | optional | rw         | boolean    | false         | -                    | Whether a digitally signed second response is requested (section 1). | *not implemented* |
| Problem           | optional | ro         | boolean    | false         | -                    | `true` while the last NTS-KE handshake with this server was refused, or its last exchange failed. Standardized variable name of OCPP; can be monitored. | last judgement |
| CertificateFingerprint | optional | ro    | string     | ""            | -                    | The SHA-256 fingerprint of the certificate the server showed at its last NTS-KE handshake. | last key exchange |
| LastKeyExchange   | optional | ro         | dateTime   | -             | -                    | When the last NTS-KE handshake with this server succeeded. | last key exchange |
| Cookies           | optional | ro         | integer    | 0             | -                    | The number of unused NTS cookies the client holds for this server. | `cookies` |

In earlier versions of this paper, `MinInterval`, `MaxInterval`, `Preflight` and `ErrorLogging` were variables of each client. A quorum needs the clients of a group to be asked in the same round, so they are variables of the group now (section 3.2.3).

**Pins.** `CertificatePins` and `RootPins` narrow what `RootCAs` allows and never widen it. When *trust on first use* learns a pin, the value of `CertificatePins` or `RootPins` changes without a request of the CSMS; a CSMS that wants to know sets a `Delta` monitor on them. Pins, `OnPinMismatch` and `TrustOnFirstUse` mean the same as for name servers in the [Secure Name Resolution](../SecureDNS/README.md) white paper (section 2.3). As there, a fingerprint is the SHA-256 hash of the whole certificate, not of its public key.

**Refreshing NTS-KE.** The NTS-KE handshake is the only moment at which a client checks the certificate of its server: its name, its chain and its pins. Cookies alone would keep a client going for much longer, because every NTS-protected response brings a fresh one. A new handshake about once a day keeps a replaced server certificate from going unnoticed for longer than that, renews the C2S and S2C keys, and still keeps the load of TLS handshakes on public time servers low. Hence the defaults of 12 and 24 hours, with a random time in between, so that many charging stations do not reach the same servers at the same moment. A client whose cookies run out or are refused makes a new handshake at once, whatever these values say. Earlier versions of this paper gave these values in days (30 and 60) for OCPP v1.6; they are given in seconds now, for both OCPP versions.

See also: [C# Reference Implementation](https://github.com/OpenChargingCloud/WWCP_OCPP/blob/master/WWCP_OCPPv2.1/Components/Logical/NTPClientController.cs), and the configuration of a server in [WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node/blob/master/WWCP_Node/Configuration/NTSServerConfiguration.cs) with its [pins](https://github.com/OpenChargingCloud/WWCP_Node/blob/master/WWCP_Node/Configuration/ServerPins.cs)


#### 3.2.5 OCPP v2.x Command Extensions

*SetVariablesRequest*

Several variables of a group depend on each other: `MinServers` on the number of enabled clients, a new client on its `ServerURL`, the removal of a group on its being disabled. Applied one by one, the same changes succeed or fail depending on the order of the *SetVariableData* entries. Therefore:

- **`IndependentRequests`** (standard OCPP, and the default): the entries are applied one by one, in the order of the request, each validated against the configuration as it is after the entries before it, each with its own result. A CSMS has to order them: enable clients before it raises `MinServers`, and lower `MinServers` before it disables clients. A new client id in `Clients` is `Rejected`, because a client cannot exist without its `ServerURL`; its `additionalInfo` says to use `ACID`. A server can still be added to the legal group via `ClockCtrlr.NtpServerUri` (section 3.2.1).
- **`ACID`** (the *DataConsistencyModel* of [Safe & Secure Device Model Updates](../SafeAndSecureDeviceModelUpdates/README.md)): all entries of the request that address `ClockCtrlr.NtpServerUri` or a component of this paper are validated and applied as **one change**. Groups added via `NTPController.ClientGroups` are created first, groups taken out of it are removed last. Either all entries are `Accepted`, or the entries that caused the refusal are `Rejected` and all others `Rolledback`.
- **`BASE`**: like `ACID`, but each group, together with its clients, is one change of its own.
- A refused entry is `Rejected`, and its `statusInfo.additionalInfo` says what is wrong. Entries that are wrong by themselves get the usual results: `UnknownComponent`, `UnknownVariable` (e.g. for a *legal only* variable of another group), `NotSupportedAttributeType` for anything but `Actual`, `Rejected` with `reasonCode` `ReadOnly` for a read-only variable, `InvalidValue` for a value that cannot be parsed and `ValueOutOfRange` for one out of range.
- An entry that names the value it expects to replace (conditional update, Safe & Secure Device Model Updates) is `Rejected` when the current value differs, e.g. because it was changed via a local web interface in the meantime.
- A change that could not be persisted SHALL be rejected with `reasonCode` `InternalError`, and SHALL NOT be put into effect: what is in effect must survive a reboot.
- Changes take effect at once, without a reboot.
- The CSMS may change every writable variable of the legal group. Every such change is an entry in the secure metrological log (section 3).

*InstallCertificateRequest*

The following defines a small extension for the *InstallCertificateRequest*. The *CertificateUseEnumType* had been extended by *"NetworkTimeRootCertificate"*. The new *certificateGroup* property allows to group rootCAs of the same *CertificateUseEnumType*. Such a rootCA group can later specify which root CAs should be used to validate the TLS certificate presented by a TLS server configured in the network settings.

Different certificates of the same type and group will be combined into a single set. Duplicate certificates will be silently ignored.

The same certificate can belong to multiple groups, but must be uploaded separately for each group.

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
                "NetworkTimeRootCertificate"
            ]
        },
        "CustomDataType": {
            "description": "This class does not get 'AdditionalProperties = false' in the schema generation, so it can be extended with arbitrary JSON properties to allow adding custom data.",
            "javaType": "CustomData",
            "type": "object",
            "properties": {
                "vendorId": {
                    "type": "string",
                    "maxLength": 255
                }
            },
            "required": [
                "vendorId"
            ]
        }
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

See also: [C# Reference Implementation](https://github.com/OpenChargingCloud/WWCP_OCPP/blob/master/WWCP_OCPPv2.1/Messages/Certificates/InstallCertificateRequest.cs)

*GetInstalledCertificateIdsRequest* and *DeleteCertificateRequest* accept the type `NetworkTimeRootCertificate` as well. Installing or deleting such a root CA is an entry in the secure metrological log (section 3).

*Reference implementation*: Root CAs for time servers are TLS roots of the node's certificate store with the usage `nts`. Instead of root CA groups per server, the reference implementation holds servers to root pins.


#### 3.2.6 Security Events and Monitoring

The following *SecurityEventNotificationRequest* types are used. `SettingSystemTime` and `ReconfigurationOfSecurityParameters` are security events of OCPP 2.x; the others are proposed by this paper.

| Type | When |
|------|------|
| `SettingSystemTime` | A correction of the clock, or a measured offset of it, equal to or greater than `ClockCtrlr.TimeAdjustmentReportingThreshold` (section 2.2). The `techInfo` gives the offset. |
| `ReconfigurationOfSecurityParameters` | The configuration of a group was changed by anybody but the CSMS itself, e.g. via a local web interface, or a pin was learned on first use. The `techInfo` says what changed; the log has it in full. |
| `LegalTimeLimited` | The legal group reached `MaxErrors`. |
| `LegalTimeRestored` | A round of the legal group produced a time again after it had reached `MaxErrors`. |
| `InvalidTimeServerCertificate` | An NTS-KE or NTP-over-TLS handshake was refused: wrong name, untrusted chain, or a pin mismatch with `OnPinMismatch = Refuse`. Sent once per change of the verdict, not at every attempt. |
| `TimeServerCertificateChanged` | A server was believed with another certificate or root CA than before. |

`NTPController.LegalTime`, `NTPClientGroupController.Limited` and `NTPClientController.Problem` are meant to be monitored: a CSMS sets a `Delta` monitor on them via *SetVariableMonitoringRequest* and receives a *NotifyEventRequest* when they change.


### 3.3 OCPP v1.6+SE Client Configuration

The following tables map the configuration of section 3.2 onto OCPP v1.6+SE configuration keys. A key `ntp.<group>.<name>` or `ntske.<group>.<name>` belongs to the group of that id. The groups of OCPP v1.6 are the well-known ones, `legal` and `local`. Further groups use the same keys with their own id, where a charging station has them, but they cannot be created via OCPP v1.6.

If a CSL (comma separated list) configuration setting is shorter than expected, e.g. the `ntp.legal.ports` list is shorter than the `ntp.legal.servers` list, the last value in the list is applied to all remaining items (here: servers). Empty entries are filled with the previous value, starting from the default value. Lists that are longer than expected will result in an error.

Servers and ports mean what they mean in section 3.2.4. In mode *NTSv4* the NTS-KE servers are those of `ntske.<group>.servers`, or those of `ntp.<group>.servers` when it is empty. The NTP server finally used is the one the NTS-KE response names.

A *ChangeConfiguration.req* changes one key at a time, so changes cannot be bundled as with `ACID` (section 3.2.5). A charging station SHALL therefore validate each key against the configuration as it would be after the change, and SHALL answer `Rejected` when the result would be inconsistent, e.g. fewer servers than `ntp.legal.minServers`. A CSMS has to change keys in an admissible order: add servers before it raises `minServers`, and lower `minServers` before it removes servers. In OCPP v1.6 `Rejected` carries no reason. The logging rules of section 3 apply unchanged: every change of a key of the legal group is an entry in the secure metrological log.

*Reference implementation*: the keys of this section are not implemented yet.

#### 3.3.1 Common Configuration Keys

| Key Name      | req/opt  | Accessibility | Type       | Default Value | Example        | Description |
|---------------|----------|---------------|------------|---------------|----------------|-------------|
| ntp.reboot.allowJumps | optional | rw | Boolean | true          | -              | Allows immediate correction of large time discrepancies during the first synchronization steps after a reboot. |
| ntp.reboot.noCertTimeCheck | optional | rw | Boolean | false     | -              | Whether the *notBefore* and *notAfter* checks of NTS-KE and NTP-over-TLS server certificates can be skipped for the first time sync request per server immediately after a reboot, as the device might have started with a wrong internal time, e.g. due to not having an RTC or backup battery. |
| ntp.timeAdjustmentReportingThreshold | optional | rw | Integer | 5 | -           | Corrections of the clock, or measured offsets of it, of at least this many seconds are logged in the metrological log and reported as the security event `SettingSystemTime`. See `ClockCtrlr.TimeAdjustmentReportingThreshold` (section 3.2.1). |

The global key `ntp.enabled` of earlier versions of this paper is replaced by `ntp.<group>.enabled`.


#### 3.3.2 *Legal Group* Configuration Keys

| Key Name      | req/opt  | Accessibility | Type       | Default Value | Example        | Description |
|---------------|----------|---------------|------------|---------------|----------------|-------------|
| ntp.legal.enabled | required | rw          | Boolean    | true          | -              | Whether the legal group is asked. See `NTPClientGroupController.Enabled`. |
| ntp.legal.servers | optional | rw          | CSL String | ""            | "ptbtime1.ptb.de, ptbtime2.ptb.de, ptbtime3.ptb.de" | The legally recognized time servers, which may vary depending on the device’s country or location. See `NTPClientController.ServerURL`. |
| ntp.legal.ports   | optional | rw          | CSL String | "123"         | "123, 125"     | The NTP ports, per server. |
| ntp.legal.mode    | required | rw          | String     | "NTSv4"       | -              | `NTSv4` or `NTPv4TLS`. `NTPv4` MUST NOT be used for the legal group. See `NTPClientController.Mode`. |
| ntp.legal.priority | optional | rw         | CSL String | "0"           | "0, 0, 10"     | The priority, per server: servers with lower values are asked first, servers with the same value in parallel (section 3.2.3). |
| ntp.legal.delayAsym | optional | rw        | CSL String | "0"           | "0, -0.05"     | The delay asymmetry correction, per server, in milliseconds. See `NTPClientController.DelayAsymmetry`. |
| ntp.legal.delayVarAsym | optional | rw     | CSL String | "0"           | "+0.5, 0, -0.5" | See `NTPClientController.DelayVarAsymmetry`, per server. |
| ntp.legal.minInterval | optional | rw      | Integer    | 30            | 600            | The shortest time between two rounds, in seconds. See `NTPClientGroupController.MinInterval`. |
| ntp.legal.maxInterval | optional | rw      | Integer    | 1800          | 1800           | The longest time between two rounds, in seconds; shorter than `ntp.legal.maxAge`. See `NTPClientGroupController.MaxInterval`. |
| ntp.legal.preflight | optional | rw        | Integer    | -             | 60             | After this many seconds without a round, preflight packets are sent first. See `NTPClientGroupController.Preflight`. |
| ntp.legal.timeout | optional | rw          | Decimal    | -             | 3              | How long one exchange may take, in seconds. See `NTPClientGroupController.Timeout`. |
| ntp.legal.minServers | optional | rw       | Integer    | 2             | 3              | The quorum: how many servers of one priority must answer. See `NTPClientGroupController.MinServers`. |
| ntp.legal.maxDeviation | optional | rw     | Decimal    | 60            | 0.5            | The spread between the answers of one round, in seconds, that is accepted silently; a spread equal to or greater than it is recorded in the secure metrological log. See `NTPClientGroupController.MaxDeviation`. |
| ntp.legal.errorLogging | optional | rw     | Integer    | 5             | 10             | The number of consecutive failed rounds that leads to an entry in the secure metrological log. When a round produces a time again, another entry is added. |
| ntp.legal.maxErrors | optional | rw        | Integer    | 10            | 20             | The number of consecutive failed rounds that leads to limited charging session features, e.g. dynamic tariff changes are no longer available, and an entry in the secure metrological log. When a round produces a time again, another entry is added. |
| ntp.legal.authority | optional | rw        | String     | ""            | "PTB"          | Who stands behind the time of the legal group. Without it the time is not legal time. See `NTPClientGroupController.LegalTimeAuthority`. |
| ntp.legal.tolerance | optional | rw        | Decimal    | 1             | 0.5            | How far the station's own clock may be from the time of the legal group and still be legal time, in seconds. See `NTPClientGroupController.LegalTimeTolerance`. |
| ntp.legal.maxAge  | optional | rw          | Integer    | 3600          | 3600           | How old the last round that produced a time may be and still be legal time, in seconds. See `NTPClientGroupController.LegalTimeMaxAge`. |
| ntske.legal.servers | optional | rw        | CSL String | ""            | "ntske1.example.org, ntske2.example.org" | The NTS-KE servers, per server. When empty and the mode is NTSv4, the servers of `ntp.legal.servers` are used. See `NTPClientController.NTSKEServerURL`. |
| ntske.legal.ports | optional | rw          | CSL String | "4460"        | "4460, 4461"   | The NTS-KE ports, per server. |
| ntp.legal.rootCAs | optional | rw          | CSL String | ""            | "legalTimeCA1, legalTimeCA1, legalTimeCA2" | The `certificateGroup` of `NetworkTimeRootCertificate` root CAs, per server. In the example the first two servers must chain to `legalTimeCA1`, the third to `legalTimeCA2`. When not set, every `NetworkTimeRootCertificate` root CA may vouch for the server, and when there are none, the root CAs of the system *(not recommended)*! |
| ntske.legal.certificatePins.*n* | optional | rw | CSL String | "" | "41C7…3F61"  | The certificate pins of the *n*-th server, numbered from 1 in the order of `ntp.legal.servers`. See `NTPClientController.CertificatePins`. |
| ntske.legal.rootPins.*n* | optional | rw  | CSL String | ""            | "9D2E…D8E"     | The root pins of the *n*-th server. See `NTPClientController.RootPins`. |
| ntske.legal.onPinMismatch | optional | rw | CSL String | "Refuse"     | "Refuse, Record" | Per server. See `NTPClientController.OnPinMismatch`. |
| ntske.legal.trustOnFirstUse | optional | rw | CSL String | "None"     | "Root, None"   | Per server. See `NTPClientController.TrustOnFirstUse`. |
| ntske.legal.minRefresh | optional | rw     | CSL String | "43200"       | "43200, 21600" | Per server, in seconds. See `NTPClientController.MinRefresh`. |
| ntske.legal.maxRefresh | optional | rw     | CSL String | "86400"       | "86400, 43200" | Per server, in seconds. See `NTPClientController.MaxRefresh`. |
| ntske.legal.aead  | optional | rw          | CSL String | "AES-SIV-CMAC-256" | "AES-SIV-CMAC-256, AES-128-GCM-SIV" | The AEAD algorithm, per server: `AES-SIV-CMAC-256` or `AES-128-GCM-SIV`. See `NTPClientController.AEADAlgorithm`. |
| ntp.legal.signedResponses | optional | rw  | Boolean    | false         | -              | Whether digitally signed responses are requested. See `NTPClientController.SignedResponses`. |

OCPP v1.6 limits a configuration value to 500 characters, so at most 7 fingerprints without colons fit into one pin key.


#### 3.3.3 *Local Group* Configuration Keys

The local group uses the keys of section 3.3.2 with `local` in place of `legal`, e.g. `ntske.local.ports`, except for `authority`, `tolerance` and `maxAge`, which exist for the legal group only. Its entries go to the security log, not to the secure metrological log (section 3). These keys differ from those of the legal group:

| Key Name      | req/opt  | Accessibility | Type       | Default Value | Example        | Description |
|---------------|----------|---------------|------------|---------------|----------------|-------------|
| ntp.local.enabled | required | rw          | Boolean    | false         | -              | Whether the local group is asked. |
| ntp.local.servers | optional | rw          | CSL String | ""            | "lc1.local, lc2.local" | Local time servers, e.g. running on OCPP Local Controllers, that shall be used as a shared local time source for use cases like *local load management*, for which having a consistent local time across devices is more important than having legal time accuracy. |
| ntp.local.mode    | required | rw          | String     | "NTSv4"       | -              | `NTSv4`, `NTPv4TLS` or `NTPv4`. `NTPv4` should not be used unless further security measures protect it. |
| ntp.local.maxInterval | optional | rw      | Integer    | 3600          | 60             | The longest time between two rounds, in seconds. |
| ntp.local.errorLogging | optional | rw     | Integer    | 5             | 10             | The number of consecutive failed rounds that leads to an entry in the security log. When a round produces a time again, another entry is added. |
| ntp.local.maxErrors | optional | rw        | Integer    | 50            | 100            | The number of consecutive failed rounds that leads to a stop of the load management feature and an entry in the security log. When a round produces a time again, another entry is added. |


#### 3.3.4 OCPP v1.6+SE Minimal Example

```
ntp.legal.enabled     =  true
ntp.legal.servers     = "ptbtime1.ptb.de, ptbtime2.ptb.de, ptbtime3.ptb.de"
ntp.legal.mode        = "NTSv4"
ntp.legal.rootCAs     = "legalTimeCA"
ntp.legal.minServers  =  2
ntp.legal.authority   = "PTB"
```


#### 3.3.5 OCPP v1.6+SE Command Extensions

*InstallCertificateRequest*

The following defines a small extension for the *InstallCertificateRequest* defined within the OCPP v1.6 Security Extensions. The *CertificateUseEnumType* had been extended by *"NetworkTimeRootCertificate"*. The new *certificateGroup* property allows to group rootCAs of the same *CertificateUseEnumType*. Such a rootCA group can later specify which root CAs should be used to validate the TLS certificate presented by a TLS server configured in the network settings.

Different certificates of the same type and group will be combined into a single set. Duplicate certificates will be silently ignored.

The same certificate can belong to multiple groups, but must be uploaded separately for each group.

```
{
  "$schema": "http://json-schema.org/draft-06/schema#",
  "$id": "urn:OCPP:Cp:1.6:2020:3:InstallCertificate.req",
  "definitions": {
    "CertificateUseEnumType": {
      "description": "Indicates the certificate type that is sent.",
      "type": "string",
      "additionalProperties": false,
      "enum": [
        "CentralSystemRootCertificate",
        "ManufacturerRootCertificate",
        "NetworkTimeRootCertificate"
      ]
    }
  },
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "certificateType": {
      "$ref": "#/definitions/CertificateUseEnumType"
    },
    "certificateGroup": {
      "description": "A X.509 certificate group.",
      "type": "string",
      "maxLength": 50
    },
    "certificate": {
      "description": "A PEM encoded X.509 certificate.",
      "type": "string",
      "maxLength": 5500
    }
  },
  "required": [
    "certificateType",
    "certificate"
  ]
}
```

See also: [C# Reference Implementation](https://github.com/OpenChargingCloud/WWCP_OCPP/blob/master/WWCP_OCPPv1.6/Messages/Certificates/InstallCertificateRequest.cs)


### 3.4 Example Configuration Using Chrony

Chrony is an Open Source NTP client compatible with NTS, suitable for e.g. Linux based charging stations and licensed under the GNU General Public License version 2. It can be used as an underlying software for rapid prototyping.

Below is an example configuration for a charging station supporting multiple NTS servers with prioritized parallel querying:

```
# /etc/chrony/chrony.conf
# Primary servers
server ptbtime1.ptb.de iburst nts minpoll 6 maxpoll 10 prefer certset 1
server ptbtime2.ptb.de iburst nts minpoll 6 maxpoll 10 prefer certset 1
server ptbtime3.ptb.de iburst nts minpoll 6 maxpoll 10 prefer certset 1
minsources 2

# Secondary servers
server time.cloudflare.com iburst nts minpoll 6 maxpoll 10 certset 2
server nts.netnod.se       iburst nts minpoll 6 maxpoll 10 certset 3

# Configuration options
authselectmode require
driftfile /var/run/chrony/drift
ntsdumpdir /var/run/chrony
makestep 1.0 3
rtcsync

# Limit NTS certificate verification
nosystemcert
ntstrustedcerts 1 /etc/chrony/certs/ptb_ca.pem
ntstrustedcerts 2 /etc/chrony/certs/cloudflare_ca.pem
ntstrustedcerts 3 /etc/chrony/certs/netnod_ca.pem
```

This configuration:
- Queries ptbtime1.ptb.de and ptbtime2.ptb.de in parallel, selecting the best based on performance metrics.
- `minsources 2` tells chronyd to refuse to update the clock until two sources are simultaneously selectable.
- Enables real-time clock synchronization and step corrections for large time offsets.

More about PTB time servers:
- https://www.ptb.de/cms/ptb/fachabteilungen/abt9/gruppe-95/ref-952/zeitsynchronisation-von-rechnern-mit-hilfe-des-network-time-protocol-ntp.html
- https://www.ptb.de/cms/ptb/fachabteilungen/abt4/fb-44/ag-442.html
- https://www.ptb.de/cms/ptb/fachabteilungen/abt4/fb-44/fragenzurzeit/fragenzurzeit07.html
- https://www.ptb.de/cms/ptb/fachabteilungen/abt9/gruppe-95/ref-952.html
- https://www.ptb.de/cms/ptb/fachabteilungen/abt9/gruppe-95/ref-952/zeitsynchronisation-technische-hinweise.html
- https://uhr.ptb.de/analog



## 4. Secure Metrological Log Book

Secure metrological log books, also known as audit trails or tamper-evident event logs, are an established requirement for energy meters subject to legal metrology in the European Union and other regulated markets. These log books are used to record all relevant events affecting measurement results or the operational integrity of the device. This includes configuration changes, firmware updates, clock adjustments, error conditions, and all interactions that could impact the accuracy, traceability, or legal validity of measured values. Log entries must be immutable, cryptographically secured, and accessible for inspection by market surveillance authorities, verification bodies, and—in some jurisdictions—end users.

With the anticipated extension of metrological requirements to electric vehicle charging stations, these principles will also apply to the entire charging system, not just the integrated energy meter. For charging station manufacturers, this means implementing secure logging mechanisms at the system level. All critical events—such as configuration or tariff changes, firmware updates, time synchronization actions, communication faults, and security-relevant incidents—must be logged in a manner that is resistant to tampering and unauthorized modification. This typically requires the use of cryptographic signatures (e.g., digital signatures or HMACs), hardware-backed secure storage, and controlled access rights.

Furthermore, the log book must provide a clear, chronological record of all relevant activities, with timestamps that are synchronized via a secure mechanism such as NTS. The log data must be protected against deletion or alteration, and, in case of device failure, there must be provisions for data export and recovery. Regulatory frameworks often require that these logs are retained for a defined period (e.g., at least the legally mandated retention time for metrological data) and that the log format is standardized and machine-readable to facilitate audits.

For manufacturers, this introduces additional design and certification challenges. Secure storage, cryptographic modules, and mechanisms for log export and inspection must be integrated into the charging station architecture. Existing field devices may require hardware or firmware upgrades to meet these requirements. Moreover, the process for software updates and configuration changes must be tightly controlled and traceable, ensuring that every relevant action is securely logged and verifiable.

The Open Charge Point Protocol (OCPP) already specifies the concept of a ***security log***. OCPP defines which types of events—such as security incidents, configuration changes, firmware updates, and communication errors—should be recorded in this log. Furthermore, OCPP outlines standardized methods (such as the GetLog and LogStatusNotification messages) for remote access to these logs by authorized backend systems or operators.

However, the existing requirements in OCPP are intentionally kept abstract and primarily oriented toward classical IT log file management rather than strict legal metrology or advanced cybersecurity standards. The protocol’s specifications describe what must be logged and how logs can be retrieved, but they do not prescribe how the integrity, authenticity, or immutability of these logs should be technically enforced. For example, there are no explicit requirements for cryptographic protection, hardware-based secure storage, or mechanisms to detect and prevent tampering.

This gap is critical in the context of future metrological and cybersecurity regulations. As secure metrological log books become mandatory for charging stations, simply maintaining OCPP-compliant log files will no longer suffice. Manufacturers will be required to extend or harden their logging implementations to meet the demands of both legal metrology (e.g., audit-trail capability, standardized export, non-repudiation) and cybersecurity regulations (e.g., cryptographic signatures, tamper detection, access control).

The specifics of secure metrological log books are beyond the scope of this whitepaper and will be addressed in a forthcoming whitepaper.


## 5. Communication with Energy Meters

Within the European Union, almost all metrological regulations, specifically the [Measuring instruments (MID) Directive 2014/32/EU](https://single-market-economy.ec.europa.eu/single-market/european-standards/harmonised-standards/measuring-instruments-mid_en), apply primarily to energy meters, not to charging stations themselves. As a result, the requirements for legal metrology, conformity assessment, and data integrity have so far been limited to the meters integrated within or attached to charging infrastructure, but not to the charging stations as complete systems.

This situation may change with the upcoming revision of the EU MID, which is expected to be adopted by the end of 2025. The revised MID is planned to introduce a new instrument category specifically for electric vehicle charging stations. This will likely extend metrological requirements, such as type approval, conformity assessment, and data security, to the entire charging station, not just to the integrated/attached meter.

Such a regulatory change will have direct consequences for the hardware and system architecture of charging stations. Manufacturers will need to ensure that their devices, including all components relevant for measurement, data processing, and data storage, comply with the new legal metrology requirements. This may necessitate redesigning system boundaries, implementing secure and auditable data paths, and introducing tamper-evident hardware elements to meet both measurement accuracy and regulatory audit-trail standards.

This implies that, in the near future, while the regulatory framework will permit a more flexible interface between charging stations and energy meters, there will still be a strict requirement to extend secure time synchronization (originally implemented between the charging station controller and NTS servers) to the energy meter as well. As a consequence, unencrypted protocols such as Modbus/RTU, Modbus/TCP, or plain HTTP for communication between the controller and the meter will no longer be compliant, especially in light of the additional cybersecurity requirements imposed by regulations such as the [EU Radio Equipment Directive (RED)](https://single-market-economy.ec.europa.eu/sectors/electrical-and-electronic-engineering-industries-eei/radio-equipment-directive-red_en) and the [EU Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act).

Nevertheless, detailed technical recommendations for securing this communication channel are beyond the scope of this white paper. One possible approach is to require that energy meters natively support NTS, allowing them to synchronize directly with external NTS servers or, alternatively to support at least a subset of NTS to be able to sync with the charging station controller acting as a embedded NTS server. This would ensure cryptographically secure time synchronization and data integrity throughout the measurement chain, thereby fulfilling both metrological and cybersecurity requirements.


## 6. NTP-over-TLS

Chapter 7 of the [Technical Guideline (BSI TR-03109-5)](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/TR-03109-5_Detailspezifikationen.pdf?__blob=publicationFile&v=11) of the German [Federal Office for Information Security](https://www.bsi.bund.de) describes how NTPv4 can be used in a proprietary ***NTP-over-TLS*** mode. Hereby the NTP client sends a normal NTPv4 request, but instead of using UDP transport it is sent within a TLS connection.

- TLS-Port: 443 or other
- The SMGW uses a TLS certificate using the X.509 v3 Extended Key Usage: [Time Stamping (OID 1.3.6.1.5.5.7.3.8)](https://oidref.com/1.3.6.1.5.5.7.3.8)
- Certificate Requirements of the Smart Metering PKI: [TLS nach TR-03116-4 Checkliste für Diensteanbieter](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/TLS-Checkliste.pdf?__blob=publicationFile&v=5)
- [Certificate Policy](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/PKI_Certificate_Policy.pdf?__blob=publicationFile&v=8) of the Smart Metering PKI
- List of all registered [SmartMeter-SubCAs](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Smart-metering/Smart-Meterin-PKI/Registrierte_Sub-CAs/registrierte_sub_cas_node.html)

- The client exposes the following information towards the charging station application:
  - Current Time (UTC)
  - Timestamp of last successful time synchronization
  - Maximum error (difference of system time from root time): `rootdelay/2 + rootdisp`
  - Estimated precision: `dispersion / jitter`


- [Network Time Protocol Best Current Practices](
https://datatracker.ietf.org/doc/rfc8633/)
  - Clients should respect rate-limit responses.
  - Vendors of embedded devices SHOULD include the ability to update the list of NTP servers.





## 7. Operational Guide

CPOs must not only configure their charging stations, but also configure their network infrastructure including private APNs, Virtual Private Networks (VPNs) and#
private IPv4/v6 subnets and their CSMS to support NTS. Further they have to ensure compliance with local regulations like e.g., using Germany's PTB servers.

Two implementation options are presented: Direct access to custom or legal NTS servers and integration with a local Smart Meter Gateways (SMGWs) as a special
national solution for Germany.

### 7.1 Direct Access to Custom or Legal NTS Servers

### 7.2 Integration with Local Smart Meter Gateways (Germany-Specific)



## 8. Relation to Other White Papers

- [Critical Legal Time Services](../CriticalLegalTimeServices/README.md): the rationale of this paper. It explains why legal time must fail closed, why several servers must agree, and what a provider of legal time should publish for its clients: a signed policy, DNS records and a status API. Its `quorum.clients` corresponds to `MinServers` and `MaxDeviation` of the NTP Client Group Controller, and its managed networks (section 4.2) are the environment in which the configuration of this paper is communicated via OCPP.
- [Secure Name Resolution for OCPP](../SecureDNS/README.md): NTS-KE servers are found by name, so time synchronization is only as trustworthy as name resolution. Its components are named alike, and pins, `OnPinMismatch` and trust on first use mean the same there.
- [Safe & Secure Device Model Updates](../SafeAndSecureDeviceModelUpdates/README.md): the `ACID` and `BASE` *DataConsistencyModel* and the conditional updates used in section 3.2.5.



## References

- [PTB Leaflet: Time server / Time server infrastructure for intelligent measuring systems](https://www.ptb.de/cms/fileadmin/internet/fachabteilungen/abteilung_8/8.5_metrologische_informationstechnik/8.51/PTB-8.51-MB09-ZS-EN-V07.pdf)


## Acknowledgements

The initiative to enhance the security and accuracy of time synchronization in EV infrastructure was launched at the "Bonner Eichrechtstage."    
Special thanks also go to the technical departments of the German PTB for their detailed specification and implementation support.



## ToDo's

- In Deutschland wird die gesetzliche Zeit entsprechend § 6 Einheiten- und Zeitgesetz (EinhZeitG) [6] von der PTB dargestellt und verbreitet („Gesetz über die Einheiten im Messwesen und die Zeitbestimmung (Einheiten- und Zeitgesetz - EinhZeitG)“, Bundesgesetzblatt, Jahrgang 2016 Teil 1 Nr. 35, Februar 1985, zuletzt geändert am 18. Juli 2016.)
- Für die Prüfung muss die Dokumentation eine detaillierte Beschreibung der Anbindung and die PTB-Zeitserver enthalten. 
- Wie viele und welche Zeitservern der PTB, NTP-Standard, verwendetes Authentifizierungsverfahren
- Die Verbindung zwischen Messgerät und PTB-Zeitserver darf nicht an einem Proxy o. Ä. unterbro-chen werden, sondern muss bis zum Endgerät getunnelt werden.
- Empfohlen wird eine stündlicher Verbindungsaufbau zum PTB-Zeitserver (siehe auch: PTB-A 50.7 [1], Abschnitt 3.1.7.)
- RootCA Änderungen müssen dann durch Logbucheinträge in einem rechtlich relevanten Logbuch nach PTB-A 50.7 [1], Abschnitt 3.1.6 protokolliert werden.
- WELMEC-Leitfadens 7.2 [10] erfüllen müssen. Bei Verwendung eines Universalbetriebssystems befinden sich Anforderungen im Merkblatt „Konfiguration von Universal-Betriebssystemen für Messgeräte“ [11], welche aufzeigen, wie die Software gegen unzulässige Eingriffe und Veränderun-gen abgesichert werden kann. 
- Das Betriebssystem der Komponenten GW-Admin-Server, ist zusätzlich nach PTB-A 50.8 [2] Ab-schnitt 9 gegen unzulässige Eingriffe und Veränderungen zu sichern. (PTB-A 50.8 [2], Abschnitt 8.1 (g))
- 
