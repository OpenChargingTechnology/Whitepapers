White Paper

# Secure Time Synchronization for OCPP


## Abstract
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

The paper concludes with recommended testing parameters to validate these configurations, ensuring robust and compliant time synchronization.


## 2. Network Time Security Process Flow

Network Time Security (NTS), as specified in [RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915), enhances the Network Time Protocol (NTP) by adding authentication and encryption, ensuring secure and accurate time synchronization with minimal latency which is not possible with normal TLS connections (TCP+TLS handshakes) or digital signatures using asymmetric cryptography (UDP+DTLS). NTS operates in two distinct phases: the NTS Key Establishment (NTS-KE) phase, which securely negotiates cryptographic keys over TLS-protected TCP connections, and the NTS-protected NTP phase, which uses these keys to secure classical time synchronization NTPv4 queries over UDP. This section outlines the NTS-KE request and response process, the NTS-protected NTP request and response, and how the client processes the results, providing a clear understanding of NTS’s operational mechanics.

### 2.1 NTS Key Establishment (NTS-KE) Phase

The NTS-KE phase establishes a secure channel to derive cryptographic keys and parameters for the subsequent NTP communication. This phase uses TLS 1.3 (or higher) over TCP port 4460 to ensure confidentiality and authenticity.


#### NTS-KE Request:
The client, an OCPP Charging Station or an OCPP Local Controller, initiates a TLS v1.3 connection to the NTS-KE server and ensures the server’s identity by validating its certificate, mitigating MITM risks. Which root certification authorities (root CAs) are used to validate the server certificate is an configuration option. For security reasons this should not be the entire World Wide Web root CA bundle used within web browsers.

Then the client sends an NTS-KE request message, which includes:
- Supported cryptographic algorithms (e.g., AES-SIV-CMAC for message authentication).
- A unique client identifier or nonce to prevent replay attacks.
- Optional parameters, such as a request for an additional digital signed NTP response.

#### Key Derivation
A set of cryptographic keys for Client-to-Server (C2S) and Server-to-Client (S2C) encryption will be deviated from the key material of the TLS connection and later be used to encrypt and authenticate the NTP communication via an [Authenticated Encryption with Associated Data (AEAD)](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) algorithm. This method is based on TLS 1.3 exporter mechanism, as defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446), using `EXPORTER-network-time-security` as constant.

Some NTS-KE servers also support a non-standardized way to generate both keys at the server and include them in the NTS-KE response. Supporting this feature can be an option for TLS libraries that do not support the key-exporter functions.


#### NTS-KE Response:
The server responds with:
- Confirmation of the selected cryptographic algorithm.
- Multiple opaque NTS-KE cookies, which encapsulates server state as the NTS-KE server discards all state after the TLS session closes and all further communication
relies purely on the client to store cookies containing key material or references to it.
- The NTS client stores these cookies within a secure storage.

Some NTS-KE servers also support a no-longer-standardized way to return NTP server addresses and UDP ports. This feature can be used, but charging station operators have to provide fall-back mechanisms.
 

### 2.2 NTS-Protected NTP Phase

The NTS-protected NTP phase uses the keys and cookies obtained from NTS-KE to secure time synchronization queries over UDP port 123, maintaining low latency.


#### NTS-Protected NTS Request

The client sends an NTP packet to the specified NTP server, augmented with NTS extensions:
- The packet includes a standard NTPv4 header with timestamp fields.
- An unique identifier extensions to prevent replay attacks.
- An NTS cookie, which allows the server to retrieve session state without maintaining per-client data.
- An NTS authenticator extension, using the C2S key to compute a message authentication code (MAC) via authenticated encryption (e.g., AES-SIV-CMAC).


#### NTS-Protected NTS Response

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

**Logging and Compliance**: For OCPP charging stations, the client logs synchronization events (e.g., successful updates or failures) to support regulatory audits, particularly for time-based or dynamic tariffs requiring traceable time sources. Clock adjustments over a defined threshold (e.g. 5 seconds) should be logged as security critical event and appended to the metrological log book.


## 3. Network Time Security OCPP Client Configuration

OCPP v1.6+SE and v2.x are very different in the way a charging station is configured. While OCPP v1.x uses a simple Key-Value-Store for configuration data OCPP v2.x provides its own Device Model. At the time of writing this white paper OCPP v1.6 still has by far the largest market share, so we have to provide solutions for both.

Since OCPP time synchronization serves two main use cases: ***legal time*** for billing and ***local time*** for load balancing, many settings are organized around these purposes and can differ significantly. In practice, it is often beneficial to synchronize local time every few seconds, whereas legal time may only need to be synchronized once or twice per hour, or on demand, e.g. shortly before scheduled dynamic tariff changes will be applied.

All changes of the NTP/NTS configuration settings and all NTP server certificate changes shall be logged within the default security log.

Changed NTP time sync rootCA certificates have to be logged within the secure metrological log.



### 3.1 OCPP vNext Client Configuration

### 3.2 OCPP v2.x Client Configuration

### 3.3 OCPP v1.6+SE Client Configuration

#### 3.3.1 Common Configuration Keys

The following table gives an overview how the NTP/NTP client configuration can be mapped onto OCPP v1.6+SE configuration keys and values.

If a CSL (comma separated list) configuration setting is shorter than expected, e.g. the "ntp.ports" list is shorter than the "ntp.servers" list, the last value in the list is applied to all remaining items (here: servers). Empty entries are filled with the previous value, starting from the default value. Lists that are longer than expected will result in an error.


| Key Name      | req/opt  | Accessibility | Type       | Default Value | Values | Example        | Description |
|---------------|----------|---------------|------------|---------------|--------|----------------|-------------|
| ntp.enabled   | required |  rw           | Boolean    | false         | -      | -              | Whether NTP/NTS is enabled. |
| ntp.reboot.allowJumps | optional | rw | Boolean | true | | | Allows immediate correction of large time discrepancies during the first synchronization steps after a reboot. |
| ntp.reboot.noCertTimeCheck | optional | rw | Boolean | false         | - | - | Whether the *notBefore* and *notAfter* timestamp checks of NTS and NTP-over-TLS TLS certificates can be skipped on the first time sync request per server immediately after a reboot, as the device might have started with a wrong internal time, e.g. due to not having an RTC or backup battery. |


#### 3.3.1 *Legal Group* Configuration Keys

| Key Name      | req/opt  | Accessibility | Type       | Default Value | Values | Example        | Description |
|---------------|----------|---------------|------------|---------------|--------|----------------|-------------|
| ntp.legal.servers | optional | rw            | CSL String | "" | - | "time1.org, time2.org, time3.org" | Defines a list of legally recognized NTP/NTS servers, which may vary depending on the device’s country or location. |
| ntp.legal.ports   | optional | rw            | CSL String | "123" | -      | "125, 126"      | NTP/NTS legal server ports |
| ntp.legal.offset | optional | rw | CSL String | "0" | - | - | These values specifie a correction (in milliseconds) which will be applied to measured time offsets per server. This can compensate known stable asymmetries in network or processing delays. For example, if packets sent to the source were on average delayed by 100 microseconds more than packets sent from the source back, the correction would be -0.05 (-50 microseconds). |
| ntp.legal.asymmetry | optional | rw | CSL String | "0" | - | "+0.5,0,-0.5,0,0"| These values can fine-tune the offset calculations when network delay variability is greater in one direction than the other. Use only if you know your network has a consistent asymmetry. |
| ntp.legal.mode    | required |  rw           | String     | nts           | NTPv4 \| NTSv4 \| NTPv4TLS | - | NTP/NTS legal server mode. *NTPv4* may be prohibited unless additional security measures are implemented! |
| ntp.legal.priority  | optional |  rw           | CSL String | "0"           | -      | 0, 0, 10 | NTP/NTS legal server priority list: Servers with lower values are queried first; servers with the same value are queried in parallel. |
| ntp.legal.minInterval | optional |  rw           | Integer    | 30            | -      | 60 (seconds)   | The minmal time span between randomized NTP/NTS time sync requests. |
| ntp.legal.maxInterval | optional |  rw           | Integer    | 3600          | -      | 3600 (seconds) | The maximal time span between randomized NTP/NTS time sync requests. |
| ntp.legal.preflight | optional |  rw | CSL String | "60"         |        | "60, 90, 30" | Occasional requests to an NTP/NTS server may be delayed due to network caching effects such as ARP or DNS resolution, firewall state establishment, TLS tunnel setup, and similar factors. To prevent inaccurate delay measurements, a *preflight* NTP packet is sent and its response ignored before the actual measurement takes place. The configured values define the time intervals since the last measurement that trigger sending preflight NTP packets. |
| ntp.legal.minServers | optional | rw           | Integer    | 1             | -      | 2 (servers)    | The minimal number of legal servers that are required for a valid measurement. Failed measurements must be logged. |
| ntp.legal.maxDeviation | optional | rw | Integer | 60 | | 60 (seconds)   | Time discrepancies equal to or greater than this threshold value must be recorded in the secure metrological log book. |
| ntp.legal.errorLogging | optional | rw           | Integer    | 5             | -      | 10 (errors)    | The number of consecutive measurement errors that should lead to an entry within the secure metrological log book. When the measurements recovered from the error another log book entry shall be added. |
| ntp.legal.maxErrors | optional | rw           | Integer    | 10             | -      | 20 (errors)    | The number of consecutive measurement errors that should lead to limited charging session features, e.g. dynamic tariff changes are no longer available, and an entry within the secure metrological log book. When the measurements recovered from the error another log book entry shall be added. |
| ntske.legal.servers | optional  |  rw           | CSV String | ""            | -      | time1.org, time2.org, time3.org | NTS-KE server list. When empty the *ntp.legal.servers* setting will be used. |
| ntske.legal.ports   | optional |  rw           | CSL String | "4460"        | -      | "4461,4462" | NTS-KE server port list. |
| ntske.legal.rootCAs | optional |  rw           | CSL String | ""            | -      | "legalTimeCA1, legalTimeCA1, legalTimeCA2" | Which rootCA group can be used for NTS-KE server certificate validation. When this configuration is not set, the system default list of rootCAs is used *(not recommended)*! |
| ntske.legal.noCertTimeCheck | optional | rw | Boolean | false         | - | - | Whether the *notBefore* and *notAfter* timestamp checks of NTS-KE TLS certificates can be skipped on the first NTS-KE request per server immediately after a reboot, as the device might have started with a wrong internal time, e.g. due to not having an RTC or backup battery. |
| ntske.legal.minRefresh | optional | rw | CSL String | "30"         | - |         "30,32" | Refreshing the NTS keys and cookies should be started after the given time spans (in days) since the last NTS-KE handshakes *(randomly between given min and max values)*.
| ntske.legal.maxRefresh | optional | rw | CSL String | "60"         | - |         "60,90" | Refreshing the NTS keys and cookies must be completed within the given time spans (in days) since the last NTS-KE handshakes *(randomly between given min and max values)*.
| ntske.legal.aead    | optional |  rw           | CSV String | "AES-SIV-CMAC-256"            | AES-SIV-CMAC-256\|AES-128-GCM-SIV | "AES-SIV-CMAC-256" | Authenticated Encryption with Associated Data (AEAD) algorithms enabled for NTS authentication of NTP messages. *(Can be different for different servers.)* |
| nts.legal.signedResponses | optional |  rw           | Boolean    | false         |        |                | Whether NTS responses shall be digital signed. |
| ntptls.legal.rootCAs | optional |  rw           | CSL String | ""            | -      | "legalTimeCA1, legalTimeCA1, legalTimeCA2" | Which rootCA group can be used for NTP-over-TLS server certificate validation. When this configuration is not set, the system default list of rootCAs is used *(not recommended)*! |


#### 3.3.1 *Local Group* Configuration Keys

| Key Name      | req/opt  | Accessibility | Type       | Default Value | Values | Example        | Description |
|---------------|----------|---------------|------------|---------------|--------|----------------|-------------|
| ntp.local.servers | optional | rw            | CSL String | ""            | -      | "lc1.local, lc2.local" | Defines a list of local NTP/NTS servers, e.g. running on OCPP Local Controllers, that shall be used as a shared local time source for use cases like *local load management*, for which having a consistent local time across devices is more important than having legal time accuracy. |
| ntp.local.ports   | optional | rw            | CSL String | "123" | -      | "125, 126"      | NTP/NTS local server ports |
| ntp.local.offset | optional | rw | CSL String | "0" | - | - | These values specifie a correction (in milliseconds) which will be applied to measured time offsets per server. This can compensate known stable asymmetries in network or processing delays. For example, if packets sent to the source were on average delayed by 100 microseconds more than packets sent from the source back, the correction would be -0.05 (-50 microseconds). |
| ntp.local.asymmetry | optional | rw | CSL String | "0" | - | "+0.5,0,-0.5,0,0"| These values can fine-tune the offset calculations when network delay variability is greater in one direction than the other. Use only if you know your network has a consistent asymmetry. |
| ntp.local.mode    | required |  rw           | String     | nts           | NTPv4 \| NTSv4 \| NTPv4TLS | - | NTP/NTS local server mode. |
| ntp.local.priority  | optional |  rw           | CSL String | "0"           | -      | 0, 10 | NTP/NTS local server priority list: Servers with lower values are queried first; servers with the same value are queried in parallel. |
| ntp.local.minInterval | optional |  rw           | Integer    | 30            | -      | 60 (seconds)   | The minmal time span between randomized NTP/NTS time sync requests. |
| ntp.local.maxInterval | optional |  rw           | Integer    | 3600          | -      | 3600 (seconds) | The maximal time span between randomized NTP/NTS time sync requests. |
| ntp.local.preflight | optional |  rw | CSL String | "60"         |        | "60, 90, 30" | Occasional requests to an NTP/NTS server may be delayed due to network caching effects such as ARP or DNS resolution, firewall state establishment, TLS tunnel setup, and similar factors. To prevent inaccurate delay measurements, a *preflight* NTP packet is sent and its response ignored before the actual measurement takes place. The configured values define the time intervals since the last measurement that trigger sending preflight NTP packets. |
| ntp.local.minServers | optional | rw           | Integer    | 1             | -      | 2 (servers)    | The minimal number of local servers that are required for a valid measurement. Failed measurements must be logged. |
| ntp.local.errorLogging | optional | rw           | Integer    | 5             | -      | 10 (errors)    | The number of consecutive measurement errors that should lead to an entry within the security log book. When the measurements recovered from the error another log book entry shall be added. |
| ntp.local.maxErrors | optional | rw           | Integer    | 50            | -      | 100 (errors)    | The number of consecutive measurement errors that should lead to a stop of the load management feature and an entry within the security log book. When the measurements recovered from the error another log book entry shall be added. |
| ntske.local.servers | optional  |  rw           | CSV String | ""            | -      | "lc1.local, lc2.local" | NTS-KE local server list. When empty the *ntp.local.servers* setting will be used. |
| ntske.ports   | optional |  rw           | CSL String | "4460"        | -      | "4461,4462" | NTS-KE local server port list. |
| ntske.local.rootCAs | optional |  rw           | CSL String | ""            | -      | "localTimeCAs" | Which rootCA group can be used for NTS-KE server certificate validation. When this configuration is not set, the system default list of rootCAs is used *(not recommended)*! |
| ntske.local.noCertTimeCheck | optional | rw | Boolean | false         | - | - | Whether the *notBefore* and *notAfter* timestamp checks of NTS-KE TLS certificates can be skipped on the first NTS-KE request per server immediately after a reboot, as the device might have started with a wrong internal time, e.g. due to not having an RTC or backup battery. |
| ntske.local.minRefresh | optional | rw | CSL String | "30"         | - |         "30,32" | Refreshing the NTS keys and cookies should be started after the given time spans (in days) since the last NTS-KE handshakes *(randomly between given min and max values)*.
| ntske.local.maxRefresh | optional | rw | CSL String | "60"         | - |         "60,90" | Refreshing the NTS keys and cookies must be completed within the given time spans (in days) since the last NTS-KE handshakes *(randomly between given min and max values)*.
| ntske.local.aead    | optional |  rw           | CSV String | "AES-SIV-CMAC-256"            | AES-SIV-CMAC-256\|AES-128-GCM-SIV | "AES-SIV-CMAC-256" | Authenticated Encryption with Associated Data (AEAD) algorithms enabled for NTS authentication of NTP messages. *(Can be different for different servers.)* |
| nts.local.signedResponses | optional |  rw           | Boolean    | false         |        |                | Whether NTS responses shall be digital signed. |
| ntptls.local.rootCAs | optional |  rw           | CSL String | ""            | -      | "localTimeCAs" | Which rootCA group can be used for NTP-over-TLS server certificate validation. When this configuration is not set, the system default list of rootCAs is used *(not recommended)*! |


#### 3.3.2 OCPP v1.6+SE Command Extensions

*InstallCertificateRequest*

The following defines a small extension for the *InstallCertificateRequest* defined within the OCPP v1.6 Security Extensions. The *CertificateUseEnumType* had been extended by *"TimeSyncRootCertificate"*. The new *certificateGroup* property allows to group rootCAs of the same *CertificateUseEnumType*. Such a rootCA group can later specify which root CAs should be used to validate the TLS certificate presented by a TLS server configured in the network settings.

Different certificates of the same type and group will be combined into a single set. Duplicate certificates will be silently ignored.

The same certificate can belong to multiple groups, but must be uploaded separately for each group.

```
{
  "$schema": "http://json-schema.org/draft-06/schema#",
  "$id": "urn:OCPP:Cp:1.6:2020:3:InstallCertificate.req",
  "definitions": {
    "CertificateUseEnumType": {
      "type": "string",
      "additionalProperties": false,
      "enum": [
        "CentralSystemRootCertificate",
        "ManufacturerRootCertificate",
        "TimeSyncRootCertificate"
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
      "type": "string",
      "maxLength": 50
    },
    "certificate": {
      "type": "string",
      "maxLength": 11000
    }
  },
  "required": [
    "certificateType",
    "certificate"
  ]
}
```


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

https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/TR-03109-5_Detailspezifikationen.pdf?__blob=publicationFile&v=11








## 7. Operational Guide

CPOs must not only configure their charging stations, but also configure their network infrastructure including private APNs, Virtual Private Networks (VPNs) and#
private IPv4/v6 subnets and their CSMS to support NTS. Further they have to ensure compliance with local regulations like e.g., using Germany's PTB servers.

Two implementation options are presented: Direct access to custom or legal NTS servers and integration with a local Smart Meter Gateways (SMGWs) as a special
national solution for Germany.

### 7.1 Direct Access to Custom or Legal NTS Servers

### 7.2 Integration with Local Smart Meter Gateways (Germany-Specific)







## References

- [PTB Leaflet: Time server / Time server infrastructure for intelligent measuring systems](https://www.ptb.de/cms/fileadmin/internet/fachabteilungen/abteilung_8/8.5_metrologische_informationstechnik/8.51/PTB-8.51-MB09-ZS-EN-V07.pdf)


## Acknowledgements

The initiative to enhance the security and accuracy of time synchronization in EV infrastructure was launched at the "Bonner Eichrechtstage."    
Special thanks also go to the technical departments of the German PTB for their detailed specification and implementation support.
