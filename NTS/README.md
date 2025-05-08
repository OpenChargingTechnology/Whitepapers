White Paper

# Secure Time Synchronization for OCPP


## Abstract
This white paper offers a technical guide for configuring electric vehicle (EV) charging stations compliant with Open Charge Point Protocol (OCPP) v1.6 and v2.x to
enable secure and accurate time synchronization — an essential requirement for compliance with emerging time-based and dynamic tariff regulations. Two implementation strategies are detailed:
- **Direct NTS Integration**: Direct synchronization with legal Network Time Security (NTS) servers—such as those operated by Germany’s PTB—using Network Time
Security Key Establishment (NTS-KE) and authenticated NTP (NTP+NTS). This approach supports multiple prioritized time sources with parallel querying to ensure high
performance and resilience.
- **NTP-over-TLS via SMGW**: A Germany-specific option using NTP-over-TLS in combination with a local Smart Meter Gateway (SMGW), suitable for integration into smart
metering infrastructures.

The paper also includes operational guidance on configuring internal network components—such as firewalls, NAT, and IP addressing—for secure backend communication
within Charge Point Operator (CPO) environments. It concludes with test criteria and recommended parameters for validating the correct and compliant implementation
of time synchronization mechanisms.


## 1. Introduction

Precise and secure time synchronization is vital for electric vehicle (EV) charging stations to ensure accurate transaction logging, reliable billing, and adherence
to regulatory mandates, particularly with the rise of time-based and dynamic tariff structures. The Open Charge Point Protocol (OCPP) v1.6 and v2.x facilitate
communication between charging stations and Charging Station Management Systems (CSMS), relying on consistent timekeeping for secure operations, such as validating
TLS certificates and scheduling smart charging profiles. Traditionally, OCPP heartbeats and the Network Time Protocol (NTP) have been employed for time synchronization.
However, OCPP heartbeats lack the precision required for high-latency mobile networks, and NTP’s inherent lack of security exposes it to vulnerabilities like
man-in-the-middle (MITM) attacks. Securing NTP with (D)TLS introduces additional latency and jitter, which can degrade performance in time-sensitive applications.

Network Time Security (NTS), as defined in RFC 8915, addresses these shortcomings by providing authenticated and encrypted time synchronization with minimal delay,
making it an ideal solution for modern EV charging infrastructure. NTS combines NTS Key Establishment (NTS-KE) for secure key exchange with NTS-protected NTP for robust
time queries, ensuring both security and accuracy. This white paper provides a comprehensive guide for configuring OCPP v1.6 and v2.x compliant charging stations to
implement NTS, enabling Charge Point Operators (CPOs) to meet emerging regulatory requirements, such as those for time-based and dynamic tariffs in markets. It details
the setup of NTS-KE and NTS-protected NTP, including support for multiple prioritized servers with parallel querying to optimize performance and reliability.

Additionally, the paper offers an operational guide outlining two implementation strategies tailored to CPO needs. The first strategy involves direct access to legal
NTS servers, such as Germany’s Physikalisch-Technische Bundesanstalt (PTB) servers, requiring specific network, firewall, and Network Address Translation (NAT)
configurations to accommodate private IP networks within the CPO’s backend. The second strategy focuses on integration with a local Smart Meter Gateway (SMGW) using NTS
or NTP-over-TLS, a solution primarily applicable in Germany to comply with the Mess- und Eichrecht (calibration law). The paper concludes with recommended testing
parameters to validate these configurations, ensuring robust and compliant time synchronization. By adopting NTS, CPOs can enhance the security, scalability, and
regulatory compliance of their EV charging networks, paving the way for advanced tariff models and operational efficiency.


## 2. Network Time Security Process Flow

Network Time Security (NTS), as specified in RFC 8915, enhances the Network Time Protocol (NTP) by adding authentication and encryption, ensuring secure and accurate
time synchronization with minimal latency which is not possible with normal TLS connections (TCP+TLS handshakes) or digital signatures using asymmetric cryptography.
NTS operates in two distinct phases: the NTS Key Establishment (NTS-KE) phase, which securely negotiates cryptographic keys
over a TLS-protected TCP connection, and the NTS-protected NTP phase, which uses these keys to secure classical time synchronization NTP queries over UDP. This section
outlines the NTS-KE request and response process, the NTS-protected NTP request and response, and how the client processes the results, providing a clear understanding
of NTS’s operational mechanics.

### 2.1 NTS Key Establishment (NTS-KE) Phase

The NTS-KE phase establishes a secure channel to derive cryptographic keys and parameters for the subsequent NTP communication. This phase uses TLS 1.3 (or higher) over
TCP port 4460 to ensure confidentiality and authenticity.


#### NTS-KE Request:
The client (e.g., an OCPP charging station) initiates a TLS v1.3 connection to the NTS-KE server and ensures the server’s identity by validating its certificate,
mitigating MITM risks.

Then the client sends an NTS-KE request message, which includes:
- The desired NTP server address for time queries (often the same server or a related one).
- Supported cryptographic algorithms (e.g., AES-SIV-CMAC for message authentication).
- A unique client identifier or nonce to prevent replay attacks.
- Optional parameters, such as a request for an additional digital signed NTP response.

#### Key Derivation
A set of cryptographic keys for Client-to-Server (C2S) and Server-to-Client (S2C) encryption will be deviated from the key material of the TLS connection and later
be used to encrypt and authenticate the NTP communication via the Authenticated Encryption with Associated Data (AEAD) algorithm.
This method is based on TLS 1.3 exporter mechanism, defined in RFC 8446, using `EXPORTER-network-time-security` as constant.

Some NTS-KE servers also support a non-standardized way to generate both keys at the server and include them in the NTS-KE response.
Supporting this feature can be an option for TLS libraries that do not support the key-exporter functions.


#### NTS-KE Response:
The server responds with:
- Confirmation of the selected cryptographic algorithm.
- Multiple opaque NTS-KE cookies, which encapsulates server state as the NTS-KE server discards all state after the TLS session closes and all further communication
relies purely on the client to store cookies containing key material or references to it.
- The NTS client stores these cookies within a secure storage.
 

### 2.2 NTS-Protected NTP Phase

The NTS-protected NTP phase uses the keys and cookies obtained from NTS-KE to secure time synchronization queries over UDP port 123, maintaining low latency.


#### NTS-Protected NTS Request

The client sends an NTP packet to the specified NTP server, augmented with NTS extensions:
- The packet includes a standard NTP header with timestamp fields.
- An unique identifier extensions to prevent replay attacks.
- An NTS cookie, which allows the server to retrieve session state without maintaining per-client data.
- An NTS authenticator extension, using the C2S key to compute a message authentication code (MAC) or authenticated encryption (e.g., AES-SIV-CMAC).


#### NTS-Protected NTS Response

The server verifies the cookie and the AEAD MAC, ensuring the request’s authenticity and integrity and responds with:
- A standard NTP response containing timestamps (origin, receive, transmit, and reference).
- A new cookie to replace the used one, ensuring continued stateless operation.
- An NTS authenticator extension, using the S2C key to authenticate the response.


#### Client Processing of NTS Results

Upon receiving the NTS-protected NTP response, the client performs several steps to validate and utilize the time data:
- Authentication: The client verifies the response’s MAC using the S2C key, ensuring the response originates from the trusted server and has not been altered.
- Timestamp Extraction: If authenticated, the client extracts the timestamps to calculate the network delay and clock offset. The standard NTP algorithm
computes the round-trip time and adjusts the local clock based on the server’s reference time.
- Cookie Management: The client stores the new cookie from the response, using it for subsequent NTS requests to maintain session continuity without
repeated NTS-KE negotiations.
- Clock Adjustment: The client applies the calculated offset to its local clock, either gradually (slewing) for small corrections or immediately (stepping)
for large discrepancies, depending on configuration (e.g., Chrony’s makestep setting).

**Error Handling**: If the response fails authentication or contains invalid data (e.g., high jitter or stratum), the client discards it and may query another
server from its configured pool, leveraging prioritized parallel querying for reliability.

**Logging and Compliance**: For OCPP charging stations, the client logs synchronization events (e.g., successful updates or failures) to support regulatory
audits, particularly for time-based or dynamic tariffs requiring traceable time sources. Clock adjustments over 5(???) seconds should be logged as security
critical event and appended to the metrological log book.


## 3. Network Time Security OCPP Configuration

OCPP v1.6 and v2.x are very different in the way a charging station is configured. While OCPP v1.x uses a simple Key-Value-Store for configuration data
OCPP v2.x provides its own Device Model. At the time of writing this white paper OCPP v1.6 still has by far the largest market share, so we have to
provide solutions for both.

### 3.1 OCPP v1.6 Configuration


### 3.2 OCPP v2.x Configuration


### 3.3 Example Configuration Using Chrony

Chrony is an Open Source NTP client compatible with NTS, suitable for e.g. Linux based charging stations and licensed under the GNU General Public License version 2.
It can be used as an underlying software for rapid prototyping.

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


## 4. Operational Guide

CPOs must not only configure their charging stations, but also configure their network infrastructure including private APNs, Virtual Private Networks (VPNs) and#
private IPv4/v6 subnets and their CSMS to support NTS. Further they have to ensure compliance with local regulations like e.g., using Germany's PTB servers.

Two implementation options are presented: Direct access to custom or legal NTS servers and integration with a local Smart Meter Gateways (SMGWs) as a special
national solution for Germany.

### 4.1 Direct Access to Custom or Legal NTS Servers

### 4.2 Integration with Local Smart Meter Gateways (Germany-Specific)




## 5. NTP-over-TLS

https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/TR-03109-5_Detailspezifikationen.pdf?__blob=publicationFile&v=11


