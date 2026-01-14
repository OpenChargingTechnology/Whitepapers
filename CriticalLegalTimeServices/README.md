# Critical Legal Time Services

## 1. Time as Legal Evidence and Systemic Trust Anchor

In critical infrastructure, **time is not just a *"best-effort"* auxiliary service with transport security**. Time is a legally relevant quantity and forms the backbone of evidence chains, compliance verification, and liability attribution. Treating time as a best-effort network utility is therefore incompatible with regulated environments and fundamentally at odds with the objectives of the EU NIS2 Directive.

From a legal perspective, timestamps are used to *prove* that something happened at *"a specific moment"* and in *"a specific order"*. This applies equally to forensic investigations, regulatory reporting, billing processes under the EU Payment Service Directive, calibrated measurements under the EU Measurements Instruments Directive, and contractual dispute resolution. In all these cases, **time is not descriptive but constitutive**: if the timestamp is wrong, the legal meaning of the event may cease to exist.

For the *Physikalisch-Technische Bundesanstalt (PTB)* as a **national time authority**, this implies a shift in perspective. The task is no longer only to ***distribute “accurate time”***, but to deliver time that is **legally defensible** and **whose correctness, integrity, and provenance can be demonstrated retroactively**.


### 1.1 Time as Legal Evidence

In legal and regulatory contexts, time underpins several critical functions simultaneously:

- Reconstruction of timelines in cybersecurity forensics and incident reconstruction
- Validation of billing and transaction boundaries under calibration and metrology law
- Determination of responsibility, fault in liability cases and dispute resolution
- Compliance with statutory reporting deadlines and escalation windows

A compromised or drifting clock does not simply introduce measurement noise. Instead, it **invalidates entire chains of otherwise correct data**. Logs remain syntactically valid, signatures verify correctly, and business logic behaves as specified, yet the resulting evidence becomes legally unusable because its temporal foundation is flawed.

This is particularly dangerous because time errors are often silent. Small offsets accumulate slowly, remain within expected tolerances, and evade detection mechanisms that focus on availability or gross failures. When the inconsistency is finally discovered, the affected period may already lie far in the past, making forensic reconstruction and legal clarification extremely difficult.


### 1.2 Asymmetry Between Attack and Defense

Time services exhibit a pronounced **asymmetry between attackers and defenders**. An attacker needs only seconds to inject false time, delay packets, or influence synchronization behavior. Defenders, by contrast, require extensive log correlation, cross-system comparison, and often external expert involvement to demonstrate that time was wrong — and to prove since when.

This asymmetry is legally relevant. Courts and regulators do not assess whether an attack was *“clever”*, but whether an operator can demonstrate due diligence and technical adequacy. If time integrity cannot be proven, the burden of proof may shift unfavorably, even if no malicious intent is established.

NIS2 explicitly targets such asymmetries. Its intent is not merely to increase uptime, but to ensure that critical services remain **trustworthy under adverse conditions**, including partial compromise, degradation, or sophisticated manipulation.


### 1.3 Time as a Horizontal Coupling Point

Unlike many other infrastructure services, time acts as a **horizontal coupling point**** across organizational and sectoral boundaries. Charging infrastructure, backend systems, roaming platforms, payment services, grid interfaces, and audit systems all rely on a shared temporal reference.

This means that a single faulty or malicious time source can simultaneously affect multiple independent operators and legal domains. The impact is not vertical (one operator fails internally), but horizontal: many compliant systems produce legally inconsistent results at the same time.

From a NIS2 perspective, this makes legal time services a **systemic risk amplifier**. They are precisely the kind of shared dependency that justifies higher security requirements, stronger governance, and explicit regulatory oversight.


### 1.4 Consequences for Security-by-Design

The traditional model *“provide accurate time and secure the transport if possible”* is insufficient. What is required is **Security-by-Design for legal time**, with the explicit goal of dissolving the attacker–defender asymmetry.

This implies that a time service must be designed to:

- Authenticate its origin cryptographically
- Protect against manipulation and replay
- Behave deterministically under fault conditions
- Expose sufficient evidence to allow later verification

Under NIS2, accepting incorrect time is often worse **than rejecting time altogether**. A fail-open design may preserve availability, but it destroys legal certainty. For critical legal time services, correctness and verifiability must therefore take precedence over continuity at all costs.

This shift in priorities is the conceptual foundation for adopting **Network Time Security (NTS)** as a mandatory baseline and for redefining the role of national time services from “clock providers” to **trust anchors for legally relevant time**.



## 2. Resilient Services Building Blocks

✔️  𝗥𝗶𝘀𝗸 𝗠𝗮𝗻𝗮𝗴𝗲𝗺𝗲𝗻𝘁: Regular assessment and implementation of technical, operational, and organizational security measures.

✔️  𝗜𝗻𝗰𝗶𝗱𝗲𝗻𝘁 𝗛𝗮𝗻𝗱𝗹𝗶𝗻𝗴: Procedures for detection, analysis, classification, and reporting of incidents.

✔️  𝗕𝘂𝘀𝗶𝗻𝗲𝘀𝘀 𝗖𝗼𝗻𝘁𝗶𝗻𝘂𝗶𝘁𝘆: Plans for service continuity, disaster recovery, and crisis management.

✔️  𝗦𝘂𝗽𝗽𝗹𝘆 𝗖𝗵𝗮𝗶𝗻 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆: Managing cybersecurity risks with suppliers and service providers.

✔️  𝗦𝘆𝘀𝘁𝗲𝗺 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆: Security in system acquisition, development, and maintenance, including vulnerability handling.

✔️  𝗚𝗼𝘃𝗲𝗿𝗻𝗮𝗻𝗰𝗲: Direct management responsibility and oversight for cybersecurity measures.

✔️  𝗖𝘆𝗯𝗲𝗿 𝗛𝘆𝗴𝗶𝗲𝗻𝗲 & 𝗧𝗿𝗮𝗶𝗻𝗶𝗻𝗴: Basic cyber hygiene practices, staff training, and use of secure authentication/communication.

✔️  𝗘𝗳𝗳𝗲𝗰𝘁𝗶𝘃𝗲𝗻𝗲𝘀𝘀 𝗔𝘀𝘀𝗲𝘀𝘀𝗺𝗲𝗻𝘁: Policies to evaluate the efficacy of cybersecurity measures.


## 3. Risk Analysis

|Risk|Impact|Likelihood|Evaluation|
|---|---|---|---|
|GNSS Spoofing|sehr hoch|mittel|kritisch|
|Soft-/Hardware Error|sehr hoch|niedrig|kritisch|
|Time-Regression/Holdover Drift|mittel|mittel|mittel|
|PKI CA Compromise|sehr hoch|niedrig|hoch|
|Key-Compromise or Configuration Mistakes|mittel|mittel|mittel|
|Missing Audit Trails|sehr hoch|hoch|kritisch|
|Men-in-the-Middle, Replay- or Delay-Attacks|hoch|hoch|kritisch|
|Denial-of-Service Attacks|hoch|hoch|kritisch|
|Internal Attackers|hoch|niedrig|mittel|

### 3.1 GNSS Spoofing

### 3.2. Soft-/Hardware Error

### 3.3. Time-Regression/Holdover Drift

### 3.4. PKI CA Compromise

### 3.5. Key-Compromise or Configuration Mistakes

### 3.6. Men-in-the-Middle, Replay- or Delay-Attacks

### 3.7. Denial-of-Service Attacks

### 3.8. Internal Attackers



## 4. Operational Environments

Before discussing concrete technical measures, it is essential to distinguish between **different operational environments**. An operational environment describes the **technical, organizational, and trust context** in which a product is deployed and operated: who controls the network, which security assumptions are valid, which parties can enforce policies, and which threat actors must be considered.

This distinction is not academic. The same technical component can be subject to **fundamentally different risk profiles** depending on whether it is operated in an unmanaged home network, in a professionally administered infrastructure, or within a closed trust domain. Consequently, the effectiveness and appropriateness of security measures cannot be assessed in isolation from the environment in which they are applied.

Under the **EU Cyber Resilience Act (CRA)**, the concept of operational environments has become a central and highly debated topic. The CRA explicitly requires manufacturers to consider **reasonably foreseeable conditions of use and misuse** and to ensure that products remain secure in those contexts. This makes it insufficient to argue that a product *can* be operated securely under ideal conditions; security must hold in the environments in which the product is actually deployed.

For time services and time-dependent systems, this is particularly critical. Time is a horizontal dependency, and weaknesses in one operational environment can propagate across system boundaries into others. For this reason, the following sections distinguish between representative operational environments and analyze their specific implications for secure and legally reliable time synchronization.


### 4.1 Operation over the Public Internet

In the public-Internet operational environment, Network Time Protocol clients such as **EV charging wallboxes operated by private end users** are exposed to the full threat landscape of the open Internet. These devices typically reside in *unmanaged home networks*, *behind consumer-grade routers*, often *without continuous monitoring, professional incident response*, or *coordinated security updates*. As a result, they are comparatively easy targets for time-related attacks such as spoofing, replay, delay injection, or selective packet dropping.

In this environment, **infrastructure-level assumptions must be minimized**. The manufacturer cannot rely on the presence of trusted network segments, enterprise firewalls, or operator-controlled routing. Instead, resilience and security must be achieved using mechanisms that function reliably under adversarial conditions and across heterogeneous networks.

This makes **state-of-the-art DNS and transport security extensions** a central building block. Secure name resolution, authenticated service discovery, redundancy through multiple independently reachable endpoints, and cryptographically protected time synchronization are core requirements. High availability and resilience must be achieved by design, not by operational tuning.

From a regulatory perspective, these requirements map directly to manufacturer obligations under the **EU Cyber Resilience Act (CRA)**. In this operational environment, the manufacturer is the only actor capable of implementing effective baseline protections. The end user neither has the expertise nor the legal responsibility to harden time synchronization against sophisticated attacks. Consequently, secure defaults, mandatory cryptographic protection, and robust failure handling must be implemented at the product level.

Accepting unauthenticated or weakly protected time in such environments is not merely a technical risk; it is a compliance risk. A product that silently accepts manipulated time undermines the integrity of all downstream functions that rely on legally relevant timestamps and therefore fails to meet the CRA’s requirement for security-by-design.


### 4.2 Operation over Managed Networks with Trust Zones

A fundamentally different situation exists in managed charging infrastructures operated by professional **Charging Station Operators (CPO)**. In these environments, EV charging stations are typically embedded in controlled trust zones, making use of *Network Address Translation (NAT)*, *HTTP or SOCKS proxies*, and additional perimeter or internal *firewalls*. Communication is often orchestrated via the **Open Charge Point Protocol (OCPP)**, which already provides a structured control channel between operator backend and charging infrastructure.

In such settings, many security-relevant parameters can be centrally managed. Time synchronization policies, trust anchors, failover strategies, and even incident response behavior can be configured or enforced by the operator. Some CPOs go further and bypass the public Internet entirely, using *Virtual Private Networks (VPNs)* or dedicated *Overlay Networks* to connect their assets and business partners.

As a consequence, the relative importance of external mechanisms such as public DNS may be reduced, while **operator-controlled configuration and governance mechanisms** become more significant. Security controls can be adapted to the specific risk profile, topology, and regulatory exposure of the operator’s infrastructure.

This also shifts the locus of responsibility. While manufacturers must still provide secure and capable implementations, many of the identified requirements are best implemented and enforced by the CPO. These requirements can be communicated to charging stations dynamically via OCPP rather than being statically embedded in the device firmware. This allows operators to align time security policies with their broader cybersecurity governance, incident handling processes, and NIS2 compliance strategies.

However, this flexibility comes with a caveat: the underlying time mechanisms must remain robust even if operator controls fail or are misconfigured. A layered approach is therefore required, where manufacturer-provided security guarantees form a hard minimum baseline, and operator-managed controls provide additional resilience and policy enforcement on top.

In summary, while the public-Internet environment demands maximal self-contained security at the product level, secured trust-zone environments enable a more distributed responsibility model. Both must be explicitly considered in the design of critical legal time services, and both must be addressed coherently to meet the combined requirements of CRA and NIS2.



## 5. Mitigations

*Network Time Security (NTS)* infrastructure is a good start, but also has its limits!

NTS solves:
- Authenticated Time Sync
- Men-in-the-Middle protection
- Scaling to millions of NTP/NTS clients

NTS does not solve:
- Erkennung falscher, aber korrekt signierter Zeit
- Koordination mehrerer Zeitserver
- Nachweis warum Zeit vertrauenswürdig war
- Gerichtsfeste Beweisführung

➡️ Resilienz entsteht erst durch zusätzliche Audit-, Konsistenz- und Governance-Schnittstellen.


### 5.1 NTS-Policy via a Signed HTTPS JSON document

Dynamic server lists with resilient service meta data via signed HTTPS JSON documents    
Yet, DNS stays primary source! *See also: Strict Transport Security (MTA-STS)*.

- Contact Infos
- Emergency Contact Infos
- ***Available DNS-based solutions***
- Key Rotation Policy
- Rate-Limit-Policy: Avoiding Denail-of-Service by friendly clients.
- Emergency Policy: Time-Source-Loss, CA-Compromise, Massive DDoS-Attacks
- Source-Transparency (GNSS / Holdover)
- Definierte Quorum- & Degradationslogik *(min-servers: 2, max_offset_ns: 50)*
- Multiple servers should deliver the exact same information.
- Multiple digital signatures with different crypto algorithms.
- Signature(s) over deterministic, byte-exact canonical JSON representation (see: RFC 8785)


#### 5.1.2 JSON Example

```
{
    "contact":               ...

    "releaseDate":           ...
    "expectedNextUpdate":    ...

    "status":               [ "https://time.ptb.de/status" ],
    "reports":              [ "https://time.ptb.de/reports" ],
    "reporting": [
        {
            "urls":             [ "https://time.ptb.de/reporting" ],
            "format":           "json"
        },
        {
            "urls":             [ "https://time.ptb.de/reporting" ],
            "format":           "html"
        },
        {
            "email":            [ "reporting@time.ptb.de" ],
            "gpgkey":           "0x00..."
        }
    ],
    "attestations":             [ "https://time.ptb.de/attestations" ],


    "tlsMinVersion":            1.2,
    "quorum": {
        "minAgreeingServers":         2
        "maxPairwiseOffset_ns":      50
        "maxServerUncertainty_ns":  500
    },

    "hosts": [

        {
            "hostname":       "time1.ptb.de",
            "ntp": {
                "udpPort":     123,
                "tcpPort":     123
            },
            "ntske": {
                "port":        4460,
                "alpn":        "ntlske"
            },
            "tlsMinVersion":   1.2
        }

    ],
    "signatures": [
        ...
    ]
}
```

#### 5.1.3 Minimal Decision Rules

|Observation|Action|
|-|-|
| reports.overall_level=OUTAGE      | No acceptance of time syncs for calibration law relevant use cases |
| status.quorum_agreement.ok=false  | Only „best-effort“ logging, no evidence based time stamps |
| status.health.level=RED           | Remove this server from the NTP/NTS pool |


### 5.2 DNS-based Solutions

Dynamic server lists with meta data via DNS to solve redundancy, failover and additional security: *DNS-SRV, SVCB, DANE.*

DNS-based solutions are the default way to distribute information in the Internet as it scales better than other approaches.


#### 5.2.1 DNS NTS-Policy Discovery

The `_nts-policy` DNS TXT record is intended **solely for policy discovery**, not as an authoritative security policy container.

```
_nts-policy.ptbtime1.ptb.de. IN TXT "v=NTSPv1; id=ptb-nts-2025;
```
=> Policy-URL: https://ptbtime1.ptb.de/.well-known/nts-policy.json    
   Expected version identification `ptb-nts-2025`.

```
_nts-policy.ptbtime1.ptb.de. IN TXT "v=NTSPv1; id=ptb-nts-2026; d=time.ptb.de"
```
=> Policy-URL: https://time.ptb.de/.well-known/nts-policy.json    
   Expected version identification `ptb-nts-2026`.

```
_nts-policy.ptbtime1.ptb.de. IN TXT "v=NTSPv1; id=ptb-nts-2026; uri=https://ptbtime.ptb.de/.well-known/nts-policy.json"
```
=> Policy-URL: https://ptbtime.ptb.de/.well-known/nts-policy.json    
   Expected version identification `ptb-nts-2026`.

##### ABNF

```
; NTSPv1 DNS TXT Record ABNF (updated)
; References:
; - RFC 5234 (ABNF)
; - RFC 7405 (%s case-sensitive strings)
;
; Intended TXT content examples:
;   v=NTSPv1; id=ptb-nts-2026
;   v=NTSPv1; id=ptb-nts-2026; d=time.ptb.de
;   v=NTSPv1; id=ptb-nts-2026; uri=https://time.ptb.de/.well-known/nts-policy.json
;
; Note: If neither d nor uri is present, the policy URI is derived
; from the queried owner name (outside ABNF; see parsing rules).

nts-policy-txt = wsp* version wsp* ";" wsp* id-param
                 *( wsp* ";" wsp* parameter ) wsp*
                 [ ";" wsp* ]  ; optional trailing semicolon

version        = "v" wsp* "=" wsp* %s"NTSPv1"

; Required parameter
id-param       = "id" wsp* "=" wsp* id-value

; Remaining (optional) parameters
parameter      = d-param / uri-param / ext-param

d-param        = "d" wsp* "=" wsp* domain-name
uri-param      = "uri" wsp* "=" wsp* https-uri

; Extension point (clients MUST ignore unknown keys)
ext-param      = ext-key wsp* "=" wsp* ext-value

; ===== Lexical rules =====

wsp            = SP / HTAB

; id-value is stable across deployments and safe in logs.
; Example: ptb-nts-2026, ptb-nts-2025-rc1
id-value       = id-char 0*127(id-char)
id-char        = ALPHA / DIGIT / "-" / "_" / "."

; Domain name in presentation form.
; Allows optional trailing dot; clients may normalize it away.
domain-name    = label *( "." label ) [ "." ]

; Hostname label: LDH rule with no leading/trailing hyphen.
label          = ( alphanum / ( alphanum *( alphanum / "-" ) alphanum ) )

alphanum       = ALPHA / DIGIT

; HTTPS URI without SP/HTAB or ';' (parameter delimiter).
https-uri      = %s"https://" uri-rest
uri-rest       = 1*( uri-char )

; Disallow whitespace and semicolon in URIs to prevent parsing ambiguity.
uri-char       = uri-allowed / pct-encoded
uri-allowed    = unreserved / sub-delims / ":" / "@" / "/" / "?" / "#" 

unreserved     = ALPHA / DIGIT / "-" / "." / "_" / "~"
pct-encoded    = "%" HEXDIG HEXDIG
sub-delims     = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / "="

; Extension keys/values:
ext-key        = 1*( ALPHA / DIGIT / "-" / "_" )

; ext-value must be non-empty and MUST NOT contain ';' or whitespace.
; (The whitespace/semicolon restriction is enforced normatively.)
ext-value      = 1*( ext-vchar )
ext-vchar      = VCHAR
```

##### Normative Parsing Rules for _nts-policy DNS TXT Record (NTSPv1)

The following rules are normative and MUST be applied by all compliant implementations.

###### 1. TXT Record Concatenation

If a DNS TXT RR contains multiple `<character-string>` elements, the client MUST concatenate them in the order presented by DNS before applying any parsing or validation rules.

###### 2. Parameter Uniqueness

Each parameter key is **case-sensitive** and **MUST NOT** appear more than once.

- The `v` parameter **MUST** appear exactly once.
- The `id` parameter **MUST** appear exactly once.
- The `d` parameter **MUST NOT** appear more than once.
- The `uri` parameter **MUST NOT** appear more than once.

If any parameter appears more than once, the record **MUST** be rejected.

###### 3. Required Parameters

A valid `_nts-policy` TXT record **MUST** contain the following parameters:

- v
- id

If either parameter is missing, the record **MUST** be rejected.

###### 4. Version Handling

The `v` parameter **MUST** have the exact value `NTSPv1`.

Clients encountering any other version value **MUST** treat the record as unsupported and **MUST NOT** apply the policy.

###### 5. Policy URI Resolution

If the `uri` parameter is present, its value **MUST** be used as the policy retrieval URI.

If the `uri` parameter is absent and the `d` parameter is present, the client **MUST** derive the policy URI as:

https://<d>/.well-known/nts-policy.json

If both `uri` nor `d` are absent, the client MUST derive the policy retrieval URI from the base domain name associated with the _nts-policy owner name that was queried.

###### 6. Whitespace Handling

Whitespace (SP or HTAB) **MAY** appear immediately before or after the `=` and `;` separators.

Whitespace **MUST NOT** appear within parameter names or parameter values.

Clients encountering whitespace within a parameter value **MUST** reject the record.

###### 7. Parameter Value Delimiters

The semicolon character (`;`) is reserved exclusively as a parameter delimiter.

Any parameter value containing a semicolon (`;`) **MUST** cause the record to be rejected.

###### 8. Unknown Parameters (Forward Compatibility)

Parameters not explicitly defined by this specification **MUST** be ignored.

Unknown parameters **MUST NOT** affect validation of known parameters and **MUST NOT** cause the record to be rejected, unless they violate other parsing rules.

###### 9. HTTPS Requirement

Any policy URI obtained either directly from the `uri` parameter or derived via the `d` parameter **MUST** use the https scheme.

Clients **MUST** reject policies resolved to non-HTTPS URIs.

###### 10. Failure Handling

If any of the above rules are violated, the client **MUST** treat the `_nts-policy` TXT record as invalid and **MUST NOT** apply any associated NTS policy.

Clients SHOULD continue operation using previously cached valid policies until their expiration, if available.



#### 5.2.2 DNS Service Records (DNS-SRV)

Deployments that operate a resilient time service typically provide multiple server instances and require a standardized mechanism for:

- distributing client load across instances
- supporting planned maintenance and failover
- keeping client configuration minimal (one service name instead of host lists)

DNS SRV (RFC 2782) provides a widely deployed, operationally proven mechanism to publish **service endpoints** with priorities and weights. Each SRV record consists of:

- `priority`: lower values are preferred.
- `weight`: relative load distribution among records with equal priority.
- `port`: service port (e.g., 123 for NTP, 4460 for NTS-KE).
- `target`: hostname of the service instance.

```
_ntp._udp.ptb.de.       3600 IN SRV 10  50  123 ptbtime1.ptb.de.
                        3600 IN SRV 10  50  123 ptbtime2.ptb.de.
                        3600 IN SRV 20 100  123 ptbtime3.ptb.de.
                        3600 IN SRV 30 100  123 ptbtime4.ptb.de.

_ntske._tcp.ptb.de.     3600 IN SRV 10  60 4460 ptbntske1.ptb.de.
                        3600 IN SRV 10  40 4460 ptbntske2.ptb.de.
                        3600 IN SRV 20 100 4460 ptbntske3.ptb.de.
                        3600 IN SRV 30 100 4460 ptbntske4.ptb.de.
```

##### Interaction with NTS Policy Discovery

SRV discovery and NTS policy discovery serve different purposes:

- SRV provides a live set of endpoints for load-balancing and failover *(operational control plane)*.
- The NTSP policy document provides enforceable requirements and security constraints that apply to endpoints discovered via DNS SRV *(governance control plane)*.

Clients SHOULD use DNS SRV for endpoint selection and use the policy document to:

- validate that selected targets are permitted.
- constrain behavior (e.g., do not use plain NTP, require NTS-KE, etc.).
- The policy document **MUST NOT** be used to introduce additional NTP or NTS-KE endpoints that are not present in the DNS SRV records.
- If an endpoint is present in DNS SRV results but prohibited by the policy document, the client **MUST NOT** use that endpoint.
- If the intersection of DNS SRV results and policy-permitted endpoints is empty, the client **MUST** treat the service as unavailable or misconfigured and **MUST NOT** fall back to endpoints outside the intersection.


##### Interaction with NTS-KE Server List

An NTS-KE server **MAY** include a list of NTP servers that the client MAY use for subsequent NTP exchanges, indicating that NTS cookies issued by the NTS-KE server are expected to be accepted by those NTP servers.

Clients **MUST** treat NTS-KE-provided NTP server lists as constraints on preference, not as an additional discovery mechanism.

The client **MUST** compute the intersection of:

- NTP servers discovered via DNS SRV
- NTP servers permitted by the applicable NTS policy
- NTP servers provided by the NTS-KE server

If this intersection is empty, the client **MUST** treat the configuration as invalid, **MUST NOT** use the issued NTS cookies, and **MUST NOT** proceed with authenticated NTP using those cookies.


#### 5.2.3 DNS Service Binding (DNS-SVCB)

DNS SVCB (RFC 9460) is a modern variant of DNS SRV for publishing connection parameters (e.g., ALPN, port, address hints) that are directly relevant to **NTS-KE over TLS**. SVCB can therefore provide a single, cacheable, operator-controlled record that combines:

- priority
- endpoint naming (target)
- protocol selection via ALPN
- port selection
- optional address hints (IPv4/IPv6)

```
nts.ptb.de.  300 IN SVCB 1 ntske.ptb.de. alpn="ntske/1" port=4460 ipv4hint=192.53.103.108 ipv6hint=2001:638:902:abcd::1
```

As DNS SVCB records do not have an explicit weight field like DNS SRV records, weighting is done by record multiplicity to model unequal hardware capacity or the gradual rollout of new servers.

```
nts.ptb.de.  300 IN SVCB 1 ntske-fast.ptb.de. alpn="ntske/1" port=4460
nts.ptb.de.  300 IN SVCB 1 ntske-fast.ptb.de. alpn="ntske/1" port=4460
nts.ptb.de.  300 IN SVCB 1 ntske-slow.ptb.de. alpn="ntske/1" port=4460
```

Expected client behavior:

- ntske-fast is selected ~66% of the time
- ntske-slow ~33%


#### 5.2.4 DNS-based Authentication of Named Entities (DANE)

```
_4460._tcp.ntske.ptb.de.  86400 IN TLSA 3 1 1 <sha256-des-aktuellen-leaf-keys>
_4460._tcp.ntske.ptb.de.  86400 IN TLSA 2 0 1 <sha256-der-ptb-root-ca>
_4460._tcp.ntske.ptb.de.  86400 IN TLSA 2 1 1 <sha256-des-ptb-root-public-keys>
```

#### 5.2.5 DNSSEC

Useful!



### 5.3 Status-Monitoring-API

- HTTPS JSON API(primary)
- HTML for user-friedlyness

```
GET https://time1.ptb.de/status
```

- Server/Service Availability
- Max. Offset, Max. Jitter, Offset-Drift-Alarms
- Source Transparency
- Source-Disagreement-Detection
- Client kann qualifiziert entscheiden, ob Zeit verwendbar ist => Voraussetzung für automatisierte Trust-Policies.
- NIS2-konforme Transparenz


### 5.4 Logging and Traceability API (History)

Signed HTTPS JSON documents.

- Vergangene Status-Events
- „Welche Zeit wurde wann mit welcher Quelle und mit welcher Qualität ausgeliefert?“ (Time Attestation)
- Incident-Disclosure API
- Security Advisories
- CVE-Handling
- Auditierbarkeit

