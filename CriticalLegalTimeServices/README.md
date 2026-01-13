# Critical Legal Time Services

## Intro

- "Time" is source of evidence – not just a *"best-effort"* service with transport security!
- Beweisgrundlage (Forensik, Eichrecht, Haftung)
- Systemkopplungspunkt verteilter Systeme. Fehlerhafte Zeit korrumpiert korrekt arbeitende nachgelagerte Systeme ohne dass diese selbst fehlerhaft sind.
- Ein Fehler wirkt sich horizontal auf viele Betreiber aus. Angreifer braucht Sekunden, Verteidiger Wochen zur Beweisführung. Kleine Drifts bleiben lange unentdeckt, sind aber rechtlich fatal.
- "Security-by-Design" notwendig um Assymetrien aufzulösen.
- NIS2 is coming!


## Risk Analysis

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

### GNSS Spoofing

### Soft-/Hardware Error

### Time-Regression/Holdover Drift

### PKI CA Compromise

### Key-Compromise or Configuration Mistakes

### Men-in-the-Middle, Replay- or Delay-Attacks

### Denial-of-Service Attacks

### Internal Attackers



## Operational Environments

### Over the plain Internet

Clients are easily attackable


### Over the Internet with trust zones

Communication via proxies, NAT, ... additional firewalls.


## Mitigations

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


### NTS-Policy via signed HTTPS JSON documents

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


### DNS-based Solutions

Dynamic server lists with meta data via DNS to solve redundancy, failover and additional security: *DNS-SRV, SVCB, DANE.*

DNS-based solutions are the default way to distribute information in the Internet as it scales better than other approaches.

#### DNS Service Records (DNS-SRV)

```
_ntp._udp.ptb.de.       3600 IN SRV 10  50  123 time1.ptb.de.
                        3600 IN SRV 10  50  123 time2.ptb.de.
                        3600 IN SRV 20 100  123 time3.ptb.de.

_ntske._tcp.ptb.de.     3600 IN SRV 10  60 4460 ntske1.ptb.de.
                        3600 IN SRV 10  40 4460 ntske2.ptb.de.
                        3600 IN SRV 10  40 4460 ntske3.ptb.de.
```

#### DNS Service Binding (DNS-SVCB)

```
nts.ptb.de.  300 IN SVCB 1 ntske.ptb.de. alpn="ntske/1" port=4460 ipv4hint=192.53.103.108 ipv6hint=2001:638:902:abcd::1
```

#### DNS-based Authentication of Named Entities (DANE)

```
_4460._tcp.ntske.ptb.de.  86400 IN TLSA 3 1 1 <sha256-des-aktuellen-leaf-keys>
_4460._tcp.ntske.ptb.de.  86400 IN TLSA 2 0 1 <sha256-der-ptb-root-ca>
_4460._tcp.ntske.ptb.de.  86400 IN TLSA 2 1 1 <sha256-des-ptb-root-public-keys>
```

#### DNSSEC

Useful!



### Status-Monitoring-API

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


### Logging and Traceability API (History)

Signed HTTPS JSON documents.

- Vergangene Status-Events
- „Welche Zeit wurde wann mit welcher Quelle und mit welcher Qualität ausgeliefert?“ (Time Attestation)
- Incident-Disclosure API
- Security Advisories
- CVE-Handling
- Auditierbarkeit


