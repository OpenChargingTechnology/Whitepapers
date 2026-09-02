# ISO 15118 via OCPP 2.1

*Companion paper: [The ISO 15118 Tunnel](ISO15118Tunnel.md), which captures and tests the SLAC, SDP and V2G TLS layers below, so that the policies proposed here can be shown to be enforced.*

An OCPP CSMS that supports ISO 15118 today can do Plug & Charge, install certificates, run smart-charging schedules, and drive bidirectional power transfer. What it cannot manage are the layers that decide whether an ISO 15118 session starts at all: the power-line pairing between vehicle and charging station (SLAC), the discovery of the charging station's communication controller (SDP), the TLS policy of the vehicle-facing connection, and the EXI codec that encodes every V2G message. A vendor can expose these functions, but OCPP 2.1 gives them no interoperable names, so no CSMS can manage them the same way across two manufacturers.

This document maps what OCPP 2.1 Edition 2 already standardizes for ISO 15118, shows where that standardized surface ends, and proposes a future management model. The model keeps `ISO15118Ctrlr` as the umbrella controller and adds five controllers for the currently unmanaged layers: `SLACCtrlr`, `SDPCtrlr`, `V2GTLSCtrlr`, `V2GEXICtrlr`, and `V2GPKICtrlr`.

Throughout, it separates four things that OCPP tends to blur, and every proposed controller is described in these terms:

- **Capability** (read-only): what the hardware and firmware can support;
- **Operator policy** (read-write): what the operator permits within that capability and the standards;
- **Effective state** (read-only): what is actually running after defaults, safety rules, and policy resolution;
- **Telemetry** (read-only, monitorable): counters, timings, selected modes, and failures.

Unless explicitly marked as a proposal, requirement identifiers refer to OCPP 2.1 Edition 2. The proposed components and variables in this document are not part of OCPP 2.1.

## Summary

- OCPP 2.1 does not manage ISO 15118 as one end-to-end functional block. Part 2, section 2.7 distributes authorization, smart charging, certificate management, and bidirectional power transfer across several functional blocks.
- The CSMS nevertheless has substantial management surface: ISO 15118-related use cases and messages; the Device Model (`ISO15118Ctrlr`, `SmartChargingCtrlr`, `V2XChargingCtrlr`, `DCDERCtrlr`, `ACDERCtrlr`, `ConnectedEV`); generic monitoring through `SetVariableMonitoring` and `NotifyEvent`; security auditing through `SecurityEventNotification`; and vendor extension mechanisms.
- The principal standardized gap is below the application use cases: OCPP 2.1 has no interoperable model for SLAC, SDP, V2G TLS policy, EXI codec and schema state, protocol-selection policy, or authorization fallback policy.
- The fix is not a second umbrella controller. It is to reuse the existing components and add five scoped controllers, each exposing capability, operator policy, effective state, and telemetry for one layer.
- Timing budgets, a two-channel event model, certificate domain separation, atomic policy bundles, and a pre-transaction `v2gSessionId` correlation identifier are cross-cutting requirements, not per-controller details.

Phase 0 needs no change to OCPP itself:

- Define versioned custom Device Model components for the missing layers, advertised through `CustomizationCtrlr.CustomImplementationEnabled[<vendorId>]`.
- Manage them through `GetReport`, `GetVariables`, `SetVariables`, `NotifyEvent`, and `SecurityEventNotification` rather than opaque `DataTransfer`.
- Enforce distinct keys for the OCPP, ISO 15118-2, and ISO 15118-20 identities immediately, independent of future standardization.

## How an ISO 15118 session starts, and where OCPP sees it

Every ISO 15118 use case in OCPP presumes that a vehicle and a charging station have already found each other and built a secure channel. The steps that get them there run below the OCPP application layer, in this order:

1. **Control Pilot** (IEC 61851): the physical signalling state changes when the cable is plugged in (state A to B).
2. **SLAC** (ISO 15118-3): the vehicle sends a burst of sounding packets over the power line; each nearby charging station measures how much the signal is attenuated; the vehicle pairs with the station showing the least attenuation, i.e. the one it is physically plugged into. This runs directly over Ethernet (EtherType `0x88E1`), with no IP layer.
3. **SDP** (SECC Discovery Protocol): over IPv6 link-local multicast, the vehicle asks for the charging station's communication controller (the SECC) and its TLS policy.
4. **V2G TLS**: TLS 1.2 for ISO 15118-2, TLS 1.3 for ISO 15118-20.
5. **SAP and EXI**: the application protocol and version are negotiated (`SupportedAppProtocolReq`), binding a session-local `schemaID`; every V2G message from here on is EXI-encoded.
6. **V2G application**: authorization, certificate installation, scheduling, and the charge loop, i.e. the use cases OCPP already covers.

The following table shows which layer each proposed controller manages, and what the companion paper captures:

```
Layer                              OCPP 2.1 today            Proposed here      Companion paper
---------------------------------  ------------------------  -----------------  ----------------------
Control Pilot (IEC 61851, A->B)    StatusNotification,       -                  -
                                   ConnectedEV
SLAC (ISO 15118-3, 0x88E1, no IP)  -                         SLACCtrlr          L2 capture, or
                                                                                reconstructed (see 2.1)
IPv6 link-local + SDP              -                         SDPCtrlr           capture + inject
TCP + V2G TLS (1.2 for -2,         M06 OCSP cache only       V2GTLSCtrlr        handshake capture
1.3 for -20)
V2GTP + EXI (SAP -> schemaID)      ConnectedEV.ProtocolAgreed V2GEXICtrlr       capture (needs secrets)
V2G application                    C07/C08, A02/A03,         ISO15118Ctrlr      -
                                   M01-M07, K15-K20, J03,    (+ policy matrix)
                                   Q01-Q12, R01-R05
Cross-cutting: V2GPKICtrlr (identities, trust anchors, revocation)
```

One consequence matters for correlation. An OCPP `transactionId` may not exist yet during SLAC, SDP, TLS, and early authorization: depending on `TxCtrlr.TxStartPoint`, a transaction can start as late as `Authorized` or as early as `EVConnected`. Nothing below the application layer can be correlated by `transactionId`. This is why the proposed model introduces a `v2gSessionId` that exists from the moment the cable is plugged in.

## Reading guide

- **New to ISO 15118**: the primer above, then chapter 2 of the companion paper, then the "What OCPP 2.1 covers today" table.
- **CSMS and operations engineers**: "Observability and security events", the "Effective state and telemetry" rows of each proposed controller, and "Structured session and event correlation".
- **Charging-station firmware implementers**: the controller tables, "Common conventions for the proposed controllers", and "Configuration must be atomic".
- **Security and certification**: "Certificate domain separation", "Policy must be a matrix", and "Safety, resilience, and privacy".

Unfamiliar acronyms are expanded in "Terminology and abbreviations" at the end.

## What OCPP 2.1 covers today

| Area | OCPP location | Standardized management surface |
|---|---|---|
| Plug & Charge authorization | C07 | Send the eMAID and `iso15118CertificateHashData` in `AuthorizeRequest`; optionally send the contract certificate chain when central validation is allowed; return authorization and certificate status; enable PnC with `ISO15118Ctrlr.PnCEnabled` |
| EIM authorization | C08 | Authorize an External Identification Means through the CSMS. C07 informatively recommends offering EIM instead of Contract while offline; the normative offline behavior is governed by `ContractValidationOffline`, local authorization settings, and C07.FR.07-C07.FR.12 |
| Charging Station and SECC leaf certificates | A02, A03 | Trigger `SignChargingStationCertificate`, `SignV2GCertificate`, or `SignV2G20Certificate`; correlate requests with `requestId`; select a PKI with `hashRootCertificate`; address each unique SECC through its `SeccId` and EVSE scope |
| Combined OCPP and V2G certificate | A00, A02/A03, message model | `SignCombinedCertificate` exists, and omission of `certificateType` represents a certificate intended for both the OCPP and ISO 15118 connections. The message model supports this reuse, but it weakens domain separation |
| Contract certificates in the EV | M01, M02 | Tunnel the EXI `CertificateInstallationReq` or `CertificateUpdateReq` through `Get15118EVCertificate`. OCPP 2.1 adds ISO 15118-20 multi-contract handling, `maximumContractCertificateChains`, `remainingContracts`, and `prioritizedEMAIDs` |
| EXI transport and signed round trips | M01/M02 and message model | `Get15118EVCertificate` carries Base64 EXI together with `iso15118SchemaVersion`; OCPP also models ISO 15118-20 price schedules so that an EXI-to-JSON-to-EXI conversion does not invalidate their digest. Neither mechanism provides generic EXI codec management or diagnostics |
| Installed certificate inventory | M03 | Retrieve installed certificate identifiers and certificate-chain hashes with `GetInstalledCertificateIds` |
| Certificate deletion and trust-anchor installation | M04, M05 | Delete an installed certificate and install CSMS, manufacturer, MO, or V2G root certificates |
| SECC certificate OCSP status | M06 | Retrieve and cache OCSP responses for the V2G/SECC certificate chain before the EV TLS handshake. OCPP requires refresh at least weekly |
| Vehicle certificate-chain revocation | M07 | New in OCPP 2.1: check an ISO 15118-20 vehicle certificate chain by OCSP and/or CRL, including cache and `nextUpdate` handling |
| ISO 15118-2 smart charging | K15-K17 | Convert an OCPP charging profile into `SAScheduleList`, support EV- and CSMS-initiated renegotiation, and return the EV charging schedule. The CSMS `SHOULD` send the profile within 60 seconds to satisfy the ISO 15118 `ChargeParameterDiscoveryReq` timeout (K15.FR.08, K17.FR.08) |
| ISO 15118-20 smart charging | K18-K20 | Support Scheduled and Dynamic Control Mode, `V2XChargingParameters`, schedule adjustment, and optional signed `AbsolutePriceSchedule` or `PriceLevelSchedule` through `ChargingProfileType.signatureValue` |
| Metering receipts | J03 | Request an EV metering receipt before forwarding a fiscal meter value when `ISO15118Ctrlr.RequestMeteringReceipt` is true. The receipt itself is not forwarded as the OCPP meter value |
| Bidirectional power transfer | Q01-Q12 | Authorize energy-transfer services, manage operation modes, switch modes, apply schedules or dynamic setpoints, support frequency services and local load balancing, and define offline/resume behavior |
| DER control | R01-R05 | Manage DC-EVSE and AC-EV-inverter DER capabilities, send/get/clear DER controls, define precedence and persistence, and report DER start/stop and alarms |
| Connected vehicle state | `ConnectedEV` | Expose offered and agreed protocols, EVCCID/vehicle identity, ISO 15118-20 vehicle certificate chain, charging state, energy offers, limits, targets, SoC, and other values obtained throughout the V2G session |
| Generic Device Model monitoring | N03-N15 | Configure delta, threshold, target, and periodic monitors; send structured `NotifyEvent` data; queue events while offline according to severity; retrieve monitoring configuration and periodic streams |
| Vendor extensions | Part 1 Device Model, P, Part 4 | Use custom/non-standardized components and variables, `DataTransfer`, `customData`, and custom triggers. These mechanisms enable implementation-specific management but do not provide cross-vendor semantics |

### Timing is part of the management problem

The 60-second sequence timeout is not the only relevant timing constraint. Part 2, section 2.7 (Tables 9 and 10) also lists much shorter ISO 15118 budgets:

- 1.5 seconds for `AuthorizationReq/Res`, and for `AuthorizationSetupReq/Res` in ISO 15118-20;
- 4.5 seconds for `CertificateInstallationReq/Res` and `CertificateUpdateReq/Res`, and for `PaymentDetailsReq/Res` in ISO 15118-2;
- 40 seconds for sequence-performance timeouts;
- 60 seconds for sequence timeouts.

C07 adds that a contract-certificate check which cannot be completed within the `PaymentDetailsReq/Res` budget may be completed during `AuthorizationReq/Res`, which can be extended up to 60 seconds.

A future management model therefore needs explicit latency budgets, cache freshness, timeout outcomes, and per-hop telemetry. It is not sufficient to expose only a Boolean success or failure state.

## Existing Device Model

### `ISO15118Ctrlr`

OCPP 2.1 standardizes one controller specifically named `ISO15118Ctrlr`. It may exist at Charging Station or EVSE level. EVSEs controlled by the same SECC report the same `SeccId`.

Part 2 standardizes the following ISO 15118-related variables:

- general: `Enabled`;
- central/offline validation: `CentralContractValidationAllowed`, `ContractValidationOffline`;
- PnC and certificate installation: `PnCEnabled`, `V2GCertificateInstallationEnabled`, `ContractCertificateInstallationEnabled`;
- metering: `RequestMeteringReceipt`;
- SECC certificate identity: `SeccId`, `CountryName`, `OrganizationName`;
- EVSE identity: `EVSE.ISO15118EvseId`;
- session behavior and capabilities: `NotificationMaxDelay`, `ServiceRenegotiationSupport`, `SupportedProviders`, `MaxPriceElements`, `ProtocolSupported`.

The Appendices additionally list typical controller variables such as `Active`, `Complete`, `Tripped`, `Problem`, `SelftestActive`, `MaxScheduleEntries`, and `RequestedEnergyTransferMode`. The Appendix explicitly states that this list does not make every variable mandatory and does not prohibit additional variables.

### Related standardized components

OCPP 2.1 spreads ISO 15118 management across several components besides `ISO15118Ctrlr`:

| Component | ISO 15118 relevance |
|---|---|
| `SmartChargingCtrlr` | Charging-profile limits, supported schedules, tariffs, and schedule construction for ISO 15118-2/-20 |
| `V2XChargingCtrlr` | Per-EVSE enablement, supported energy-transfer and operation modes, local frequency behavior, V2X measurands, and local load-balancing thresholds |
| `DCDERCtrlr` | Nameplate and DER capabilities of a DC inverter in the EVSE |
| `ACDERCtrlr` | DER capabilities that the EVSE can emulate by controlling the EV inverter through ISO 15118-20 ChargeLoop messages |
| `ConnectedEV` | Transient vehicle and session data obtained through ISO 15118 or CHAdeMO |
| `SecurityCtrlr` | Security of the OCPP connection. It does not configure the separate V2G TLS connection |
| `MonitoringCtrlr` | Reporting and offline queuing of Device Model monitoring events |

Part 5 reflects this split in the certification profiles: the ISO 15118 profile requires `ISO15118Ctrlr` and `SmartChargingCtrlr`; bidirectional power transfer uses `V2XChargingCtrlr`; DER uses `DCDERCtrlr` and/or `ACDERCtrlr`. The OCPP 2.1 certification options also make ISO 15118-2 support a prerequisite for the ISO 15118-20 option.

### `ConnectedEV` is not just handshake telemetry

`ConnectedEV.ProtocolSupportedByEV` originates in `SupportedAppProtocolReq`, `ProtocolAgreed` records the selected protocol URI and major/minor version, and `VehicleId` originates in `SessionSetupReq`. The protocol variables do not include the session-local `schemaID`, schema-set identity, or codec result. Other values are populated later from `ChargeParameterDiscoveryReq`, `ScheduleExchangeReq`, `PowerDeliveryReq`, and the AC/DC charge loop.

Consequently, `ConnectedEV` should be described as a session-state and vehicle-data surface, not merely a report of what the vehicle offered during the initial handshake. The data is queryable and monitorable through the Device Model; it is not necessarily pushed automatically.

## What OCPP 2.1 does not standardize

OCPP 2.1 does not define standardized components or variables for:

- SLAC concurrency, validation policy, rate limiting, or match diagnostics;
- SDP security-mode policy, unicast handling, source-scope validation, or request limiting;
- V2G TLS profiles, cipher suites, handshake policy, or negotiated TLS state;
- EXI schema-set identity, session-local `schemaID`, codec profile, encode/decode failures, resource-limit enforcement, or signed-element round-trip diagnostics;
- a policy for choosing among ISO 15118 namespaces offered by an EV;
- a structured policy for allowing or rejecting PnC-to-EIM fallback;
- a V2G-session identifier that exists before an OCPP transaction and correlates SLAC, SDP, TLS, SAP/EXI, authorization, scheduling, and charge-loop events.

These functions are normally implemented inside the Charging Station. They can be exposed through custom Device Model components and variables, but OCPP 2.1 does not give them interoperable names, types, constraints, defaults, or conformance tests.

The gap is therefore not that a CSMS can never manage these layers. The gap is that it cannot do so consistently across vendors using standardized OCPP semantics.

## One failed session, two views

A concrete failure shows what the gap costs and what the proposed model adds. A vehicle asks for a session without transport-layer security (`security = 0x10` in its SDP request), the operator has configured the station to require TLS, the SECC therefore answers `0x00`, and the vehicle gives up before it ever opens a TCP connection. The charge simply does not start.

**What a CSMS sees today.** Nothing that names the cause. There is no transaction yet (SDP runs long before `TxStartPoint`), so no `TransactionEvent`. At best the station emits a `SecurityEventNotification` whose 255-character `techInfo` field is free text, with no EVSE, no severity, and no way to correlate it with anything else. Diagnosing this means sending an engineer with a Green PHY sniffer to the site.

**What the proposed model adds.** The outcome becomes queryable and monitorable. `SDPCtrlr.EffectiveSecurityMode` reports what the SECC actually answered; a `NotifyEvent` carrying `SdpSecurityPolicyViolation`, the EVSE, and a `v2gSessionId` records the rejection with structure; and `SDPCtrlr.RejectedRequestCount` increments so a fleet dashboard can see it happening across thousands of stations. To see the bytes on the wire, the CSMS opens a capture through the companion paper's mechanism.

These three surfaces correlate through one identifier:

| Surface | Correlation key | Notes |
|---|---|---|
| `NotifyEvent` | `v2gSessionId` (in `techInfo` until a structured envelope exists) | scoped, severity-graded, monitorable |
| `TransactionEvent` | `transactionId`, plus `v2gSessionId` in `customData` | exists only once a transaction has started |
| `SecurityEventNotification` | station identity and time window only | lossy by design; the reason a structured envelope is proposed |
| Packet capture (companion paper) | `captureId`, linked to `v2gSessionId` in the pcapng | the raw bytes, under separate authorization |

The rest of this document defines the controllers, events, and correlation identifier that make this view possible.

## A worked Device Model example

The proposed controllers are ordinary Device Model components, managed with the messages a CSMS already implements. A `GetReport` returns a variable like any other:

```json
{
  "component": { "name": "V2GTLSCtrlr", "evse": { "id": 1 } },
  "variable":  { "name": "EffectiveTLSVersions", "instance": "ISO15118-20" },
  "variableAttribute": [
    { "type": "Actual", "value": "TLS1.3", "mutability": "ReadOnly", "persistent": false }
  ],
  "variableCharacteristics": { "dataType": "MemberList", "valuesList": [ "TLS1.2", "TLS1.3" ] }
}
```

Operator policy is set the same way. Here the CSMS narrows the allowed TLS versions for the ISO 15118-2 namespace, and the station rejects a value that would violate the profile:

```json
// SetVariablesRequest
{ "setVariableData": [
  { "attributeType": "Actual",
    "component": { "name": "V2GTLSCtrlr", "evse": { "id": 1 } },
    "variable":  { "name": "TLSVersionsAllowed", "instance": "ISO15118-2" },
    "attributeValue": "TLS1.2" } ] }

// SetVariablesResponse
{ "setVariableResult": [
  { "attributeStatus": "Rejected",
    "component": { "name": "V2GTLSCtrlr", "evse": { "id": 1 } },
    "variable":  { "name": "TLSVersionsAllowed", "instance": "ISO15118-2" },
    "attributeStatusInfo": { "reasonCode": "BelowConformanceMinimum" } } ] }
```

The instance string (`ISO15118-2`, `ISO15118-20`) is how one controller carries per-namespace policy; the EVSE scope is expressed through `component.evse`, not through the instance. See "Common conventions for the proposed controllers".

## Observability and security events

### `SecurityEventNotification`

The standardized payload is:

```text
SecurityEventNotificationRequest = {
    type: string[0..50],
    timestamp: dateTime,
    techInfo?: string[0..255]
}
```

This message has valuable audit properties: critical security events must be queued while offline with guaranteed delivery, and implemented events must be stored in the security log.

Its structure is nevertheless station-wide and sparse. It has no explicit EVSE/connector, severity, event ID, cause, cleared state, V2G session, or transaction correlation. The Appendix assigns a static binary `Critical` property to standardized event types, but that does not communicate occurrence-specific severity and does not help proprietary events.

The standardized list contains generic OCPP and station events such as `InvalidCsmsCertificate`, `InvalidChargingStationCertificate`, `InvalidTLSVersion`, and `InvalidTLSCipherSuite`. Some can be triggered by certificate workflows also used for V2G, but there is no ISO 15118-specific taxonomy for SLAC, SDP, V2G TLS, PnC fallback, or the distinct certificate roles.

### `NotifyEvent` already provides structured context

The Device Model event path must not be ignored. `NotifyEventRequest` and `EventDataType` already provide:

- message `seqNo` and `generatedAt`;
- `eventId` and optional causal event ID;
- occurrence timestamp and trigger;
- `component`, including optional EVSE and connector addressing;
- `variable` and `variableMonitoringId`;
- optional severity from 0 to 9;
- optional `transactionId`;
- `cleared`, `techCode`, and a larger `techInfo` field.

Monitoring events can be queued offline according to `MonitoringCtrlr.OfflineQueuingSeverity`. This is configurable and does not provide the unconditional guaranteed delivery required for critical security events.

### Required two-channel model

A better ISO 15118 event model should use both existing channels:

1. `SecurityEventNotification` for high-assurance audit events that require guaranteed delivery and security-log retention;
2. `NotifyEvent` for structured, scoped, monitorable protocol and operational events.

Critical occurrences may need to be represented in both channels until OCPP defines a structured security-event envelope. The two records must share a stable event/correlation identifier to avoid ambiguity.

Business rejection must not automatically be classified as a security incident. An expired contract, unknown eMAID, normal EIM selection, or policy-compliant fallback can be ordinary operational events. Cryptographic validation failure, policy violation, replay, unauthorized trust-anchor modification, or an enforced downgrade attempt are security events.

## Certificate domain separation

### Specification facts

The following OCPP mechanisms intentionally permit certificate reuse:

- A00.FR.428 permits the Charging Station certificate to be the same certificate as the ISO 15118-2 SECC certificate;
- A00.FR.513 requires a reused certificate to satisfy the applicable ISO 15118-2 or ISO 15118-20 certificate profile;
- A00.FR.514 strongly recommends not using Extended Key Usage for compatibility with ISO 15118;
- `SignCombinedCertificate` triggers a combined Charging Station and V2G certificate;
- `SignCertificateRequest.certificateType` and `CertificateSignedRequest.certificateType` are optional, and omission denotes use for both connections.

OCPP also provides separate signing paths for `ChargingStationCertificate`, `V2GCertificate`, and `V2G20Certificate`. Implementations can therefore separate the identities, but the standard does not require them to do so.

### Risk assessment

Certificate reuse is a standard-level design weakness, not an unconditional vulnerability in every implementation. The risk materializes when an implementation actually reuses the certificate and private key.

The relevant risks are:

- one key is accepted in different TLS roles: OCPP client toward the CSMS and V2G server toward the EV;
- compromise of one protocol stack or signing interface increases the blast radius in the other domain;
- trust roots, certificate profiles, lifetimes, and renewal procedures become coupled;
- rotation or revocation needed for one protocol can interrupt the other;
- the shared identity can create avoidable cross-protocol linkability;
- Key Usage cannot distinguish TLS client authentication from TLS server authentication when both require digital signatures, while EKU is discouraged.

Both keys necessarily reside in the Charging Station. The V2G private key is not stored on the cable or PLC medium. The additional exposure comes from the locally reachable V2G protocol endpoint and its implementation, not from the physical medium holding the key.

### Required future policy

The secure default for a future management model should be:

1. distinct key pairs for OCPP client, ISO 15118-2 SECC, and ISO 15118-20 SECC identities;
2. distinct certificate-purpose metadata and trust-store domains;
3. separate HSM/secure-element key handles and authorization policies;
4. independent issuance, rotation, revocation, and rollback;
5. explicit, highly visible legacy enablement for any combined certificate;
6. an audit event whenever combined identity use or a trust-anchor change is activated.

Where an ISO 15118 certificate profile cannot use EKU, the remedy is separate keys and trust domains, not removal of the last remaining domain boundary from a shared key.

## Proposed future management model

### Design principles

The management model should expose policy and evidence, not every implementation-internal tuning parameter.

For every managed layer, it should distinguish:

| View | Mutability | Meaning |
|---|---|---|
| Capability | Read-only | What hardware and software can support |
| Operator policy | Read-write | What the operator permits within the capability and standards envelope |
| Effective state | Read-only | What is currently active after defaults, local safety rules, and policy resolution |
| Telemetry | Read-only/monitorable | Counters, timings, selected modes, failures, and last-change information |

Remote policy must only select conformant modes and must not weaken hardwired security invariants. Each variable needs standardized units, scope, default behavior, constraints, persistence, application time, and failure semantics.

### Component model

Existing OCPP components should be reused instead of introducing a second umbrella controller.

| Component | Scope | Direction |
|---|---|---|
| `ISO15118Ctrlr` | Station or EVSE | Keep as umbrella. Add operator policy for enabled protocol namespaces, authorization services, selection, fallback, and offline behavior without duplicating existing variables |
| `SmartChargingCtrlr` | Station/EVSE | Continue to manage schedule construction, limits, price information, and ISO 15118 timing capacity |
| `V2XChargingCtrlr` | EVSE | Continue to manage bidirectional operation modes, measurements, local control, and offline behavior |
| `DCDERCtrlr` / `ACDERCtrlr` | EVSE | Continue to manage DER nameplate data and controls |
| `ConnectedEV` | EVSE | Continue to expose the effective vehicle/session values, subject to data-minimization rules |
| Proposed `SLACCtrlr` | Connector where possible | Expose capabilities, effective state, safe resource policy, counters, timing, and reason-coded match failures |
| Proposed `SDPCtrlr` | EVSE/transport instance | Expose supported/allowed security modes per protocol, effective source-scope enforcement, rate-limiting state, and rejected-request counters |
| Proposed `V2GTLSCtrlr` | EVSE/SECC | Expose supported and allowed TLS profiles per ISO namespace, effective negotiated version/cipher, handshake counters, and revocation freshness |
| Proposed `V2GEXICtrlr` | EVSE/SECC | Expose the active schema set and EXI profile, session-local schema selection, bounded codec policy, reason-coded encode/decode failures, timings, sizes, and resource-limit counters |
| Proposed `V2GPKICtrlr` | Station or SECC | Expose certificate-purpose inventory, trust-store generation, rotation state, expiry, revocation freshness, and whether legacy combined identity use is active |

#### Common conventions for the proposed controllers

The following tables define a minimum interoperable management surface, not an implementation-specific list of tuning knobs. `RO` and `RW` denote read-only and read-write variables. Policy variables are persistent; current-session state is transient; counters are monotonic until an explicitly reported reset. List values use Device Model `MemberList` or `SequenceList` semantics and a standardized registry, not vendor-defined free text.

A bracketed suffix denotes a Variable instance, carried in the OCPP `Variable.instance` field (`identifierString[0..50]`). `<namespace>` identifies a protocol and service profile. This document uses the short tokens `ISO15118-2`, `ISO15118-20-AC`, `ISO15118-20-DC`, and `ISO15118-20-WPT`, which map onto the `<uri>` values already reported in `ISO15118Ctrlr.ProtocolSupported` and `ConnectedEV.ProtocolAgreed` (for example `urn:iso:15118:2:2013:MsgDef` and `urn:iso:std:iso:15118:-20:DC`). A full URN would also fit the field, but the short tokens keep instance names readable; the extension specification must fix one set. `<certificatePurpose>`, `<peerRole>`, and `<trustDomain>` are likewise controlled enumerations. EVSE scope is expressed through `Component.evse`, never through the instance.

An unsupported value, a value outside the advertised capability, or a combination that would violate the applicable ISO 15118 profile must be rejected with `SetVariableStatus` and a machine-readable `statusInfo.reasonCode`. A policy change must not alter an active V2G session. It is applied `OnIdle`, at an explicitly agreed activation time, or as part of the atomic policy bundle described below.

`OnIdle` has a precise meaning here. Idle means no V2G session is running on the addressed EVSE, and, where one SECC serves several EVSEs, on none of that SECC's EVSEs. An `OnIdle` write is accepted immediately as the variable's `Target` attribute, promoted to `Actual` at the next idle transition, and visible through both `Actual` and `PolicyRevisionApplied`. Applied policy persists across reboot; effective state, counters, and any active lease do not.

**Secure defaults.** Every read-write policy variable has a defined default, and the defaults fail safe:

| Variable | Default | Note |
|---|---|---|
| `SDPCtrlr.SecurityPolicy` | `TLSRequired` | `TLSAllowed` is opt-in; the ISO 15118-20 instance is fixed at `TLSRequired` |
| `SDPCtrlr.RespondToUnicast` | `false` | |
| `V2GTLSCtrlr.StapledStatusPolicy` | `ProtocolDefault` | |
| `V2GEXICtrlr.ValidationMode` | `Strict` | |
| `V2GEXICtrlr.DiagnosticDetail` | `Metadata` | never raw EXI |
| `V2GEXICtrlr.FailureFingerprintPolicy` | `Disabled` | |
| `V2GPKICtrlr.IdentitySeparationPolicy` | `SeparatePerPurpose` | |
| `V2GPKICtrlr.RevocationUnavailableAction` | `ProtocolDefault` | not `Reject`, so C07 central/offline validation is not broken |
| `V2GPKICtrlr.MaximumCachedRevocationAgeSeconds` | `86400` | hard cap `604800`, never beyond `nextUpdate` |
| `ISO15118Ctrlr.FallbackPolicy` | `EIMOnBusinessRejection` | never on a cryptographic or transport-security failure |

**Phase 0a: the smallest read-only subset.** A vendor can ship value before any policy variable exists, by exposing only effective state and telemetry: per controller, `Available` and `State`, the negotiated or effective values (`NegotiatedTLSVersion`, `EffectiveSecurityMode`, `ActiveSchemaSetDigest`, `EffectiveIdentitySeparation`), the last-result and last-reason variables, and the counters. This is enough for fleet monitoring and post-mortem diagnosis. Phase 0b then adds the operator-policy variables. See "Incremental delivery".

#### Proposed `ISO15118Ctrlr` extensions

`ISO15118Ctrlr` stays the umbrella controller. Every other proposed controller manages one layer and defers the cross-layer decisions to a deterministic policy matrix that lives here: which namespace is selected, whether authorization falls back from PnC to EIM, and whether any allowed path remains after a lower layer fails. OCPP 2.1 already exposes the capability view as `ProtocolSupported`. The following variables add the operator-policy and effective-state views that OCPP does not yet define. They do not duplicate the existing `ISO15118Ctrlr` variables.

##### Operator policy

| Variable | Type | Access | Instance | Application | Meaning and constraints |
|---|---|---:|---|---|---|
| `ProtocolEnabled` | Boolean | RW | `<namespace>` | `OnIdle` | Enables this namespace as operator policy; it may not enable a namespace absent from `ProtocolSupported` |
| `AuthorizationServicesAllowed` | MemberList | RW | `<namespace>` | `OnIdle` | Allowed subset of `PnC` and `EIM` for this namespace |
| `NamespacePreference` | SequenceList | RW | none | `OnIdle` | Deterministic selection order among enabled namespaces when the EV offers more than one |
| `FallbackPolicy` | OptionList | RW | `<namespace>` | `OnIdle` | `None`, `EIMOnBusinessRejection`, or `EIMOnAnyFailure`; a cryptographic or policy failure never silently downgrades transport security |

##### Effective state and telemetry

| Variable | Type | Access | Instance | Meaning |
|---|---|---:|---|---|
| `SelectedNamespace` | OptionList | RO | none | Namespace chosen for the current or most recent session |
| `SelectionReason` | OptionList | RO | none | `HighestPreferenceOffered`, `OnlyOneOffered`, `FallbackAfterFailure`, or `NoCommonProtocol` |
| `AuthorizationServiceUsed` | OptionList | RO | none | `PnC`, `EIM`, or `None` |
| `FallbackExecuted` | Boolean | RO, monitorable | none | Whether PnC-to-EIM fallback was taken in the current or most recent session |
| `LastSessionOutcome` | OptionList | RO, monitorable | none | `Started`, `RejectedByPolicy`, `NoCommonProtocol`, `AuthorizationFailed`, or `LowerLayerFailed` |

The policy is a matrix, not a set of global switches; see "Policy must be a matrix". A minimal expression looks like this, and the `SelectionReason` and `LastSessionOutcome` telemetry then reports which row was applied and why:

```json
{
  "ProtocolEnabled":            { "ISO15118-20-DC": true, "ISO15118-2": true },
  "NamespacePreference":        [ "ISO15118-20-DC", "ISO15118-2" ],
  "AuthorizationServicesAllowed": { "ISO15118-20-DC": [ "PnC", "EIM" ], "ISO15118-2": [ "PnC", "EIM" ] },
  "FallbackPolicy":             { "ISO15118-20-DC": "EIMOnBusinessRejection", "ISO15118-2": "EIMOnBusinessRejection" }
}
```

#### Proposed `SLACCtrlr`

`SLACCtrlr` exposes the outcome and health of the SLAC pairing on the Control Pilot. It is scoped to the connector where the hardware allows it. The design is deliberately capability-and-telemetry first: SLAC runs on timers of tens to hundreds of milliseconds, so almost nothing here is a remotely tunable production knob. One hardware reality bounds the whole controller: on modems that terminate SLAC internally, the MMEs never reach the host and the controller can only report the modem's summary, not observe the exchange. See §2.1 of the companion paper.

##### Capabilities

| Variable | Type | Access | Instance | Meaning and constraints |
|---|---|---:|---|---|
| `Available` | Boolean | RO | none | The connector implements the proposed SLAC management surface |
| `SlacVisibility` | OptionList | RO | none | `HostTerminated` (MMEs reach the host and are observable) or `ModemTerminated` (only the modem's summary is available) |
| `AttenuationProfileAvailable` | Boolean | RO | none | Whether the modem exposes the per-sounding attenuation profile used for the match decision |

##### Operator policy

| Variable | Type | Access | Instance | Application | Meaning and constraints |
|---|---|---:|---|---|---|
| `Enabled` | Boolean | RW | none | `OnIdle` | Enables SLAC handling on this connector |
| `ConcurrencyPolicy` | (group) | RW | none | `OnIdle` | Bounded limit on concurrent and repeated match attempts, with standardized units, burst semantics, and exhaustion behavior; not a single token-bucket integer |

##### Effective state and telemetry

| Variable | Type | Access | Instance | Meaning |
|---|---|---:|---|---|
| `State` | OptionList | RO | none | `Idle`, `Sounding`, `Matching`, `Matched`, or `Failed` for the current plug-in |
| `LastMatchResult` | OptionList | RO | none | `Matched`, `NoMatch`, `TimedOut`, or `InternalError` |
| `LastMatchFailureReason` | OptionList | RO | none | Stable reason such as `NoSounExchange`, `AttenuationImplausible`, `ValidationFailed`, `Timeout`, or `Reconstructed` (modem-side, not observed) |
| `MatchAttemptCount` | Integer | RO, monitorable | none | Total SLAC match attempts |
| `MatchFailureCount` | Integer | RO, monitorable | none | Failed SLAC match attempts |

#### Proposed `SDPCtrlr`

`SDPCtrlr` manages the SECC Discovery Protocol responder and the transport-security mode it advertises. SDP is answered before `SupportedAppProtocol`, so this decision is made per SECC and independently of the later application-protocol negotiation; a `NoTLS` answer implicitly excludes ISO 15118-20 for that session. One component instance represents one SECC, placed like `V2GTLSCtrlr`.

##### Capabilities

| Variable | Type | Access | Instance | Meaning and constraints |
|---|---|---:|---|---|
| `Available` | Boolean | RO | none | The SECC implements the proposed SDP management surface |
| `SecurityModesSupported` | MemberList | RO | `<namespace>` | Implemented transport-security modes, `TLS` and/or `NoTLS` |

##### Operator policy

| Variable | Type | Access | Instance | Application | Meaning and constraints |
|---|---|---:|---|---|---|
| `Enabled` | Boolean | RW | `<namespace>` | `OnIdle` | Enables SDP responses for this namespace |
| `SecurityPolicy` | OptionList | RW | `<namespace>` | `OnIdle` | `TLSRequired` or `TLSAllowed`; for an ISO 15118-20 instance only `TLSRequired` is valid |
| `RespondToUnicast` | Boolean | RW | none | `OnIdle` | Whether the SECC answers SDP requests sent directly to its address rather than to the link-local multicast group; default `false` |
| `RequestRateLimit` | (group) | RW | none | `OnIdle` | Bounded limit on SDP requests, with standardized units, burst semantics, scope, and exhaustion behavior; not a single integer |

##### Effective state and telemetry

| Variable | Type | Access | Instance | Meaning |
|---|---|---:|---|---|
| `EffectiveSecurityMode` | OptionList | RO | `<namespace>` | The transport-security mode the SECC actually answered with |
| `LinkLocalSourceEnforced` | Boolean | RO | none | Whether requests from a non-link-local source are rejected. Normally a hardwired `true`, not a production toggle |
| `RejectedRequestCount` | Integer | RO, monitorable | none | SDP requests rejected for any reason |
| `LastRejectionReason` | OptionList | RO | none | `SourceNotLinkLocal`, `PolicyViolation`, `RateLimited`, or `MalformedHeader` |

`LinkLocalSourceEnforced` replaces the raw `RequireLinkLocalSource` switch from an earlier draft: source-scope enforcement is a hardwired invariant exposed as effective state, not a freely disabling production variable. The companion paper's §10.6 test verifies these variables from the CSMS side by injecting SDP requests and checking the responses.

#### Proposed `V2GTLSCtrlr`

`V2GTLSCtrlr` manages the SECC-side TLS policy and exposes TLS handshake evidence. It does not configure the OCPP TLS connection, store certificates, decide application-protocol fallback, or replace `ISO15118Ctrlr`. One component instance represents one SECC. It can be reported at Charging Station level when one SECC serves the whole station, or at EVSE level; EVSEs with the same `SeccId` must report consistent capability and policy values.

##### Capabilities

| Variable | Type | Access | Instance | Meaning and constraints |
|---|---|---:|---|---|
| `Available` | Boolean | RO | none | The SECC implements the proposed TLS management surface |
| `TLSVersionsSupported` | MemberList | RO | `<namespace>` | TLS protocol versions implemented for this ISO 15118 namespace/profile |
| `CipherSuitesSupported` | MemberList | RO | `<namespace>` | Implemented cipher suites using their IANA names |
| `SignatureAlgorithmsSupported` | MemberList | RO | `<namespace>` | Implemented TLS handshake signature algorithms |
| `SignatureAlgorithmsCertSupported` | MemberList | RO | `<namespace>` | Implemented certificate-signature algorithms that can be accepted for the profile |
| `PeerAuthenticationModesSupported` | MemberList | RO | `<namespace>` | Supported peer-authentication modes, for example `ServerOnly` or `Mutual`; only modes permitted by the profile may be advertised |
| `OCSPStaplingSupported` | Boolean | RO | `<namespace>` | Whether the SECC can supply the status evidence required by the profile from its local V2G PKI cache |

##### Operator policy

| Variable | Type | Access | Instance | Application | Meaning and constraints |
|---|---|---:|---|---|---|
| `Enabled` | Boolean | RW | `<namespace>` | `OnIdle` | Enables TLS support for this namespace; it does not enable the ISO 15118 namespace itself |
| `TLSVersionsAllowed` | MemberList | RW | `<namespace>` | `OnIdle` | Allowed subset of `TLSVersionsSupported`; it may not exclude a version required for conformance and keep the namespace enabled |
| `CipherSuitesAllowed` | MemberList | RW | `<namespace>` | `OnIdle` | Allowed subset of `CipherSuitesSupported` and of the applicable ISO 15118 profile |
| `CipherSuitePreference` | SequenceList | RW | `<namespace>` | `OnIdle` | Deterministic server preference restricted to `CipherSuitesAllowed`; ignored where the protocol fixes the selection behavior |
| `SignatureAlgorithmsAllowed` | MemberList | RW | `<namespace>` | `OnIdle` | Allowed subset of `SignatureAlgorithmsSupported` and the profile requirements |
| `SignatureAlgorithmsCertAllowed` | MemberList | RW | `<namespace>` | `OnIdle` | Allowed subset for certificate-chain validation; this is distinct from TLS handshake signatures |
| `PeerAuthenticationPolicy` | OptionList | RW | `<namespace>` | `OnIdle` | One advertised value such as `ServerOnly` or `Mutual`; a mode not permitted by the profile is rejected rather than emulated |
| `StapledStatusPolicy` | OptionList | RW | `<namespace>` | `OnIdle` | `ProtocolDefault` or `RequireFresh`; `RequireFresh` fails closed when current status evidence for the SECC chain is unavailable |
| `HandshakeTimeoutMs` | Integer | RW | `<namespace>` | `OnIdle` | Local TLS handshake budget in milliseconds, bounded by a standardized safe range and by the ISO 15118 communication-setup timer (`V2G_EVCC_CommunicationSetup`, about 20 s), not the 60-second sequence timeout |

For ISO 15118-2, the effective TLS version is TLS 1.2. For ISO 15118-20, it is TLS 1.3. These are therefore separate namespace instances, not values in one global minimum-version switch. The allowed lists are useful for expressing exact profile capability, future revisions, and cryptographic deprecation, but never authorize cross-version downgrade. A TLS failure must not silently cause plaintext or EIM fallback; the deterministic policy matrix in `ISO15118Ctrlr` decides whether another previously allowed path exists.

##### Effective state and telemetry

| Variable | Type | Access | Instance | Meaning |
|---|---|---:|---|---|
| `EffectiveTLSVersions` | MemberList | RO | `<namespace>` | Resolved list after capability, operator policy, conformance rules, and local security minima |
| `EffectiveCipherSuites` | SequenceList | RO | `<namespace>` | Resolved ordered list used by the SECC |
| `EffectivePeerAuthenticationMode` | OptionList | RO | `<namespace>` | Authentication mode actually enforced |
| `State` | OptionList | RO | `<namespace>` | `Disabled`, `Ready`, `Negotiating`, `Established`, `Closing`, or `Failed` for the current EVSE session |
| `NegotiatedTLSVersion` | OptionList | RO | `<namespace>` | Version selected for the current or most recently completed handshake |
| `NegotiatedCipherSuite` | OptionList | RO | `<namespace>` | Cipher suite selected for the current or most recently completed handshake |
| `NegotiatedSignatureAlgorithm` | OptionList | RO | `<namespace>` | TLS signature algorithm selected for the current or most recently completed handshake |
| `PeerCertificatePresented` | Boolean | RO | `<namespace>` | Whether the selected mode caused a peer certificate to be presented; no certificate data is exposed |
| `StapledStatusState` | OptionList | RO | `<namespace>` | `NotApplicable`, `Fresh`, `Stale`, `Unavailable`, or `Rejected` for status evidence supplied with the SECC chain |
| `LastHandshakeResult` | OptionList | RO | `<namespace>` | `Succeeded`, `RejectedByPolicy`, `FailedByPeer`, `TimedOut`, or `InternalError` |
| `LastHandshakeFailureReason` | OptionList | RO | `<namespace>` | Stable reason taxonomy including version, cipher, signature, certificate, revocation, timeout, peer-alert, local-policy, and internal failures |
| `LastHandshakeDurationMs` | Integer | RO | `<namespace>` | End-to-end TLS handshake duration in milliseconds |
| `PolicyRevisionApplied` | String | RO | `<namespace>` | Hash or version of the atomic policy bundle that produced the effective configuration |
| `HandshakeAttemptCount` | Integer | RO, monitorable | `<namespace>` | Total initiated handshakes |
| `HandshakeSuccessCount` | Integer | RO, monitorable | `<namespace>` | Successful handshakes |
| `HandshakeFailureCount` | Integer | RO, monitorable | `<namespace>` | Failed handshakes |
| `PolicyRejectionCount` | Integer | RO, monitorable | `<namespace>` | Handshakes rejected because no offered mode satisfied effective policy |
| `HandshakeTimeoutCount` | Integer | RO, monitorable | `<namespace>` | Handshakes terminated by the local handshake budget or protocol timeout |

The state variables describe only the current or last session. Historical detail is emitted as `NotifyEvent` data correlated by `v2gSessionId`. `LastHandshakeFailureReason` must use separate codes such as `NoCommonVersion`, `NoCommonCipherSuite`, `UnsupportedSignatureAlgorithm`, `CertificateExpired`, `CertificateRevoked`, `CertificateStatusUnknown`, `StaleRevocationData`, `PeerAlert`, `Timeout`, `LocalPolicy`, and `InternalError`; a single `TLSFailed` value is not operationally sufficient.

#### Proposed `V2GEXICtrlr`

`V2GEXICtrlr` manages and observes the ISO 15118 EXI codec boundary: `SupportedAppProtocol` decoding, binding the session-local `schemaID` to the agreed protocol, schema-informed encoding/decoding, resource protection, and signed-element round-trip stability. One component instance represents one SECC and follows the same Charging Station/EVSE placement rule as `V2GTLSCtrlr`. Shared capabilities and policy may be reported at Charging Station level, but current-session state and per-session-derived counters must remain EVSE-scoped when a shared SECC serves multiple EVSEs.

It does not select the application protocol, interpret the business meaning of a valid message, validate a certificate signature, or provide a generic raw-payload tunnel. `ISO15118Ctrlr` remains responsible for protocol selection and the V2G state machine; `V2GPKICtrlr` validates cryptographic trust; raw forensic data belongs to a separately authorized capture/log mechanism, described in [The ISO 15118 Tunnel](ISO15118Tunnel.md).

OCPP 2.1 already exposes `ConnectedEV.ProtocolSupportedByEV` and `ConnectedEV.ProtocolAgreed`. These remain authoritative for the offered and selected URI/version. The EXI controller adds the missing codec evidence. In particular, `schemaID` is assigned within `SupportedAppProtocolReq` and is meaningful only in that session; it must never be treated as a fleet-wide schema version. A useful correlation tuple is therefore `{ProtocolAgreed, SelectedSchemaId, ActiveSchemaSetDigest}`.

##### Failure ownership

| Failure | Owning component | EXI controller contribution |
|---|---|---|
| Invalid V2GTP version/inverse byte, payload type, or declared length | V2G transport/capture layer | None; the EXI decoder was not safely reached |
| Malformed `SupportedAppProtocolReq` or invalid `schemaID` binding | `V2GEXICtrlr` plus selection policy in `ISO15118Ctrlr` | Report decode result and session-local schema binding; the umbrella controller reports the selection decision |
| Malformed EXI grammar, datatype, facet, occurrence, or length | `V2GEXICtrlr` | Report exact stage, reason, safe location, size, timing, and counter |
| Syntactically valid message in the wrong V2G state | `ISO15118Ctrlr` | Report decode success only; do not relabel it as an EXI error |
| Signed-element serialization cannot reproduce the expected digest | `V2GEXICtrlr` and `V2GPKICtrlr` | EXI reports a signed-element round-trip mismatch; PKI reports the cryptographic verification result |
| Certificate-chain, purpose, or revocation failure | `V2GPKICtrlr` | None beyond the successfully decoded field location |
| TLS record, alert, or handshake failure | `V2GTLSCtrlr` | None; no EXI document was available |

##### Capabilities

| Variable | Type | Access | Instance | Meaning and constraints |
|---|---|---:|---|---|
| `Available` | Boolean | RO | none | The SECC implements the proposed EXI management surface |
| `EXIProfilesSupported` | MemberList | RO | `<namespace>` | Standards-defined EXI profiles implemented for this ISO 15118 namespace, including schema-informed and signed-element encoding requirements |
| `SchemaSetVersion` | String | RO | `<namespace>` | Human-readable version of the installed, approved schema bundle |
| `SchemaSetDigest` | String | RO | `<namespace>` | Deterministic digest of the exact schema/profile bundle used to generate or configure the codec |
| `SignedElementRoundTripSupported` | Boolean | RO | `<namespace>` | Whether the implementation can reproduce the required EXI representation of signed elements without changing their digest |
| `StreamingDecodeSupported` | Boolean | RO | `<namespace>` | Whether input is decoded incrementally without first allocating the declared document size |
| `MaximumInboundDocumentBytes` | Integer | RO | `<namespace>` | Maximum conformant inbound EXI document size supported by the implementation |
| `MaximumOutboundDocumentBytes` | Integer | RO | `<namespace>` | Maximum conformant outbound EXI document size supported by the implementation |
| `MaximumNestingDepth` | Integer | RO | `<namespace>` | Hard decoder nesting limit |
| `MaximumArrayElements` | Integer | RO | `<namespace>` | Hard occurrence/list-element limit supported by the decoder |
| `MaximumStringCharacters` | Integer | RO | `<namespace>` | Hard supported decoded character count for string values |
| `MaximumBinaryLengthBytes` | Integer | RO | `<namespace>` | Hard supported binary-field length, relevant to certificates, signatures, and schedule data |
| `FailureBitOffsetSupported` | Boolean | RO | none | Whether a failure can be located at a bit offset in the EXI stream |
| `SchemaPathReportingSupported` | Boolean | RO | none | Whether a failing grammar/schema path can be reported without disclosing field values |

`SchemaSetDigest` identifies schemas and codec-generation inputs, not executable code. Updating those artifacts is a signed firmware or signed schema-package operation with rollback protection, not a `SetVariables` payload.

##### Operator policy

| Variable | Type | Access | Instance | Application | Meaning and constraints |
|---|---|---:|---|---|---|
| `ValidationMode` | OptionList | RW | `<namespace>` | `OnIdle` | `Strict` or `ExtensionAware`; the latter accepts only extension points explicitly allowed by the applicable schema, never arbitrary unknown elements |
| `InboundDocumentLimitBytes` | Integer | RW | `<namespace>` | `OnIdle` | Operator limit not greater than `MaximumInboundDocumentBytes`; it may not be set below the largest mandatory conformant message while the namespace is enabled |
| `OutboundDocumentLimitBytes` | Integer | RW | `<namespace>` | `OnIdle` | Equivalent limit for generated documents |
| `DecodeTimeBudgetMs` | Integer | RW | `<namespace>` | `OnIdle` | Bounded decoder CPU-time budget that remains compatible with the applicable ISO 15118 response timeout |
| `EncodeTimeBudgetMs` | Integer | RW | `<namespace>` | `OnIdle` | Bounded encoder CPU-time budget compatible with the response timeout |
| `DiagnosticDetail` | OptionList | RW | none | immediate | `CountersOnly`, `Metadata`, or `MetadataWithSchemaPath`; no value permits raw EXI or decoded field values in ordinary events |
| `FailureFingerprintPolicy` | OptionList | RW | none | immediate | `Disabled` or `SessionScopedHmac`; a session-scoped keyed fingerprint can group repeated malformed inputs without creating a stable vehicle fingerprint |
| `FailureSampleLimitPerSession` | Integer | RW | none | immediate | Maximum detailed EXI failure events per V2G session; counters continue after the limit |
| `DiagnosticRetentionSeconds` | Integer | RW | none | immediate | Retention of last-failure metadata, with a standardized upper bound and automatic clearing |

Lenient parsing, ignored required fields, unchecked `maxOccurs`, unbounded allocations, raw payload logging, and acceptance after a resource-limit violation are not production policy options. Test-only malformed-message tolerance must use the locally authorized and time-bounded test mechanism described below.

##### Effective state and telemetry

| Variable | Type | Access | Instance | Meaning |
|---|---|---:|---|---|
| `State` | OptionList | RO | none | `Disabled`, `Ready`, `NegotiatingSchema`, `Active`, or `Failed` for the current EVSE session |
| `SelectedSchemaId` | Integer | RO | none | Session-local `schemaID` returned by the `SupportedAppProtocol` handshake; `-1` when none is selected and otherwise meaningless without `ProtocolAgreed` |
| `ActiveSchemaSetVersion` | String | RO | `<namespace>` | Schema bundle actually used after staged activation and local policy resolution |
| `ActiveSchemaSetDigest` | String | RO | `<namespace>` | Digest of the active bundle, used for fleet comparison and event correlation |
| `ActiveEXIProfile` | OptionList | RO | `<namespace>` | Exact EXI profile enforced for this namespace |
| `LastDirection` | OptionList | RO | none | `EVtoSECC` or `SECCtoEV` for the last codec operation |
| `LastDecodedMessageType` | OptionList | RO | none | Message type if it could be determined safely; `Unknown` when decoding failed before that point |
| `LastDecodeResult` | OptionList | RO | none | `Succeeded`, `RejectedMalformed`, `RejectedSchema`, `RejectedResourceLimit`, `TimedOut`, or `InternalError` |
| `LastEncodeResult` | OptionList | RO | none | `Succeeded`, `InvalidApplicationModel`, `RejectedResourceLimit`, `TimedOut`, or `InternalError` |
| `LastFailureStage` | OptionList | RO | none | `SupportedAppProtocol`, `EXIHeader`, `Grammar`, `Datatype`, `SchemaFacet`, `ResourceLimit`, `ApplicationMapping`, or `SignedElementEncoding` |
| `LastFailureReason` | OptionList | RO | none | Stable detailed reason code from the taxonomy below |
| `LastFailureBitOffset` | Integer | RO | none | Bit offset of the first detected codec failure, or `-1` when unavailable; no captured bytes are included |
| `LastFailureSchemaPath` | String | RO | none | Bounded schema/grammar path without values, subject to `DiagnosticDetail` |
| `LastInputDocumentBytes` | Integer | RO | none | Encoded size of the last inbound document |
| `LastOutputDocumentBytes` | Integer | RO | none | Encoded size of the last outbound document |
| `LastDecodeDurationUs` | Integer | RO | none | Decoder duration in microseconds |
| `LastEncodeDurationUs` | Integer | RO | none | Encoder duration in microseconds |
| `LastFailureFingerprint` | String | RO | none | Session-scoped opaque HMAC when enabled; cleared with the session |
| `PolicyRevisionApplied` | String | RO | none | Hash or version of the atomic policy bundle that produced the effective configuration |
| `SchemaNegotiationFailureCount` | Integer | RO, monitorable | none | Failed `SupportedAppProtocol` negotiations attributable to syntax or schema binding |
| `UnknownSchemaIdCount` | Integer | RO, monitorable | none | Responses or internal bindings referencing a `schemaID` not present in the current offer |
| `DecodeAttemptCount` | Integer | RO, monitorable | `<namespace>` | Total EXI decode attempts |
| `DecodeFailureCount` | Integer | RO, monitorable | `<namespace>` | Failed EXI decode attempts |
| `EncodeAttemptCount` | Integer | RO, monitorable | `<namespace>` | Total EXI encode attempts |
| `EncodeFailureCount` | Integer | RO, monitorable | `<namespace>` | Failed EXI encode attempts |
| `MalformedDocumentCount` | Integer | RO, monitorable | `<namespace>` | Invalid EXI header, options, grammar, or truncated streams |
| `SchemaConstraintViolationCount` | Integer | RO, monitorable | `<namespace>` | Datatype, enumeration, required-element, occurrence, or facet violations |
| `ResourceLimitExceededCount` | Integer | RO, monitorable | `<namespace>` | Size, nesting, list, memory, or time budget violations |
| `SignedElementRoundTripMismatchCount` | Integer | RO, monitorable | `<namespace>` | Signed elements whose required EXI representation could not be reproduced without changing the digest |

The minimum reason-code registry should distinguish at least `MalformedSupportedAppProtocol`, `DuplicatePriority`, `NoCommonProtocol`, `SelectedSchemaIdNotOffered`, `NamespaceVersionMismatch`, `InvalidEXIHeader`, `UnsupportedEXIOptions`, `UnexpectedEndOfInput`, `InvalidEventCode`, `MissingRequiredElement`, `UnexpectedElement`, `MaxOccursExceeded`, `InvalidEnumeration`, `ValueOutOfRange`, `InvalidDateTime`, `InvalidBinaryLength`, `DocumentTooLarge`, `NestingLimitExceeded`, `MemoryBudgetExceeded`, `CodecTimeout`, `InvalidApplicationModel`, `SignedElementRoundTripMismatch`, and `InternalError`.

##### Structured EXI failure reporting

A `V2GExiDecodeFailed` or `V2GExiEncodeFailed` event should carry only:

- `v2gSessionId`, EVSE, direction, and timestamp;
- `ConnectedEV.ProtocolAgreed`, session-local `SelectedSchemaId`, and `ActiveSchemaSetDigest`;
- message type when known, failure stage, reason code, bit offset, and value-free schema path;
- encoded document size, processing duration, applicable limit, and optional session-scoped HMAC fingerprint;
- policy revision and whether detailed-event rate limiting was applied.

It must not carry the raw EXI document, decoded values, eMAID, certificate material, signatures, meter values, schedules, prices, or stable vehicle identifiers. Raw payloads are large and can contain personal, contractual, cryptographic, and commercially sensitive data. If they are indispensable for a supervised investigation, they belong in a separately authorized, encrypted, bounded capture with explicit retention and access logging.

`NotifyEvent` is appropriate for the structured metadata and monitorable counters. Repeated resource-limit violations, an active schema-set change, or a signed-element round-trip mismatch can additionally trigger a `SecurityEventNotification`; ordinary interoperability errors should not automatically be classified as attacks.

##### Binding to existing OCPP surfaces

| Existing surface | What it already provides | What `V2GEXICtrlr` adds |
|---|---|---|
| `ConnectedEV.ProtocolSupportedByEV` / `ProtocolAgreed` | Offered priority list and agreed protocol URI/version | Session-local `schemaID`, exact active schema bundle/profile, and negotiation failure reason |
| M01/M02 `Get15118EVCertificate` | Base64 EXI request/response and `iso15118SchemaVersion` for certificate installation/update | Codec result, latency, size, schema binding, and reason-coded failures; no duplicate raw-payload variable |
| `OCPPCommCtrlr.FieldLength` for `exiRequest` / `exiResponse` | Supported OCPP field length when larger than the schema minimum | Local decoded-document and resource limits; distinction between OCPP envelope rejection and EXI rejection |
| ISO 15118-20 price-schedule OCPP datatypes and `digestValue` | A JSON representation intended to survive EXI round trips without invalidating the digest | Active signed-element encoding profile and explicit round-trip mismatch evidence |
| Packet/log capture | Full forensic bytes under separate authorization | Low-volume, privacy-preserving operational evidence suitable for normal monitoring |

#### Proposed `V2GPKICtrlr`

`V2GPKICtrlr` owns V2G certificate-purpose policy, key separation, trust-store state, rotation state, and revocation evidence. It does not transfer private keys or certificate bytes through Device Model variables. Existing OCPP certificate use cases remain the operational protocol: A02/A03 for SECC certificate signing, M03 for inventory, M04/M05 for deletion and trust-anchor installation, M06 for SECC-chain OCSP data, M07 for vehicle-chain OCSP/CRL data, and M01/M02 for EV contract-certificate installation or update.

The station-level instance reports shared trust domains. A per-SECC/EVSE instance reports leaf-certificate and key state. Typical controlled instances are:

- `<certificatePurpose>`: `Secc15118_2` and `Secc15118_20` for local identities;
- `<peerRole>`: `VehicleContract` and `VehicleOem` for peer-chain validation;
- `<trustDomain>`: `V2G`, `MobilityOperator`, and `VehicleOEM`.

The OCPP client certificate remains owned by the OCPP security controller. `V2GPKICtrlr` only reports whether a V2G identity is improperly shared with that domain.

##### Capabilities

| Variable | Type | Access | Instance | Meaning and constraints |
|---|---|---:|---|---|
| `Available` | Boolean | RO | none | The station implements the proposed V2G PKI management surface |
| `CertificatePurposesSupported` | MemberList | RO | none | Local V2G leaf-certificate purposes supported by the implementation |
| `TrustDomainsSupported` | MemberList | RO | none | Independently managed V2G trust domains |
| `KeyGenerationAlgorithmsSupported` | MemberList | RO | `<certificatePurpose>` | Algorithms available when producing a CSR for this purpose |
| `KeyProtectionLevelsSupported` | MemberList | RO | `<certificatePurpose>` | `Software`, `TPM`, `SecureElement`, or `HSM`; the registry must define the assurance semantics |
| `RevocationMethodsSupported` | MemberList | RO | `<peerRole>` | `OCSP`, `CRL`, or both, as supported for the relevant chain |
| `IndependentKeyPerPurposeSupported` | Boolean | RO | none | Whether OCPP, ISO 15118-2, and ISO 15118-20 can use separate private keys |
| `DualCertificateRotationSupported` | Boolean | RO | `<certificatePurpose>` | Whether old and new leaf certificates can coexist during verified rollover |
| `MaximumTrustAnchors` | Integer | RO | `<trustDomain>` | Capacity of the trust store for this domain |
| `MaximumCertificateChainSize` | Integer | RO | `<certificatePurpose>` | Maximum accepted chain size in bytes; reuse the existing OCPP value where it already covers the purpose |

##### Operator policy

| Variable | Type | Access | Instance | Application | Meaning and constraints |
|---|---|---:|---|---|---|
| `IdentitySeparationPolicy` | OptionList | RW | none | `OnIdle` or restart | `SeparatePerPurpose`, `SeparateOcppAndV2G`, or `LegacyCombined`; the secure default is `SeparatePerPurpose` |
| `AutomaticRenewalEnabled` | Boolean | RW | `<certificatePurpose>` | immediate | Allows the station to start the existing A02/A03 signing workflow before expiry |
| `RenewalLeadTimeSeconds` | Integer | RW | `<certificatePurpose>` | immediate | Time before `notAfter` at which renewal starts, with standardized minimum, maximum, and fleet-jitter behavior |
| `MinimumRemainingValiditySeconds` | Integer | RW | `<certificatePurpose>` | `OnIdle` | Minimum remaining leaf-certificate validity required to start a new V2G session |
| `RevocationUnavailableAction` | OptionList | RW | `<peerRole>` | `OnIdle` | `Reject`, `UseFreshCachedGood`, or `ProtocolDefault`; it cannot override a fail-closed profile requirement |
| `MaximumCachedRevocationAgeSeconds` | Integer | RW | `<peerRole>` | immediate | Upper age bound for cached OCSP/CRL evidence; it is capped at seven days and never extends beyond `nextUpdate` |
| `RevocationRefreshLeadTimeSeconds` | Integer | RW | `<peerRole>` | immediate | How long before `nextUpdate` a refresh should be requested, with jitter to avoid fleet-wide bursts |
| `TrustAnchorRolloverPolicy` | OptionList | RW | `<trustDomain>` | atomic, `OnIdle` | `AtomicReplace`, `DualTrustWindow`, or `ManualCommit`; a new store is validated before activation |
| `TrustAnchorOverlapSeconds` | Integer | RW | `<trustDomain>` | atomic, `OnIdle` | Bounded overlap for `DualTrustWindow`; zero for other rollover policies |
| `CertificateActivationPolicy` | OptionList | RW | `<certificatePurpose>` | atomic | `OnIdle`, `OnRestart`, or `ImmediateIfUnused`; activation during a session is prohibited |

Remote policy may retain or strengthen identity separation. Activating `LegacyCombined` is a privileged local exception, must be time-bounded where possible, and generates a critical audit event; an ordinary `SetVariables` request cannot silently weaken the policy. Deleting the last valid trust anchor, activating an unvalidated chain, exporting a private key, accepting an expired or revoked certificate, and extending revocation freshness beyond `nextUpdate` are hard invariants rather than configurable options.

##### Effective state and telemetry

| Variable | Type | Access | Instance | Meaning |
|---|---|---:|---|---|
| `EffectiveIdentitySeparation` | OptionList | RO | none | Identity separation actually enforced after capability and local security policy |
| `CombinedIdentityActive` | Boolean | RO, monitorable | none | A V2G certificate or key is currently shared with the OCPP client identity |
| `CertificateState` | OptionList | RO | `<certificatePurpose>` | `Missing`, `Staged`, `Active`, `Expiring`, `Expired`, `Invalid`, or `Revoked` |
| `ActiveCertificateId` | String | RO | `<certificatePurpose>` | Opaque identifier that can be reconciled with the M03 inventory; never a DER (Distinguished Encoding Rules) or PEM certificate, nor private-key material |
| `CertificateNotBefore` | DateTime | RO | `<certificatePurpose>` | Start of the active leaf certificate's validity interval |
| `CertificateNotAfter` | DateTime | RO, monitorable | `<certificatePurpose>` | End of the active leaf certificate's validity interval |
| `KeyProtectionLevel` | OptionList | RO | `<certificatePurpose>` | Effective protection of the active private key |
| `PrivateKeyExportable` | Boolean | RO, monitorable | `<certificatePurpose>` | Must normally be `false`; a transition to `true` is a critical security event |
| `RotationState` | OptionList | RO | `<certificatePurpose>` | `Idle`, `CSRRequested`, `AwaitingCertificate`, `Staged`, `Validating`, `AwaitingActivation`, `RollingBack`, or `Failed` |
| `LastRotationResult` | OptionList | RO | `<certificatePurpose>` | `Succeeded`, `Rejected`, `ValidationFailed`, `ActivationFailed`, `RolledBack`, or `TimedOut` |
| `LastRotationAt` | DateTime | RO | `<certificatePurpose>` | Time of the most recent completed rotation attempt |
| `TrustStoreGeneration` | String | RO, monitorable | `<trustDomain>` | Monotonic generation or content hash of the active trust-store set |
| `ActiveTrustAnchorCount` | Integer | RO, monitorable | `<trustDomain>` | Number of active anchors |
| `StagedTrustAnchorCount` | Integer | RO | `<trustDomain>` | Number of anchors staged but not active |
| `RevocationStatus` | OptionList | RO | `<peerRole>` | `Good`, `Revoked`, `Unknown`, `Stale`, or `Error` for the latest validation |
| `RevocationEvidenceSource` | OptionList | RO | `<peerRole>` | `LiveOCSP`, `CachedOCSP`, `CachedCRL`, `CentralValidation`, or `None` |
| `RevocationThisUpdate` | DateTime | RO | `<peerRole>` | Issuance time of the evidence used for the latest decision |
| `RevocationNextUpdate` | DateTime | RO, monitorable | `<peerRole>` | Expiry time of the evidence used for the latest decision |
| `LastValidationFailureReason` | OptionList | RO | `<peerRole>` | Stable reason such as chain, signature, purpose, validity, trust-anchor, revocation, freshness, or internal failure |
| `CertificateInstallRejectedCount` | Integer | RO, monitorable | `<certificatePurpose>` | Rejected or invalid certificate installations |
| `CertificateRotationFailureCount` | Integer | RO, monitorable | `<certificatePurpose>` | Failed rotations including rollback |
| `TrustAnchorChangeCount` | Integer | RO, monitorable | `<trustDomain>` | Successful active trust-store changes |
| `RevocationRefreshFailureCount` | Integer | RO, monitorable | `<peerRole>` | Failed OCSP/CRL refresh attempts |
| `PeerCertificateValidationFailureCount` | Integer | RO, monitorable | `<peerRole>` | Peer chains rejected by V2G PKI validation |
| `LegacyCombinedIdentityActivationCount` | Integer | RO, monitorable | none | Activations of the legacy shared OCPP/V2G identity mode |

`ActiveCertificateId` and `TrustStoreGeneration` are correlation identifiers, not a second certificate inventory. Their canonical representation and access control must be standardized to avoid vendor-specific parsing and unnecessary fleet fingerprinting.

##### Binding to existing OCPP certificate workflows

| Management intent | Existing OCPP mechanism | Required controller behavior |
|---|---|---|
| Create or renew an ISO 15118-2 or ISO 15118-20 SECC identity | A02/A03 `SignCertificate` / `CertificateSigned` | Expose CSR, staging, validation, activation, rollback, and final purpose-specific state; correlate by `requestId` |
| Select the intended PKI | A02/A03 `hashRootCertificate` | Verify the returned chain against that trust domain and reject cross-domain substitution |
| Inventory installed certificates | M03 `GetInstalledCertificateIds` | Keep `ActiveCertificateId`, state, purpose, and inventory consistent |
| Install or delete a trust anchor | M05 `InstallCertificate`, M04 `DeleteCertificate` | Stage and validate the new set, activate it atomically, increment `TrustStoreGeneration`, and emit an audit event |
| Refresh SECC-chain status evidence | M06 `GetCertificateStatus` | Update the evidence used for TLS stapling without extending freshness beyond `nextUpdate` |
| Validate a vehicle chain | M07 `GetCertificateChainStatus` | Record OCSP/CRL source, freshness, and result separately for the applicable peer role |
| Install or update an EV contract certificate | M01/M02 `Get15118EVCertificate` | Treat the EXI payload as an end-to-end application object; do not expose it in Device Model variables or diagnostic events |
| Validate a contract centrally | C07 `Authorize` | Keep the PKI validation result separate from the business authorization result |

The cross-controller boundary is strict: `SDPCtrlr` advertises and filters the transport security mode, `V2GTLSCtrlr` enforces the selected TLS profile, `V2GEXICtrlr` enforces the selected schema/codec profile, `V2GPKICtrlr` supplies identity and trust decisions, and `ISO15118Ctrlr` owns application-protocol, message-state, and PnC/EIM selection. None of these controllers may infer a fallback merely because the preceding layer failed.

### Policy must be a matrix

Simple global values such as `TLSPreferred`, `VersionDowngradePolicy`, or `EIMFallbackPolicy` are ambiguous. Policy decisions depend on at least:

- ISO 15118 namespace and energy-transfer service;
- wired or wireless transport;
- PnC or EIM authorization service;
- TLS/security mode offered by the EV;
- EVSE/connector capability;
- online/offline state and certificate-status freshness;
- operator minimum-security policy.

The policy surface should therefore express allowed combinations and deterministic selection order. This is what the proposed `ISO15118Ctrlr` extensions above provide: `ProtocolSupported` remains the capability view, `ProtocolEnabled`, `NamespacePreference`, `AuthorizationServicesAllowed`, and `FallbackPolicy` express operator policy, and `SelectedNamespace` with `SelectionReason` report the resolved decision as effective state and telemetry.

### Configuration must be atomic

Changing protocol, TLS, authorization, fallback, and certificate policies with unrelated `SetVariables` operations can leave an unsafe partial configuration.

A future policy bundle needs:

- schema and policy version;
- validation/dry-run;
- stage and commit;
- `applyAt` or `OnIdle` semantics;
- all-or-nothing application across related variables;
- rollback and last-known-good state;
- explicit `RebootRequired` handling;
- old/new policy hashes in the audit log.

### Structured session and event correlation

Depending on `TxCtrlr.TxStartPoint`, an OCPP `transactionId` may not exist yet during SLAC, SDP, TLS, SAP/EXI, and early authorization. A future model therefore needs an opaque, locally generated, privacy-preserving `v2gSessionId` that exists from plug-in and can correlate the complete chain without exposing an eMAID, certificate, or stable vehicle identifier.

Concretely, `v2gSessionId` is a 128-bit random value in lowercase hexadecimal, allocated once when the cable is plugged in (Control Pilot state B, or the first SLAC frame) and held across SLAC retries and any ISO 15118 pause/resume. It is never derived from the EVCCID, a MAC address, or an eMAID, and it is distinct from the ISO 15118 `SessionID` carried in `SessionSetupRes`. It appears in every `NotifyEvent` and `SecurityEventNotification` for the session, in the `transactionId` correlation once a transaction starts (through `customData`), and in the capture Custom Block. On a station whose SECC runs on a separate SoC, it is generated once and shared, so both sides label the same session identically.

A structured ISO 15118 event should contain:

- event ID, timestamp, layer, protocol phase, and reason code;
- EVSE and connector;
- `v2gSessionId` and optional `transactionId`;
- policy decision and outcome: allowed, rejected, rate-limited, fallback, or failure;
- occurrence severity, cause, and cleared state;
- counters or durations where relevant;
- no raw certificates, eMAIDs, challenges, private material, or unnecessary vehicle identifiers.

Suggested event semantics include:

| Event | Default classification | Important qualification |
|---|---|---|
| `SlacMatchRateLimited` | Operational warning; security if sustained | Rate limiting is evidence of load or abuse, not proof of an attacker |
| `SlacAttenuationAnomaly` | Operational/security anomaly | An implausible profile is not by itself proof of a relay or rogue EVSE |
| `SlacValidationFailed` | Operational or security | Include reason and policy result |
| `SdpSecurityPolicyViolation` | Security | A peer requested a mode prohibited by effective policy |
| `SdpSourceScopeRejected` | Security/operational | Include source class, not a full identifying address unless needed |
| `V2GTlsPolicyViolation` | Security | Split version, cipher, signature, and security-mode reasons |
| `V2GSchemaNegotiationFailed` | Operational/security anomaly | Include protocol offers, selected policy, and reason without treating every incompatibility as an attack |
| `V2GExiDecodeFailed` | Operational; security if malformed or repeated | Include stage, reason, safe location, size, and session-scoped fingerprint, never the payload |
| `V2GExiResourceLimitExceeded` | Security/operational | Identify the exceeded size/time/nesting/list limit and whether detailed-event rate limiting was applied |
| `V2GExiSignedElementRoundTripMismatch` | High-severity integrity event | Keep the EXI reproducibility failure distinct from PKI signature verification |
| `V2GPeerCertificateValidationFailed` | Security | Identify certificate purpose and failure reason without sending the certificate |
| `V2GTrustAnchorChanged` | High-severity security audit | Include old/new trust-store generation or hash, actor, and outcome |
| `PnCFallbackExecuted` | Operational notice | Security only when unexpected or policy-forced by a suspicious failure |
| `PnCFallbackDenied` | Security/operational | Include violated policy and preceding cause |
| `PnCAuthorizationRejected` | Business/operational | Do not treat an ordinary contract rejection as a security incident |

The existing OCPP severity scale 0-9 should be used for `NotifyEvent`; critical security events additionally use the guaranteed-delivery security channel.

### Why the obvious knobs are not enough

The naive way to manage these layers is a handful of raw Boolean switches. Each one is either unsafe or underspecified, and the controllers above replace it with a capability, a bounded policy, and effective-state evidence:

| Naive variable | Problem | Replaced by |
|---|---|---|
| `RequireLinkLocalSource` (Boolean) | A freely disabling switch turns off a security invariant | `SDPCtrlr.LinkLocalSourceEnforced` as effective state, normally a hardwired `true` |
| A single rate-limit integer | No units, burst, scope, or exhaustion semantics; assumes one token-bucket implementation | A rate-limit policy group with standardized units and safe bounds |
| A scalar attenuation min/max | Does not model an SLAC attenuation profile and can damage interoperability | `SLACCtrlr` capability and reason-coded telemetry, not a remote threshold |
| `ClientCertRequired` (Boolean) | Can expose a non-conformant production mode for penetration testing | `V2GTLSCtrlr.PeerAuthenticationPolicy`, restricted to profile-conformant modes |
| `RequireOCSPStapling` (Boolean) | Hides cache freshness and the actual result | `V2GTLSCtrlr.OCSPStaplingSupported` plus `StapledStatusPolicy` and `StapledStatusState` |

Four design rules follow, and the controllers above already apply them:

- TLS versions and cipher suites are scoped per ISO 15118 namespace and profile, never copied from the separate OCPP Security Profile 2/3 configuration.
- EXI document lengths, occurrence counts, nesting, and processing time are checked before allocation or iteration wherever possible, and the session-local `schemaID` is always reported together with the agreed protocol and active schema-set digest.
- Valid EXI in the wrong V2G phase is a state-machine error, not a decoder error; raw EXI and decoded field values never appear in ordinary OCPP events or Device Model variables.
- Test-only behavior must be locally authorized, time-limited, clearly indicated, and automatically reverted, never a persistent production variable.

### Safety, resilience, and privacy

A complete future management design also needs:

- fail-safe behavior for loss of CSMS connectivity during PnC, V2X, and DER operation;
- maximum acceptable age for cached OCSP/CRL information and an explicit stale-status policy;
- power direction, SoC reserve, grid-code, and local safety constraints that remote policy cannot override;
- defined precedence among CSMS, local EMS, grid/DER controls, EV requests, and hardware limits;
- latency histograms and timeout-reason telemetry for every V2G phase;
- message-size and codec-latency histograms, with schema/namespace labels but without vehicle identifiers or decoded values;
- bounded queues, deduplication, coalescing, and flood protection for events;
- least-privilege access to policy changes and certificate operations;
- retention limits, pseudonymization, and access control for `ConnectedEV.VehicleId`, vehicle certificates, offered protocols, and session traces;
- conformance tests for safe defaults, unsupported-policy rejection, partial failure, rollback, offline recovery, downgrade prevention, and event correlation.

## Incremental delivery

### Phase 0: OCPP 2.1-compatible vendor extension

- Define versioned custom Device Model components for the missing layers.
- Advertise support through `CustomizationCtrlr.CustomImplementationEnabled[<vendorId>]`.
- Use `GetReport`, `GetVariables`, `SetVariables`, and Device Model monitoring instead of opaque `DataTransfer` wherever possible.
- Use `NotifyEvent` for structured layer telemetry and `SecurityEventNotification` for critical audit events.
- Enforce distinct OCPP, ISO 15118-2, and ISO 15118-20 keys immediately, independent of future standardization.
- For packet-level evidence that these policies are enforced, the capture lifecycle of [The ISO 15118 Tunnel](ISO15118Tunnel.md) is deployable on OCPP 2.1 as its transport profile 1, with no protocol change.

Phase 0 splits naturally in two. **Phase 0a** exposes only the read-only effective-state and telemetry subset described in "Common conventions", which already delivers fleet monitoring and post-mortem diagnosis. **Phase 0b** adds the operator-policy variables and their safe defaults once the read side is trusted.

### Phase 1: proposed OCPP standardization

- Standardize missing components, scopes, variables, enums, constraints, and defaults.
- Add a structured security-event envelope or align security events with `EventDataType` while preserving guaranteed delivery.
- Add V2G-session correlation and atomic policy bundles.
- Define interoperability and negative-security test cases.

### Phase 2: certification and operations

- Add certification profiles for SLAC/SDP/TLS/EXI policy and telemetry.
- Test downgrade, fallback, schema negotiation, malformed/truncated EXI, parser resource exhaustion, signed-element round trips, certificate separation, trust-anchor rollover, timeout, flood, offline, and recovery scenarios.
- Publish operational baselines and migration rules for legacy combined certificates.

## Priorities

| Priority | Action |
|---|---|
| P0 | Enforce separate certificate keys for the OCPP, ISO 15118-2, and ISO 15118-20 identities; use M03-M07 as the operational certificate protocol; distinguish `SecurityEventNotification` from `NotifyEvent` |
| P1 | Define the versioned custom Device Model extension including `V2GEXICtrlr`, session correlation, policy matrix, structured event taxonomy, and atomic configuration workflow |
| P2 | Standardize and certify the missing layer-management semantics across vendors |

## Terminology and abbreviations

| Term | Meaning |
|---|---|
| CSMS | Charging Station Management System, the operator's backend the station connects to over OCPP |
| SECC | Supply Equipment Communication Controller, the ISO 15118 endpoint inside the charging station |
| EVCC | Electric Vehicle Communication Controller, the ISO 15118 endpoint inside the vehicle |
| EVCCID | The EVCC identifier, in practice the vehicle's MAC address; a stable vehicle identifier |
| SLAC | Signal Level Attenuation Characterization (ISO 15118-3), the power-line step that pairs the vehicle with the station it is plugged into |
| SDP | SECC Discovery Protocol, by which the vehicle finds the SECC and its transport-security mode over IPv6 link-local multicast |
| V2GTP | Vehicle-to-Grid Transport Protocol, the small header that frames SDP and V2G messages |
| SAP | `SupportedAppProtocol`, the ISO 15118 handshake that agrees the protocol namespace and version and binds a session-local `schemaID` |
| EXI | Efficient XML Interchange, the binary encoding of every V2G application message |
| schemaID | A number chosen by the vehicle in the SAP handshake, meaningful only within that session; not a fleet-wide schema version |
| PnC | Plug & Charge, ISO 15118 authorization using a contract certificate in the vehicle |
| EIM | External Identification Means, authorization by any other means (RFID, app, payment terminal) |
| eMAID | e-Mobility Account Identifier, the identity in a PnC contract certificate; identifies the contract holder |
| MO | Mobility Operator, the party that issues the contract certificate |
| V2G | Vehicle-to-Grid; here, the ISO 15118 communication between vehicle and station, secured or not |
| V2X | Bidirectional power transfer (vehicle to grid, home, or load) |
| DER | Distributed Energy Resource. Note: in a certificate context, "DER" instead means Distinguished Encoding Rules, an X.509 encoding |
| namespace | One ISO 15118 protocol and service profile, e.g. `ISO15118-2` or `ISO15118-20-DC` (see "Common conventions") |
| management surface | The set of variables, messages, and events through which a CSMS can configure, observe, and control a function |
| v2gSessionId | The proposed pre-transaction correlation identifier defined in "Structured session and event correlation" |
| HSM / TPM | Hardware Security Module / Trusted Platform Module, hardware that holds a private key so it cannot be exported |
| CSR | Certificate Signing Request, sent to have a certificate issued |
| OCSP / CRL | Online Certificate Status Protocol / Certificate Revocation List, the two ways to check whether a certificate is revoked |
