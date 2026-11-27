# Chargy in the Vehicle: Meter Readings, Vehicle-Side Measurement and a Signed Charging Report over ISO 15118

**Status:** Concept paper, draft for discussion.

**Version:** 0.3 (2026-11-27)

**Point of contact:** Achim Friedland, GraphDefined GmbH

**Prototype:** in [EVCLI](https://github.com/OpenChargingCloud/EVCLI) and the [WWCP\_ISO15118](https://github.com/OpenChargingCloud/WWCP_ISO15118) stack. The first two steps are built, see Sections 11.5 and 11.6.

## 1. Summary

ISO 15118 carries the charging station's meter readings to the vehicle and lets the vehicle acknowledge them with a signature. Both parts of the standard even reserve a field for the meter's own signature. In practice the chain is complete in none of the five stacks examined: each implements a different half, and none had the ISO 15118-20 confirmation as a working flow. Our stack now has one as a prototype, so far checked only against itself.

The vehicle's receipt is also only an acknowledgement of receipt. The car signs the station's number, not its own measurement. And the driver sees none of it.

This paper therefore proposes **Chargy in the Vehicle**. Before energy flows, the vehicle compares its clock with the station's and the meter's. During charging it verifies the signed meter readings live and compares them with the measurements of its own battery system, using the meter's digital calibration certificate. At the end it issues its own signed charging report.

Three groups benefit:

- **Drivers**, most of all when charging bidirectionally. A vehicle that feeds energy back is the seller, and today it is paid according to the buyer's meter alone.
- **Metrology authorities.** A fleet of reporting vehicles acts as a travelling standard across all stations, and a vehicle with a calibrated reference meter is a test instrument that needs no test load.
- **Operators**, who get a second, independent record for every disputed session.

The core works without changing the standard, over ISO 15118-20. Three small extensions would turn it into a charging record signed by both sides. The revision of the Measuring Instruments Directive points the same way: it lets the measurement result be made accessible through a device of the end user.

The paper is based on the XSD schemas of the standard, on requirement identifiers, and on the source code of the stacks in our interoperability rig. Normative text is paraphrased, never quoted.

## 2. ISO 15118-2: MeterInfo out, MeteringReceipt back

In ISO 15118-2 the meter reading rides on the charge-loop response, and the station can demand a signed receipt for it. The sequence:

1. The station sends an optional `MeterInfo` in `ChargingStatusRes` (AC) or `CurrentDemandRes` (DC).
2. If it also sets `ReceiptRequired = true`, the vehicle must send a `MeteringReceiptReq` next.
3. The `MeteringReceiptReq` contains `SessionID`, `SAScheduleTupleID` and the station's `MeterInfo`, echoed unchanged.
4. The vehicle signs this body with the private key of the contract certificate: XMLDSig in the header, ECDSA P-256 with SHA-256 over the EXI-encoded fragment (`[V2G2-903]`).
5. The station answers with `MeteringReceiptRes` and continues the charge loop.

`MeterInfoType` has five elements, of which only the first is mandatory:

| Element | Type | Meaning |
| --- | --- | --- |
| `MeterID` | string | identifier of the meter |
| `MeterReading` | unsignedLong, Wh | meter register |
| `SigMeterReading` | base64Binary, at most 64 bytes | the meter's signature over its reading |
| `MeterStatus` | short | status word of the meter |
| `TMeter` | long, Unix seconds | the meter's timestamp |

Three things limit this:

- **Plug & Charge only.** Without a contract certificate there is no key, so an EIM session has no signed receipt.
- **Verification is optional.** `[V2G2-904]` is a *may*: the station may verify the signature, or pass receipt and certificate on to a secondary actor. `[V2G2-481]` (`FAILED_MeteringSignatureNotValid`) applies only if the station requires a valid signature.
- **The receipt confirms receipt, not correctness.** The clause says explicitly that the vehicle does not thereby confirm the amount of energy for billing. A note concedes that the vehicle may be unable to verify `SigMeterReading` at all.

The requirement with teeth is on the outbound side: under `[V2G2-902]` the `MeterInfo` must be the unaltered output of the meter. What exactly `SigMeterReading` signs, the standard does not say.

## 3. ISO 15118-20: the vehicle may ask, the receipt gets richer

ISO 15118-20 keeps the principle, but partly reverses the initiative and separates the receipt from the charge loop.

- **The vehicle asks.** `MeterInfoRequested = true` in the `ChargeLoopReq` is the vehicle's only lever (`[V2G20-1081]`). The station then *shall* return `MeterInfo` (`[V2G20-1082]`). A station equipped with a meter shall also send an initial value in the very first response (`[V2G20-1833]`).
- **The station demands the receipt by notification.** It sets `EVSENotification = MeteringConfirmation` and includes `MeterInfo` (`[V2G20-1083]`).
- **The receipt is called `MeteringConfirmationReq`.** It carries a `SignedMeteringData` with `SessionID`, `MeterInfo`, an optional `Receipt` (time anchor, energy, occupancy, additional-service and tax costs) and one branch per control mode. The element has an `Id` and is thus the signed fragment.
- **Stronger cryptography.** The signature is ECDSA P-521 with SHA-512, or Ed448.
- **A message stream of its own.** The confirmation travels as its own V2GTP payload type beside the charge loop and does not hold it up.
- **Every message is timestamped.** The ISO 15118-20 header carries a `TimeStamp`, so the vehicle sees the station's clock from the first response on.

|  | ISO 15118-2 | ISO 15118-20 |
| --- | --- | --- |
| Carrier of the reading | `ChargingStatusRes`, `CurrentDemandRes` | `AC_`/`DC_ChargeLoopRes` |
| Who initiates | the station only | vehicle (`MeterInfoRequested`) or station |
| Energy fields | one register in Wh | charged, discharged (BPT), capacitive and inductive reactive energy |
| Meter's signature | `SigMeterReading`, at most 64 bytes | `MeterSignature`, at most 64 bytes |
| Vehicle's receipt | `MeteringReceiptReq` | `MeteringConfirmationReq` with `SignedMeteringData` |
| Receipt covers | session, tariff tuple, MeterInfo | session, MeterInfo, cost receipt, control mode |
| Signature algorithm | ECDSA P-256 / SHA-256 | ECDSA P-521 / SHA-512 or Ed448 |
| Trigger | `ReceiptRequired` | `EVSENotification = MeteringConfirmation` |

The chain is linked more tightly here than in ISO 15118-2: without `MeterInfo` there is neither a confirmation nor a kWh-based receipt (`[V2G20-1919]`). A station that never sets the element has made the whole path unreachable.

Two weaknesses remain. The 64 bytes hold exactly one raw P-256 signature `r‖s`, which is not even enough for the curves ISO 15118-20 prescribes elsewhere. And here, too, nothing defines what the meter signs.

## 4. What the stacks actually implement

No third-party stack has the complete chain, and none has the ISO 15118-20 confirmation as a flow. Ours has had one since 27 November 2026, from the prototype (Section 11.6). State of the source trees in our rig on 26 November 2026, with our own row updated for the prototype:

| Stack (revision) | -2: station sends MeterInfo | -2: meter signature | -2: vehicle signs receipt | -2: station verifies receipt | -20: MeterInfo | -20: MeteringConfirmation |
| --- | --- | --- | --- | --- | --- | --- |
| Ours (WWCP\_ISO15118) | yes | yes, own convention | yes | yes, verdict logged per receipt | yes, AC and DC, with `MeterSignature`; vehicle can ask, EVCLI's does in every charge loop | yes, AC and DC: station asks, vehicle signs, station verifies; a prototype, checked only against itself |
| Josev (`d645255`) | no, commented out in the code | no | yes, if demanded and over TLS | yes, aborts on failure | yes, if the vehicle asks, unsigned; its own EVCC never asks | a TODO and the failure response only |
| EVerest `EvseV2G` (2026.02.1, deprecated) | yes, 2 of 5 elements | no | (station only) | no, and does not forward it | (-2 only) | (-2 only) |
| EVerest C++ stack (2026.10.0, `74845c57`) | yes | no | yes, new EV side | yes | no: the request is read, the response never set | omitted, per its own documentation |
| eVDriveFlow (`60249c3`, -20 only) | (-20 only) | (-20 only) | (-20 only) | (-20 only) | no, generated classes only | no, classes and a timeout entry only |
| tux-evse (`fc51088`, replayer) | replays what the scenario dictates | no | encoders for -2 and DIN exist | no logic of its own | no -20 part in the JSON interface | no |

Three observations:

- **Everyone has a different half.** Josev verifies a receipt for a record it never sends itself. EVerest's old module sends the record and drops the receipt into an empty function, which we measured on the wire.
- **Nobody but us sends the meter's signature.** And ours is a simulator convention (`"V2G-METER-1"`, protocol byte, SessionID, MeterID, reading, time), not a legal-metrology format.
- **ISO 15118-20 is almost empty.** Only Josev and we answer the vehicle's request, Josev with a fixed simulator value. EVerest reads `MeterInfoRequested` and answers byte-identically whether asked or not (control run of 10 August 2026). Release 2026.10.0 still sets the element in none of its -20 charge-loop states.

Our own stack already has two building blocks for what follows: `SigningMeter` on the station side, and `EvMeter`, a counter of the vehicle's own that is never fed from the station's answer.

## 5. What today's signature proves, and what it does not

Even fully implemented, the standard's mechanism proves only that a certain contract received a certain record. For transparency in the sense of legal metrology, six things are missing:

1. **The meter's key.** 64 bytes hold a signature, but no public key, no serial number and no format identifier. A key supplied by the station itself only shows that nothing changed in transit.
2. **The signed content.** Real meters sign a record with start and end register, time, user identification and meter status, for instance as OCMF. `MeterInfo` contains fragments of that. Without the exact signed bytes the vehicle can verify nothing.
3. **A statement of the vehicle's own.** The car echoes the station's number. Its own measurement appears in no message.
4. **The right identity.** The signing key is the contract key. It identifies the energy contract, not the vehicle and not its measuring equipment.
5. **EIM sessions.** Without Plug & Charge, ISO 15118-2 has no receipt at all.
6. **The human.** None of this reaches a display. Transparency software checks an invoice days later, instead of the charging session while it runs.

Point 3 matters most. A signature protects a number from being altered after the measurement. Whether the measurement is right, only a second, independent measurement can show, and the only one that is present at every charging session anyway sits in the car.

## 6. Chargy in the Vehicle: the concept

Chargy in the Vehicle is the live view of the Chargy web app, except that it runs in the car, takes its data straight from the ISO 15118 session, and puts a second measurement beside the station's. A tool for checking invoices becomes a measuring partner during charging.

### 6.1 First, compare the clocks

The first thing the vehicle does, before any energy flows, is compare clocks. Every later check rests on it.

Three clocks meet in a session:

| Clock | Where the vehicle reads it | Reference quality |
| --- | --- | --- |
| Station controller | header `TimeStamp` of every ISO 15118-20 message, from `SessionSetupRes` on | whatever the station synchronises to |
| Meter | `MeterTimestamp` (-20) or `TMeter` (-2), and the timestamp inside the signed record, which in OCMF carries its own synchronisation status | the legally relevant one |
| Vehicle | satellite time, or authenticated network time | independent of the station |

Why this comes first:

- **A time-of-use tariff turns a clock error into a price error.** The quantity can be exactly right and the invoice still wrong.
- **The sample-by-sample comparison needs a common time axis.** On a 300 kW ramp, two seconds of offset look like an energy deviation.
- **Session binding uses time.** A signed record from the wrong hour belongs to somebody else.
- **It costs one subtraction.** The offset is known after the first exchange, to within half the round-trip time, and before the driver has authorised anything. A station whose clock is implausible can be flagged before charging starts.

The vehicle records the offsets of both station clocks at the start and at the end of the session. The difference is the drift, and the two station clocks disagreeing with each other is a finding of its own. All of it goes into the charging report.

ISO 15118-2 has no header timestamp. There the meter's `TMeter` is the only clock the vehicle sees, and only once a `MeterInfo` arrives.

How the station should obtain legally defensible time is the subject of two companion papers: [Secure Time Synchronization for OCPP](../SecureTimeSync/README.md) and [Critical Legal Time Services](../CriticalLegalTimeServices/README.md).

### 6.2 Building blocks

| Block | Task | Exists |
| --- | --- | --- |
| V2G tap | takes `MeterInfo`, meter signature, timestamps, tariff and receipt from the EVCC; sets `MeterInfoRequested` | in the stack: `Evcc20Base.RequestMeterInfo` |
| Clock comparison | offsets of station and meter clock against the vehicle's reference | in the stack: `ClockComparison`; shown on EVCLI's Charging page |
| Receipt signer | signs the station's reading when asked, as `MeteringConfirmationReq` | in the stack: `Evcc20Base`, ISO 15118-20 AC and DC; shown on EVCLI's Charging page |
| Transparency record | key, serial number, signed raw data and calibration certificate of the meter | missing, see implementation |
| Verification core | verifies the meters' signature formats | `ChargyCore.TS` |
| Vehicle measurement | reads current, voltage, state of charge and auxiliary consumption from the battery system | in the simulator: `EvMeter`; in a real car through the vehicle interface |
| Comparator | loss model, uncertainty budget, deviation detection | new |
| Report signer | produces and signs the charging report | new |

### 6.3 Three runtime environments, one core

- **Infotainment.** An app on Android Automotive or in the manufacturer's web view. This is the goal. Android Automotive gives third-party apps with the energy permission at least the instantaneous charge rate in milliwatts and the battery level in watt-hours, but neither voltage, current nor an energy counter, and nothing from the ISO 15118 session. The full scope needs the manufacturer.
- **Phone at the car.** The app pairs with the vehicle or an OBD adapter. Less data, but feasible without the manufacturer.
- **EVCLI.** Our simulated vehicle with its web interface plays the car. The prototype is built there, because both ends of the session are ours.

### 6.4 What the driver sees

- The clock check, as the first line, before charging starts.
- Two running counters side by side: station and vehicle, with power and energy.
- Between them the difference as a band: expected loss, uncertainty, actual deviation.
- A chain of verification seals, each with one sentence on what it is worth.
- The running price, recomputed from the session's tariff.
- At the end, a report to take away.

### 6.5 The verification chain

Every step has a result of its own. A green tick on step 2 says nothing about step 6.

1. **Clocks agree?** Station, meter and vehicle time are within tolerance, and the offsets are recorded.
2. **Signature valid?** The record has not been altered since the meter.
3. **Key trustworthy?** The key comes from a source outside the station: a register, a certificate or a calibration certificate.
4. **Belongs to this session?** SessionID, EVSE ID, contract and time match.
5. **Gapless?** The register never falls, never jumps, and the start value precedes the first current.
6. **Plausible against the vehicle?** The difference lies within loss model and uncertainty.
7. **Price correct?** Quantity times tariff gives the station's receipt.

An unsigned value is a state of its own, and an honest one, not a fault. Almost every station in the field sends that, and the comparison in step 6 works regardless.

## 7. Bidirectional charging: the driver becomes the seller

With bidirectional charging the driver has a direct financial interest in a second measurement, because the roles reverse. When the vehicle feeds energy back, the driver is the seller, and is paid according to a meter that belongs to the buyer.

In no other market does the seller accept that without a measurement of their own. Here the stakes are higher than usual, for four reasons:

- **Every discharged kilowatt-hour costs the driver twice.** It was paid for when it was charged, and it ages the battery when it leaves. An under-count on discharge is not a rounding matter; it is unpaid wear.
- **The losses change sides.** When charging, cable and conversion losses lie behind the meter and the driver pays for energy that never reaches the battery. When discharging, the battery gives up more than the meter counts. Who bears which loss is a contract question that can only be settled with numbers from both ends.
- **Errors no longer cancel.** A meter that reads 2 % high on charging and 2 % low on discharging is within a class A error limit both times, and costs the driver 4 % on every cycle.
- **The volume is large.** A vehicle that cycles daily for grid services can move more energy through the meter than it uses for driving.

ISO 15118-20 already separates the directions: `MeterInfo` has `ChargedEnergyReadingWh` and `BPT_DischargedEnergyReadingWh`, plus reactive energy in both directions. The vehicle's battery system counts both directions as well, because it needs to for state-of-charge estimation.

So Chargy in the Vehicle treats a bidirectional session as two measurements with opposite roles. The charging report states both directions separately, each with its own comparison, and for the discharge direction it is the seller's delivery note. A vehicle owner who sells energy without one is trusting the customer's scale.

## 8. Comparing against the battery system

Station and vehicle measure the same energy at different places. The difference is therefore never zero, but it can be explained: losses, auxiliary consumption and measurement uncertainty. Whatever goes beyond that is the finding.

```
 Station's measuring point                Vehicle's measuring points
            |                              |                               |
            v                              v                               v
   +----------------+   +--------+   +-----------+   +--------------+   +----------------+
   | Station meter  |-->| Cable  |-->|   Inlet   |-->|   Charger    |-->| Battery sensor |
   | with signature |   | plus   |   |    own    |   | on board, AC |   |    measured    |
   |                |   | conn.  |   |  measure- |   |              |   |     by BMS     |
   +----------------+   +--------+   |   ment    |   +------+-------+   +----------------+
                                     +-----------+          |
                                                            v
                                                   +-----------------+
                                                   | Auxiliary loads |
                                                   | cooling, 12 V   |
                                                   +-----------------+
```

*Measurement chain: three measuring points, two parties.*

Between the station's meter and the sensor at the battery lie the cable, for AC the on-board charger, and the branch to the auxiliary loads. The closer the vehicle's measuring point is to the inlet, the less the loss model has to explain.

### 8.1 The balance

```math
E_{\mathrm{station}} = E_{\mathrm{battery}} + E_{\mathrm{aux}} + E_{\mathrm{loss}} + \varepsilon
```

| Quantity | How the vehicle knows it | Documented magnitude |
| --- | --- | --- |
| Energy into the battery | pack voltage times pack current, integrated by the BMS | shunt sensor: ±0.4 % of reading plus offset over the full temperature range ([Isabellenhütte IVT-S](https://www.isabellenhuette.com/hubfs/Files/Data-sheets/IVT-S.pdf)) |
| Auxiliary consumption | power of compressor, heater and 12 V converter from the vehicle network | no citable measurement found; has to be measured per vehicle |
| On-board charger (AC only) | the charger's input measurement, or an efficiency map | 90.8 % at 240 V, 88.8 % at 120 V, charging station included ([INL, Chevrolet Volt](https://inldigitallibrary.inl.gov/sites/sti/sti/5436981.pdf)) |
| Cable and connector | voltage drop between station and inlet, times current | at most 0.5 % between meter and transfer point, otherwise compensation is required ([Bender](https://www.bender.de/docs/charge-controller/Eichrecht/)) |
| Station meter | accuracy class or calibration certificate | maximum permissible errors for class A / B / C: 3.5 / 2 / 1 % at 5 to 30 °C ([MID, Annex V](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32014L0032)); Germany requires at least class A ([REA 6-A](https://oar.ptb.de/files/download/681c517e53218de84f08e6bd)) |

Two conclusions follow. The station's meter may be less accurate than the vehicle's current sensor: a class A station has an error limit of up to 3.5 %, a good shunt 0.4 %. And the largest unknown is the auxiliary consumption, for which no reliable figures exist.

The revision of the Measuring Instruments Directive introduces dedicated classes for charging equipment with ±2 / ±1 / ±0.5 %, determined at the transfer point, for AC and DC ([Council document 6233/2026](https://data.consilium.europa.eu/doc/document/ST-6233-2026-INIT/de/pdf)). From version 1.2 on, OCMF can sign the cable resistance used for compensation. The vehicle can check it against its own voltage drop.

Per charging mode, the vehicle uses the measuring point that is closest to the station and belongs to itself. For DC that is voltage and current at the inlet, with only the cable in between. For AC it is the input measurement of the on-board charger. If neither exists, it calculates backwards from the battery. No value may come from an answer of the station, or one compares a number with itself.

### 8.2 The digital calibration certificate

The Digital Calibration Certificate (DCC) is PTB's machine-readable XML format for calibration results. For Chargy in the Vehicle it does four things:

- **Trust anchor.** A certificate signed by the laboratory that names the meter's serial number and key fingerprint binds the key to a device, without having to believe the operator. That solves step 3 of the verification chain.
- **Correction.** The certificate states the measured deviation at the test points. The vehicle can correct the station's value at the current operating point.
- **Real uncertainty.** Instead of the class's error limit, 3.5 % for class A, the comparison uses the stated uncertainty. The band narrows and detection becomes more sensitive.
- **Validity.** An expired verification period or a revoked certificate becomes visible before charging.

Two caveats belong here. The [DCC schema 3.3.0](https://www.ptb.de/dcc/v3.3.0/dcc.xsd) has no dedicated field for a device key. The fingerprint would have to go into the generic `identifications` of the item, and the certificate's signature is the issuer's. And for billing meters the governing document is not the calibration certificate but the conformity assessment. Its digital counterpart is [PTB's D-CoC](https://www.dmet.ptb.de/d-coc), which is still under development and so far mainly covers type-examination certificates. We found no work specific to electricity or charging meters.

Conversely, the vehicle's current sensor can receive a calibration certificate at the end of the production line. Then two traceable measurements face each other.

### 8.3 Decision rule

```math
\left| E_{\mathrm{station}} - \hat{E}_{\mathrm{station}} \right| \le k \sqrt{u_{\mathrm{meter}}^2 + u_{\mathrm{vehicle}}^2 + u_{\mathrm{model}}^2}
```

Here Ê is the vehicle's estimate of the station's value, and k = 2 the usual coverage factor. Inside the band the session is unremarkable, between k = 2 and k = 3 conspicuous, beyond that a deviation. The rule is evaluated continuously per sample and cumulatively, so that a slow drift shows as clearly as a jump.

### 8.4 Error patterns

| Pattern of the deviation | Probable cause |
| --- | --- |
| Fixed factor at every power | scaling: transformer ratio or wrong cable-loss compensation |
| Fixed amount in watts | unmodelled auxiliary load, or the station's own consumption behind the meter |
| Factor near one third or two thirds (AC) | one phase is missing from the measurement |
| Grows with the square of the current | contact resistance at the connector, which is also a safety finding |
| Jump in the register | foreign session, register change or manipulation |
| Energy before the first or after the last current | start or end value wrongly assigned |
| Same curve, shifted in time | clock or averaging window, already caught in step 1 |

### 8.5 The honest limit

The vehicle's sensor is not a legally verified measuring instrument. A deviation is therefore a well-founded indication that justifies an official inspection, not proof. A single session says little; many sessions at the same station say a lot. Section 10 builds on that.

## 9. The vehicle's charging report

At the end the vehicle issues a report of its own and signs it. It is the counterpart of the station's receipt: the same session, seen by the recipient, or for discharged energy by the supplier.

### 9.1 Content

| Part | Content | Why |
| --- | --- | --- |
| Session | SessionID, EVSE ID, protocol, start, end, charging mode | identifies what the report is about |
| Clocks | offsets of station and meter clock at start and end, and the vehicle's time reference | the basis of every timestamp below |
| Station's evidence | every signed meter record in the original, byte for byte, plus tariff and cost receipt | third parties can verify for themselves |
| Trust sources | the meter's key, where it came from, hash of the calibration certificate | makes step 3 traceable |
| Vehicle measurement | energy per measuring point and per direction, the sample series or its hash root, the sensor and its uncertainty | the vehicle's own statement |
| Comparison | loss model, uncertainty budget, deviation, result per verification step | the verdict and how it was reached |
| Provenance | version and hash of the verification software, identifier of the vehicle or a pseudonym | who is judging here |

### 9.2 Format

The report is a JSON-LD document. Our stack already generates JSON-LD from the schemas, and Chargy reads JSON. The signature covers a canonical form, so that it survives reformatting. The report should also be exportable in the Chargy transparency format, so that existing transparency software can open it.

The sample series is attached as a hash tree. The driver can then disclose individual minutes to the operator without handing over the whole charging profile.

### 9.3 What the vehicle signs with

| Key | For | Against |
| --- | --- | --- |
| Contract certificate | present in every Plug & Charge session; the station knows the chain | identifies the contract, not the vehicle; absent with EIM; changes with the provider |
| OEM provisioning certificate | identifies the vehicle, issued by the manufacturer | meant for another purpose; makes every report traceable |
| A dedicated measurement certificate under the OEM CA | says exactly the right thing: this vehicle, this measuring equipment, optionally with a calibration certificate | does not exist yet |

Recommendation: a dedicated measurement certificate, with rotating pseudonyms for privacy and the key in the vehicle's security module. For the prototype the contract key is enough, because it is already there.

### 9.4 Signed by both sides

The strongest report carries two signatures. The vehicle signs its report, and the station acknowledges its hash, just as the vehicle today acknowledges the station's meter reading. Afterwards neither side can claim not to have known the other's view. This is the standard's `MeteringConfirmation`, mirrored in the opposite direction. The forward direction runs in the prototype (Section 11.6). The mirrored one does not exist yet.

## 10. For metrology authorities: market surveillance by vehicle

Vehicles that report can tell a metrology authority which stations to inspect, and a vehicle with a calibrated reference meter can do the inspection without a test load. The two ideas need each other: the fleet finds where to look, the verification-office car goes there and measures.

### 10.1 The gap today

A charging station is assessed when it is placed on the market and re-verified at fixed intervals or after a complaint. In between, nobody measures. Complaints are rare, because customers have no measurement of their own to complain with. And testing a DC station on site means bringing a reference meter and a load that can absorb the station's power.

### 10.2 The fleet as a travelling standard

In an interlaboratory comparison, one artefact travels from laboratory to laboratory and reveals how they differ. A vehicle does the same between charging stations, every day, as a by-product of charging.

For session *i* of vehicle *v* at station *s*, the vehicle's report gives the ratio of the station's reading to the vehicle's own estimate:

```math
\ln \frac{E_{\mathrm{station},i}}{\hat{E}_{\mathrm{vehicle},i}} = b_s - b_v + \varepsilon_i
```

Here *b\_s* is the systematic relative error of the station, *b\_v* that of the vehicle including its loss model, and ε the noise of one session. One session cannot separate the three. Many sessions form a network of stations and vehicles, and a least-squares fit over the network yields every *b\_s* and every *b\_v* with an uncertainty.

Two properties decide what this is worth:

- **Resolution grows with the number of sessions.** With a noise of σ per session, *n* sessions resolve σ/√n. At σ = 1 %, a hundred sessions resolve 0.1 %. That is arithmetic, not a measured figure, and it holds only if the network is well connected: vehicles that visit several stations, stations that see several vehicles.
- **One constant stays free.** If every station and every vehicle were off by the same amount, the fleet could not tell. The network measures differences. It needs anchors to become absolute: vehicles with a calibrated sensor, or stations that have just been verified.

What an authority gets from it:

| Output | What it shows |
| --- | --- |
| Bias per station, with uncertainty | where to send an inspector first: risk-based instead of calendar-based surveillance |
| Error curve over power, temperature and charging mode | a station that is within limits at 20 °C and outside them in winter |
| Drift over months | ageing between two verifications |
| Common bias of one model or firmware version | a type defect, such as a wrong cable-loss compensation, visible after weeks instead of after a complaint |
| Step change at one station on one day | a repair, a meter swap or a manipulation |
| Clock offsets per station | surveillance of the time base behind time-of-use tariffs |

Three design points:

- **Robustness.** A vehicle can be wrong, or lie. Because each vehicle has its own *b\_v*, a bad vehicle mostly harms its own estimate. A station is flagged only when many independent vehicles agree, and robust estimators keep single outliers from moving the result.
- **No test mode to detect.** Every customer is a probe. A station cannot behave differently for an inspection it cannot recognise.
- **Privacy.** The fit needs only station, vehicle pseudonym, ratio, power band, temperature and date. Rotating pseudonyms protect drivers but thin out the network, since a new pseudonym is a new vehicle to the estimator. That trade-off has to be designed, not ignored.

The legal weight is that of an indication. A flagged station is a reason for an official inspection, not a substitute for one. Reports are signed by the vehicles, so whoever aggregates them, an authority or a neutral body, does not have to be trusted for their authenticity.

### 10.3 The verification-office car as test equipment

A vehicle that carries a calibrated reference meter directly behind its inlet, traceable and with a digital calibration certificate, is a test instrument for charging stations. It has properties no test bench has:

- **Its battery is the test load.** No load bank has to be brought to the site.
- **It measures at the transfer point.** That is exactly where the revised directive defines the permissible error. The loss model drops out; only the contact of one connector remains between the two meters.
- **It is a programmable load.** In DC charging the vehicle requests the current. It can step through the load points of a test plan, from minimum to maximum current, and with bidirectional charging in both directions.
- **The station cannot tell.** The car appears as an ordinary customer over ISO 15118. What is tested is what customers get: meter, signature, clock, tariff, receipt, display and, later, the billing record against the report.
- **The result is machine-readable.** The signed charging report, with the reference meter's calibration certificate attached, is the as-found test record.

The reference meter has to be clearly better than the limit under test, by a factor that verification rules prescribe. Against error limits of 1 to 3.5 % that is available technology.

The limits are practical ones:

- **Energy has to go somewhere.** Battery capacity and state of charge bound each test, and high-power points are reachable only at a low state of charge. Bidirectional stations can take the energy back; elsewhere the car has to discharge between tests.
- **The battery sets the curve.** Deliverable power depends on battery temperature, so the test plan has to follow what the battery accepts.
- **AC is limited by the on-board charger.** The car cannot test an AC station beyond its own charger's rating.
- **There is no recognised procedure yet.** Test plan, sealing of the reference installation and the treatment of the connector contact have to be defined together with PTB and the verification authorities.

A path in three stages:

1. **Software only.** EVCLI against ChargingStationCLI, with simulated meters and switchable faults. This shows the protocol, the report and the evaluation.
2. **Test bench.** EVCLI drives real charging hardware as a vehicle emulator, with a real station meter and a reference meter. This shows the measurement.
3. **A real vehicle.** A car with a sealed reference meter, as a pilot with a verification authority.

### 10.4 How the two fit together

The verification-office cars are the anchors that fix the fleet's free constant, and the fleet tells the cars where to drive. A handful of calibrated vehicles makes thousands of ordinary ones metrologically useful. Other vehicles with calibrated sensors, in a car-sharing or taxi fleet for instance, can serve as additional anchors without ever being sent anywhere on purpose.

## 11. Implementation in ISO 15118

The path has three stages. The first works today, the second is schema-valid without changing the standard, the third consists of three small extensions to the standard.

### 11.1 Stage 0: with what the standard already has

- The vehicle reads the header `TimeStamp` of the first ISO 15118-20 response and compares clocks.
- It sets `MeterInfoRequested` in every ISO 15118-20 charge loop, and in ISO 15118-2 reads every `MeterInfo` that arrives.
- The comparison with its own measurement (step 6 of the verification chain) needs no signature and works immediately, also with EIM.
- The meter's key comes from outside the session: a QR code on the station, or a register looked up by `MeterID`.
- The vehicle's receipt runs as standardised.

The limit is the 64 bytes. [OCMF](https://raw.githubusercontent.com/SAFE-eV/OCMF-Open-Charge-Metering-Format/master/OCMF-en.md) signs with ECDSA on secp256r1 by default and defines DER as the only encoding. Such a signature has 70 to 72 bytes and does not fit. It converts losslessly into the raw form `r‖s` and then fits exactly. But the bytes that were signed are still missing.

### 11.2 Stage 1: schema-valid carriers in ISO 15118-20

**A private value-added service (VAS) for the master data.** The station offers a service of its own in `ServiceDiscoveryRes`. `ServiceDetailRes` returns up to 32 parameters per set, strings up to 80 characters. That is enough for:

| Parameter | Size | Fits |
| --- | --- | --- |
| Format identifier, such as OCMF | a few characters | yes |
| Serial number of the meter | under 32 characters | yes |
| Public key P-256, compressed | 33 bytes, 44 characters base64 | yes |
| SHA-256 of the calibration certificate | 64 hex characters | yes |
| Short URL for the rest | up to 80 characters | yes |
| Signed meter record, calibration certificate | kilobytes | no |

**The Internet service for everything large.** ISO 15118-20 knows an Internet value-added service through which the vehicle speaks HTTP over the charging link. Over it the station serves three paths:

| Call | Returns |
| --- | --- |
| `GET /.well-known/chargy/meter` | key, serial number, calibration certificate |
| `GET /.well-known/chargy/sessions/{SessionID}/records` | the signed meter records of the running session |
| `POST /.well-known/chargy/sessions/{SessionID}/report` | accepts the charging report, answers with the station's counter-signature |

The paths are a proposal of this paper. The charge loop delivers the running number with its 64-byte signature, the HTTP channel the bytes that belong to it. They are matched by `MeterID` and register value.

**The live problem is smaller than expected.** Besides begin (`B`) and end (`E`), OCMF knows signed intermediate readings during charging (`C`) and at a tariff change (`T`), numbered without gaps. According to the specification, begin, end and tariff change are as a rule the legally relevant ones. So the format permits a signed live view. Whether a given meter signs intermediate readings remains to be checked. Where it does not, the view is honestly two-tiered: unsigned intermediate values, bracketed by a signed start and end value.

ISO 15118-2 has the same seams in a smaller size: `ServiceDetail` with tighter parameters, and an Internet service. The recommendation remains to start with ISO 15118-20.

### 11.3 Stage 2: three extensions to the standard

1. **`MeterInfo` gets the whole record.** An optional element for signed meter data as bytes, with signing method, encoding and key. Its shape should match OCPP's `SignedMeterValue`, so that the station hands the same record unchanged to car and backend.
2. **The vehicle reports its measurement.** An optional `EVMeterInfo` in the `ChargeLoopReq`: energy at the inlet and into the battery, per direction. Today only ISO 15118-20 AC states any power of the vehicle's own at all (`EVPresentActivePower`); DC states only the voltage.
3. **The receipt covers both views.** `SignedMeteringData` takes `EVMeterInfo` and the hash of the charging report, and `MeteringConfirmationRes` carries the station's counter-signature. "Received" becomes "received X, measured Y myself, and both know it".

Two clarifications belong with them: what `MeterSignature` signs, and a length limit that fits the curves of ISO 15118-20.

The way there leads through the standard's working group, or first through an open VAS convention. A running implementation with interoperability evidence is the best argument for it.

### 11.4 Behind the station

The report is only useful if it reaches the operator. For the station's meter values the path exists: OCPP has `SignedMeterValue` (in [2.1](https://raw.githubusercontent.com/mobilityhouse/ocpp/master/ocpp/v21/schemas/MeterValuesRequest.json) up to 32,768 characters, signing method and key optional), and the [OCPI CDR](https://raw.githubusercontent.com/ocpi/ocpi/release-2.2.1-bugfixes/mod_cdrs.asciidoc) carries `signed_data` with values of nature Start, End and Intermediate.

For the vehicle's receipt or report there is nothing. The JSON schemas of OCPP 1.6, 2.0.1 and 2.1 contain no field for `MeteringReceipt`, `MeteringConfirmation` or a signature of the vehicle. What remains is `DataTransfer` and `customData`. The prose part of the specification was not checked. So today the car's signature ends at the station at the latest, even if the station verifies it.

### 11.5 The prototype: EVCLI

The prototype is built in [EVCLI](https://github.com/OpenChargingCloud/EVCLI), our simulated electric vehicle with a web interface and a prompt. Its counterpart, [ChargingStationCLI](https://github.com/OpenChargingCloud/ChargingStation), plays the station. Both use the same ISO 15118 stack, WWCP\_ISO15118, as a library.

| Where | What |
| --- | --- |
| WWCP\_ISO15118 (stack) | `MeteringConfirmation` as a real flow on both sides (built); the clock comparison and the pairing of every reading with the vehicle's own count (built); the transparency VAS; `SigningMeter` emitting real OCMF records beside the simulator convention |
| ChargingStationCLI (station) | the signing meter with switchable faults: scaling error, missing phase, register jump, wrong clock; the three HTTP paths over the Internet service |
| EVCLI (vehicle) | clock comparison at session start (built); `EvMeter` as the vehicle's own measurement (built); comparator with loss model and uncertainty band; report signer; a *Transparency* view that shows the two counters, the band and the verification chain live (built as a section of the *Charging* page, with clocks, counters and the metering confirmations; band and chain still missing) |

EVCLI already logs every request and every answer while it happens. The transparency page is a second view on the same event stream, not a second data path.

Order of work:

1. Clock comparison and the two counters in EVCLI, against ChargingStationCLI with an unsigned meter. No signature is needed yet, and step 6 already works. **Built**, but against the stack's own station program, not ChargingStationCLI.
2. `MeteringConfirmation` in the stack, with a loopback test and a recorded session. **Built**, with loopback tests and a live run. The recorded session is still missing.
3. OCMF from the signing meter, the VAS and the HTTP paths; `ChargyCore.TS` verifies in the EVCLI web interface.
4. Fault switches in the station and the comparator's verdicts against them.
5. The signed charging report, and its export in the Chargy format.
6. Interoperability against EVerest, once its ISO 15118-20 module sets `MeterInfo`.

### 11.6 What the prototype shows

Steps 1 and 2 are built. They went into the stack with [WWCP\_ISO15118#55](https://github.com/OpenChargingCloud/WWCP_ISO15118/pull/55) and into EVCLI's vehicle with [EV#2](https://github.com/OpenChargingCloud/EV/pull/2). EVCLI has pinned both since 27 November 2026.

**Clock comparison.**

- **Sources.** The vehicle reads the station's clock from the header `TimeStamp` of every ISO 15118-20 response, starting with `SessionSetupRes`, so before anything is authorised. It reads the meter's `MeterTimestamp` as a second clock.
- **Precision.** The offset is resolved as far as whole-second timestamps and the round trip allow.
- **Drift.** A clock counts as drifted only when it moved by more than two samples can hide, so a second ticking over is not reported.
- **Live result.** The station program was started with its clock 90 seconds ahead. The Charging page showed the station clock 89.9 s ahead with a warning, the meter clock in step, and 935 Wh on both sides. This is the case Section 6.1 anticipates: the station's two clocks disagreeing with each other.

**Readings side by side.** Every `MeterInfo`, in ISO 15118-2 and -20, is paired with what the vehicle's own `EvMeter` counted in the same iteration. Each reading is marked either "signed, not verified" or "unsigned". Verifying the meter's signature (step 2 of the chain) needs the record and the key from Stage 1, which do not exist yet.

**MeteringConfirmation, AC and DC.**

| Side | Behaviour | Requirement |
| --- | --- | --- |
| Station asks | sets `EVSENotification = MeteringConfirmation` with the reading, every n-th charge-loop response | `[V2G20-1083]` |
|  | never in the first charge-loop response | `[V2G20-1622]` |
|  | never under EIM, and never without a meter | `[V2G20-2704]` |
|  | no second request while one is open and its `NotificationMaxDelay` has not run out | `[V2G20-2105]` |
| Vehicle signs | `SessionID`, reading, receipt and the selected schedule tuple, with the contract key | `[V2G20-776]`, `[V2G20-2236]`, `[V2G20-1808]` |
|  | sends on V2GTP payload type `0x8102`, between two charge-loop iterations | `[V2G20-1084]`, `[V2G20-1085]` |
| Station checks | session; reading field by field against what it sent; receipt; control mode; digest; the signature against the contract certificate from `AuthorizationReq`. Each result is recorded separately | `[V2G20-904]` |
| Station answers | `OK`, or `FAILED_MeteringSignatureNotValid` (which ends the session) when set to require a valid confirmation | `[V2G20-1990]` |

Command-line switches:

- Station: `--metering-confirmation <n>` and `--require-metering-confirmation`.
- Vehicle: `--no-metering-confirmation`, which keeps it silent.

**Test results.**

- **Normal live run.** The stack's station and vehicle programs ran over TCP, with a throwaway P-256 test contract and the station asking in every response after the first. The station asked twice. Both confirmations passed every check, at 1,600 and 2,400 Wh, and the vehicle had counted 2,400 Wh itself.
- **Silent vehicle.** With the vehicle silenced, the station asked once and did not ask again within the 5 seconds it had allowed.
- **Loopback tests.** Eight tests cover the same cases, plus a wrong key and the mode that requires a valid confirmation.
- **Not tested.** Nothing has run over TLS or against another stack. No other stack implements the exchange.

**Three choices no second implementation has confirmed yet:**

- **The signed bytes.** The stack signs the EXI fragment of the whole `MeteringConfirmationReq`, with the signature slot left empty, which is how cbV2G's ISO 15118-20 fragment grammar carries this message. The signature reference names `SignedMeteringData` by its `Id`. Whether a foreign station computes the same digest is open.
- **The signature form.** The vehicle signs in the same P-256 form its Plug & Charge `AuthorizationReq` already uses, not with the P-521/SHA-512 or Ed448 named in Section 3. The station accepts both EXI encodings of `SignedInfo`: the grammar of ISO 15118-20's common messages and the standalone XMLDSig one.
- **The side stream, one at a time.** The vehicle never sends a confirmation while a charge-loop request is outstanding. The station answers every frame in arrival order, on the payload type it came in on. A vehicle that sends both at once is untested.

**What it does not change.** The confirmation still only says "received". The vehicle's own count is shown beside the station's reading, but it is not part of what the vehicle signs: `SignedMeteringData` has no place for it. That gap is extension 3 of Section 11.3, and the prototype makes it concrete.

**On the Charging page.** Since [EV#3](https://github.com/OpenChargingCloud/EV/pull/3), EVCLI's Transparency section shows the confirmations beside the clocks and counters:

| Line | Shows |
| --- | --- |
| Metering confirmations | how many the vehicle signed with its contract key, and the station's answers ("OK to all", or each answer with its count); "the station asked for none" where it did not ask |
| Last confirmed | the last confirmed reading and meter, whether the cost receipt was signed too, and the vehicle's own count with the difference |
| Could not sign | only where the station asked and the vehicle had no contract key or no reading to sign |

A note under them repeats the limit above: a confirmation says the vehicle received the reading, not that it is right. The session log has a line per confirmation as it is answered. An ISO 15118-2 session shows no such lines, because it counts its metering receipts on the run itself. A `FAILED` answer ends the session in the stack, so it appears as the session's error.

In a live run, EVCLI with a throwaway contract charged at the stack's station program, which asked in every response after the first. The station asked four times, at 374, 561, 748 and 935 Wh, and every check passed. The page showed "4 signed with the contract key; the station answered OK to all" and the last reading at 935 Wh, with the vehicle's 935 Wh beside it.

## 12. Further ideas

Sorted by usefulness, the obvious ones first.

- **Connector diagnosis as a by-product.** In DC both sides state their voltage. The difference divided by the current is the resistance of cable and contact. If it grows from session to session, the connector is ageing. That is a safety finding, and it checks the meter's cable-loss compensation at the same time.
- **Recomputing the invoice in the car.** ISO 15118-20 transfers price schedules and a cost receipt. The vehicle computes quantity times tariff live and later compares with the provider's billing record. Deviations in price are more frequent than in the meter.
- **A transparency log for meter keys.** A public, append-only directory as in Certificate Transparency: serial number, key, hash of the calibration certificate. A swapped key stands out because it is entered nowhere. Vehicles can compare the log state among themselves.
- **A hash chain over the session.** Every charge-loop message is appended to a chain whose head both sides sign at the end. The whole session, not just the final register, is then unalterable afterwards.
- **Attesting the parking time.** The vehicle knows to the second when it was plugged in and when the current ended. That belongs in the report, because occupancy fees depend on it.
- **Detecting a tap.** A difference that no loss model explains and that appears abruptly can be a consumer between meter and car.
- **Phase-resolved for AC.** The on-board charger knows the currents per phase. That turns "one third is missing" into "L2 is not being counted".
- **Proof without disclosure.** With a zero-knowledge proof the vehicle can show that its measurement deviates by more than the band, without revealing the charging profile. The pragmatic precursor is the hash tree from the report section.
- **Trust in route planning.** The navigation system shows per station whether it signs, whether its key is in the log, and how the fleet rates it. Transparency becomes a selection criterion.
- **The simulator as a test rig for vehicles.** The fault switches of ChargingStationCLI make detection testable, and every vehicle implementation comparable against the same faults.

## 13. Open questions and next steps

### 13.1 Open questions

- Which meters in the field actually sign intermediate readings? OCMF permits it; practice is open.
- Will there be a digital conformity document for charging meters, and where in it does the meter's key go?
- Does the vehicle count as a "device of the end user"? The revision of the Measuring Instruments Directive lets the measurement result of charging equipment be made accessible through a local display, a remote display or a device of the consumer, traceable to the instrument under control and with manipulation detectable ([Council document 6233/2026](https://data.consilium.europa.eu/doc/document/ST-6233-2026-INIT/de/pdf), No. 10.6). We found no position of PTB on a display in the vehicle.
- What tolerance applies to the clock comparison, and which of the station's two clocks is the legally relevant one in each tariff model?
- Can a statistical finding from the fleet carry more weight than an indication, in the way sampling procedures already do elsewhere in legal metrology?
- What would a recognised test procedure for the verification-office car look like: load points, sealing, treatment of the connector contact, required accuracy of the reference meter?
- How does an app in a real vehicle get voltage, current and auxiliary consumption? The open Android properties suffice for a coarse check, not for an uncertainty budget.
- Which key signs the report, and how does the driver stay pseudonymous without thinning out the fleet network?
- How does the report reach the operator when OCPP has no field for it: as an extension, or past the station's backend?
- How large is the auxiliary consumption really? There is no citable source, so it takes measurement series of our own.
- Which octets does the signature of a `MeteringConfirmationReq` cover, and which curve do contract certificates carry in practice? The prototype had to choose both (Section 11.6). Only a second implementation can confirm the choice.

### 13.2 Next steps

- [x] Clock comparison and the two counters in EVCLI (against the stack's station program; ChargingStationCLI not yet)
- [x] `MeteringConfirmation` as a flow in the stack, with loopback tests and a live run
- [ ] A recorded `MeteringConfirmation` session in the corpus, and the same exchange over TLS
- [x] Show the confirmations on EVCLI's Charging page
- [ ] Write down the transparency VAS and the three HTTP paths as a convention, and implement them
- [ ] Extend `SigningMeter` to OCMF and let `ChargyCore.TS` verify against it
- [ ] Comparator with loss model and uncertainty band, first against the station's fault switches
- [ ] Define the charging report as JSON-LD, sign it with the contract key, export it in the Chargy format
- [ ] Simulate the fleet estimator on synthetic sessions, to find how many sessions and anchors it needs
- [ ] Read EN 50470 and VDE-AR-E 2418-3-100 in full, the prose part of OCPP 2.1 and the OCMF rules on timestamp status; confirm the Official Journal number of the directive's revision
- [ ] Write the three extensions to the standard as a short proposal for the working group
- [ ] Discuss sections 6.1 and 10 with PTB and a verification authority

## 14. Sources

Own material:

- XSD schemas of ISO 15118-2 and ISO 15118-20 as used by the WWCP\_ISO15118 stack
- Requirement identifiers on `MeterInfo`, `MeteringReceipt` and `MeteringConfirmation`, and the measurements against EVerest, from the ISO15118ConformanceTests repository
- Source trees in the interoperability rig: Josev `d645255`, everest-core 2026.10.0 `74845c57`, eVDriveFlow `60249c3`, iso15118-simulator-rs `fc51088`
- The prototype: [WWCP\_ISO15118#55](https://github.com/OpenChargingCloud/WWCP_ISO15118/pull/55) and [EV#2](https://github.com/OpenChargingCloud/EV/pull/2), merged and pinned in EVCLI on 27 November 2026; the Charging page's confirmations, [EV#3](https://github.com/OpenChargingCloud/EV/pull/3), merged the same day

Read on the web on 26 November 2026:

- [OCMF specification, S.A.F.E. e.V.](https://raw.githubusercontent.com/SAFE-eV/OCMF-Open-Charge-Metering-Format/master/OCMF-en.md)
- OCPP JSON schemas [2.0.1](https://raw.githubusercontent.com/mobilityhouse/ocpp/master/ocpp/v201/schemas/MeterValuesRequest.json) and [2.1](https://raw.githubusercontent.com/mobilityhouse/ocpp/master/ocpp/v21/schemas/MeterValuesRequest.json), [OCA application note on signed meter values](https://openchargealliance.org/wp-content/uploads/2025/05/signed_meter_values-v10-1.pdf)
- [OCPI 2.2.1, CDR module](https://raw.githubusercontent.com/ocpi/ocpi/release-2.2.1-bugfixes/mod_cdrs.asciidoc)
- [DCC schema 3.3.0](https://www.ptb.de/dcc/v3.3.0/dcc.xsd) and [D-CoC](https://www.dmet.ptb.de/d-coc), PTB
- [Measuring Instruments Directive 2014/32/EU](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32014L0032), [Council document 6233/2026 on its revision](https://data.consilium.europa.eu/doc/document/ST-6233-2026-INIT/de/pdf), [REA document 6-A](https://oar.ptb.de/files/download/681c517e53218de84f08e6bd)
- [Bender, Eichrecht documentation](https://www.bender.de/docs/charge-controller/Eichrecht/), [Isabellenhütte IVT-S](https://www.isabellenhuette.com/hubfs/Files/Data-sheets/IVT-S.pdf), [INL, charging efficiency of the Chevrolet Volt](https://inldigitallibrary.inl.gov/sites/sti/sti/5436981.pdf)
- [Android VehiclePropertyIds](https://developer.android.com/reference/android/car/VehiclePropertyIds)
