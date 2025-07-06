# Advanced Diagnostics for OCPP

As the complexity and criticality of electric vehicle (EV) charging infrastructure increases, the need for robust and transparent **diagnostic capabilities** in charging stations and other OCPP enabled devices becomes paramount. Currently, the *Open Charge Point Protocol (OCPP)* lacks a standardized mechanism to ***explicitly*** **define, trigger, and monitor** e.g. **self and integration tests** within its device model and message set. This gap leads to proprietary extensions, inconsistent implementations, and reduced interoperability across manufacturers and management systems on top of the specified generic device model reporting, diagnostic and logging mechanisms.

An explicit diagnostics model, tightly integrated into the OCPP device model and messsage framework, would enable charging station operators to reliably enumerate, parameterize, and execute a wide range of diagnostics — ranging from simple **software integrity self checks**, over **complex hardware validation routines** to **integration tests within the charging station operator network**. By describing available tests, their required parameters, operational constraints, intermediate reports, and expected outcomes in a **machine-readable** and discoverable manner, operators gain better tools for remote maintenance, troubleshooting, and regulatory compliance.

Importantly, self tests should not only be accessible for manual execution by human operators or for periodic automated routines, but also be available to intelligent software agents and **AI-based diagnostic systems**. Such agents can proactively trigger or sequence self tests in response to anomalies, performance degradation, or security incidents, enabling more effective root cause analysis and faster problem resolution within the charging infrastructure.

Moreover, standardized test models support automation of periodic health checks, real-time fault isolation, and evidence-based reporting for quality assurance and **cybersecurity audits**. It also facilitates seamless backend integration, future-proofing OCPP deployments against evolving reliability and safety requirements in critical infrastructure like the upcoming ***European Network and Information Systems 2 (NIS2) Directive***. Therefore, the introduction of a formal self test model in OCPP and related protocols is essential for improving the transparency, resilience, and maintainability of EV charging networks.

## Scope

This subchapter provides a differentiation between various diagnostic test types that can be performed by charging stations and other OCPP devices. By clearly outlining the purpose and scope of each test type, this section ensures consistent terminology and lays the foundation for advanced diagnostics and automated monitoring of the entire charging infrastructure.

| Test Type | Support | Role and Description | Example |
|------------------|--|----------------------------------|----------------------------------|
| Diagnostic Control | yes | A normal OCPP request sent to read or set internal state or simulate interactions that are out-of-scope of the normal OCPP communication. | Simulate the swiping of a RFID card for starting an authorization and charging process. |
| Self Test          | yes | A test executed locally and autonomously by the charging station to verify the integrity and correct functioning of its internal hardware and software components, independent of external systems. Self-tests can be triggered on demand, scheduled, or during startup, and provide detailed diagnostic results on the internal health status of the device. | Testing the reachability of the internal energy meter connected via RS485 and Modbus/RTU. |
| Integration Test   | yes | A test performed by the charging station to verify the correct operation and connectivity of external interfaces, dependencies, and services such as backends, network infrastructure, or peripheral devices. Integration tests ensure the station is correctly embedded in its operational environment and can communicate as expected. | Testing the reachability and rootCAs of *Network Time Secure* legal servers. |
| Health Check       | yes | A lightweight, often automated status assessment that provides a quick, aggregated indicator of the station’s general operational state. Health checks may combine results from self-tests and integration tests but are not intended to replace detailed diagnostics. Typically used for monitoring or liveness endpoints. | Enough RAM, flash storage and free CPU cycles to start new charging sessions. |
| Security Test      | maybe later | A test aimed at verifying the robustness of the station’s cybersecurity measures, including authentication, authorization, data integrity, and secure communication. Security tests may simulate attack vectors or check the validity and expiration of cryptographic credentials. | No well-known unsecure configuration settings had been detected. |
| Compliance Test    | maybe later | A test that verifies whether the charging station adheres to relevant regulatory, safety, or protocol standards. Compliance tests may include both self-test and integration-test elements and are essential for audits, certifications, or market access. | No well-known unsafe grid code configuration settings had been detected. |
| Performance Test   | maybe later | A test that measures the station’s behavior under defined workloads or stress scenarios, focusing on timing, throughput, and resource consumption. Performance tests help identify bottlenecks and ensure the device meets operational requirements under load. | Response time and total time until the entire device model was reported. Number of concurrent monitoring data streams supported. Time to process complex charging profiles. |


## Current State of the Art

This chapter gives a short overview which kind of diagnostic functions are already available within the current OCPP v2.1 version.

### GetBaseReport

|||
|---------------------|--------------------------------------------------------------------|
| **Function**        | Query full or partial device/component inventory, including firmware/software versions (for diagnostic/audit purposes). |
| **Usage** | CSMS requests; Charge point responds with inventory tree. |


### GetReport

|||
|---------------------|--------------------------------------------------------------------|
| **Function**        | Request specific diagnostic data or variables from components (e.g., power electronics health, communication state).
| **Schema**          | Filtered by component or variable name. |
| **References**      | OCPP 2.0.1, section 4.5.2 |


### GetLog

|||
|---------------------|--------------------------------------------------------------------|
| **Function**        | Remote download of log files (e.g., error logs, operational logs). |
| **Usage**           | CSMS (central system) requests specific logs from EVSE. |
| **Schema**          | GetLogRequest fields: logType, requestId, retries, retryInterval, log, logParameters (start/end time, remote location, etc.) |
| **Response fields** | status, filename/location |
| **References**      | OCPP 2.0.1, section 14.5  |


### LogStatusNotification

|||
|---------------------|--------------------------------------------------------------------|
| **Function**        | Notify CSMS about the status of log upload (Started, Success, Failed, etc.) |
| **Usage** | EVSE reports back upload status after GetLog. |
| **Schema** | requestId, status (enum) |


### TriggerMessage

|||
|---------------------|--------------------------------------------------------------------|
| **Function**        | Central system can instruct EVSE to trigger specific events, e.g., send a StatusNotification, or in future, initiate self-test (where supported).
| **Schema**          | requestedMessage (e.g., StatusNotification, BootNotification), optional evseId, connectorId |

**Note**: OCPP 2.1 introduces extendable types to include e.g. "SelfTest" or "HealthCheck" as triggerable messages, but (optional) parameters on triggers are missing.


### EventNotification

|||
|---------------------|--------------------------------------------------------------------|
| **Function**        | Report real-time component-level events, errors, warnings (component name, event type, severity, timestamp, technical details).
| **Schema**          | Extensive; supports component, eventType, eventId, severity, etc. |
| **References**      | OCPP 2.0.1, section 2.3.2 |





## Diagnostic Control

New *Diagnostic Control* requests provide a standardized mechanism to remotely read and manipulate the internal state of components such as charging stations. This extension is designed specifically to support advanced testing, simulation, and validation workflows during development, deployment, or maintenance.

It enables simulation of physical interactions, like the **swiping of an RFID card**, entirely through software. This allows triggering of typical sequences like RFID UID detection, authorization, and initiation of a charging session without requiring physical presence or hardware interaction.

Beyond behavioral simulation, Diagnostic Control may also permit direct **manipulation** of internal system state, including the setting of **Device Model Variables** that are ***normally read-only*** under standard OCPP access control policies. This allows validation of edge cases, failure modes, or system behavior under specific manipulated conditions that would otherwise be difficult or impossible to reproduce.

Unlike traditional OCPP requests, Diagnostic Control requests are not part of the normal operational interface, but instead serve as diagnostic and testing tools. These requests and their corresponding responses follow the **same message structure as regular OCPP operations**. However, they are distinguished by the strong requirement for **digital signatures**, verifiably issued by an entity that holds explicit *Diagnostic Control* access rights.

This cryptographic enforcement ensures that only authorized diagnostic tools or operators can issue such requests. As a result, it is considered safe and compliant to keep this interface **active even in production environments**, since misuse by unauthorized parties is effectively prevented through cryptographic validation.


### GetExecutingEnvironment

This request returns information about the executing environment of the software under test. Especially when an embedded software is run within an emulator or a multi-user operating system and it hangs within an endless loop or crashed in unexpected ways, it is usefull to find out more details about its executing environment. By this for example the *process identifiction* might be retrieved to be able to `kill -9` and to restart the process. Also alternative ways to initiate a hard restart or to download a memory image might be exposed.

#### OCPP v1.6

*GetExecutingEnvironmentRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


*GetExecutingEnvironmentResponse:*

The response can contain any data the executing environment wants to share with the user that optionally signed the request. This also means, that different users might see different information. It is good practise to describe the collection of data via a *JSON-LinkedData (JSON-LD)* `@context` property.

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|processId|O|ProcessId|Number *(Integer > 0)*|The process identification of the main application process.|
|restartURL|O|URL|String|An URL that can be called to kill and restart the entire process, e.g. *tcp://192.168.178.23:8123* or *http://192.168.178.23:8123*.|
|restartSecret|O|String|String|A long string acting as *shared secret* to kill and restart the entire process. The *restartURL* determines the actual usage, e.g. sending this string as TCP data or *POST*ing it to the given HTTP URL.|
|*...any...*|O|...|...|...|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

*GetExecutingEnvironmentRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


*GetExecutingEnvironmentResponse:*

The response can contain any data the executing environment wants to share with the user that optionally signed the request. This also means, that different users might see different information. It is good practise to describe the collection of data via a *JSON-LinkedData (JSON-LD)* `@context` property.

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|processId|O|ProcessId|Number *(Integer > 0)*|The process identification of the main application process.|
|restartURL|O|URL|String|An URL that can be called to kill and restart the entire process, e.g. *tcp://192.168.178.23:8123* or *http://192.168.178.23:8123*.|
|restartSecret|O|String|String|A long string acting as *shared secret* to kill and restart the entire process. The *restartURL* determines the actual usage, e.g. sending this string as TCP data or *POST*ing it to the given HTTP URL.|
|*...any...*|O|...|...|...|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### AdjustTimeScale

This request is a diagnostic extension to OCPP that enables external test tools or validation frameworks to temporarily **alter the rate at which simulated time progresses** within a charging station or associated components. This feature is particularly valuable in testing scenarios that depend on elapsed time, such as the automatic stop of a charging session after a specified duration, authorization timeouts, or inactivity handling. By accelerating or decelerating the passage of time for internal logic, **long-running tests can be executed significantly faster**, or timers can be frozen for controlled debugging.

The request specifies a timeScale value, which is a positive decimal number representing the multiplier applied to simulated time. A value of 1.0 indicates normal time progression, while a value of 2.0 causes internal time to progress twice as fast as real time. A value of 0.5 slows time down by half, and a value of 0.0 effectively pauses all time-based logic in the affected domain. To prevent unintended permanent changes, the request may optionally include a duration parameter (in seconds), after which the time scale automatically reverts to the normal value of 1.0.

This request is intended solely for testing and validation purposes in non-production environments. Charging stations operating in production mode may reject this request unless explicitly configured to permit it under controlled conditions. The response to such a request includes a status field indicating whether the operation was accepted, rejected, or not supported, and may optionally return the actually applied time scale, which might be capped or adjusted internally for implementation or safety reasons.

#### OCPP v1.6

*AdjustTimeScaleRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|scale|M|Double|Number *(Double)*|The time scale.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*AdjustTimeScaleResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

*AdjustTimeScaleRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|scale|M|Double|Number *(Double)*|The time scale.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*AdjustTimeScaleResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### TimeTravel

This request enables controlled manipulation of the system clock on a charging station or related component. Unlike the *AdjustTimeScale* request, which affects only the relative flow of internal time, *TimeTravel* allows the system to temporarily **jump forward or backward in time**, for example to simulate behavior under certificate expiration, daylight saving changes, authorization token expiry, **dynamic tariff changes**, or to validate metrological timestamp boundaries. Optionally, it may also define a duration, after which the system clock reverts to the original (real) time source. If no duration is specified, the simulated time remains active until explicitly reset or overridden by a subsequent request.

This request is intended solely for testing and validation purposes in non-production environments. Charging stations operating in production mode may reject this request unless explicitly configured to permit it under controlled conditions. 

#### OCPP v1.6

*TimeTravelRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|timestamp|M|Timestamp|String *(ISO8601)*|The timestamp to travel to *(UTC or with time zone offset)*.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*TimeTravelResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

*TimeTravelRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|timestamp|M|Timestamp|String *(ISO8601)*|The timestamp to travel to *(UTC or with time zone offset)*.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*TimeTravelResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|





## Charging Station Diagnostics

### SetErrorState

This request simulates an **Error State** within the entire charging station or within one of its EVSEs. When the charging station for example detects an *upstream grid supply anomaly* like ***undervoltage***, ***overvoltage***, or a ***phase failure***, is must log, report and propagate this error state to one or more of its EVSEs. These EVSEs can then enter a *PowerQualityError* or *GridFault* state and signal the reduced-availability or fault indication via the *Control Pilot (CP)* to the EV. As a consequence, the charging process may be paused, limited, or aborted, depending on the error severity and the EV's response strategy.

#### OCPP v1.6

*SetErrorStateRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|faultType|M|FaultType|String|`VoltageHigh` \| `VoltageLow` \| `PhaseLoss` \| `ResidualCurrent` \| ...|
|connectorId|O|ConnectorId|Number *(Integer)*|The optional connector identification, when the charging station has more than one connector (0 > ConnectorId ≤ MaxConnectorId).|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|duration|O|TimeSpan|Number (ms)|An optional duration of the error state for short transient errors.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetErrorStateResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

*SetErrorStateRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|faultType|M|FaultType|String|`VoltageHigh` \| `VoltageLow` \| `PhaseLoss` \| `ResidualCurrent` \| ...|
|evse|O|EVSE|Object|The optional EVSE and connector identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId) and (0 > ConnectorId ≤ MaxConnectorId(EVSEId)).|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|duration|O|TimeSpan|Number (ms)|An optional duration of the error state for short transient errors.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|-|An (optional) enumeration of cryptographic signatures.|

*SetErrorStateResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### SwipeRFIDCard

This request simulates the **swiping of an RFID card** triggering RFID UID detection, authorization, and maybe the start of a charging session without requiring physical presence or hardware interaction. The same mechanism can also be used to terminate an active charging session, either by simulating the swipe of the same RFID card used to initiate the session, or by simulating a swipe of another card that belongs to the same authorization group.

#### OCPP v1.6

*SwipeRFIDCardRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|idTag|M|IdTag|String|The identification tag, e.g. of the RFID card to be swiped.|
|readerId|O|ConnectorId|Number (Integer)|The optional RFID reader identification, when the charging station has more than one connector and therefore more than one RFID reader or an additional user interface process to select a specific connector before or after swiping the RFID card (0 > ReaderId ≤ MaxConnectorId).|
|simulationMode|O|IdTagSimulationMode|String|An optional simulation mode: `Software\|Hardware\|...`|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SwipeRFIDCardResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

*SwipeRFIDCardRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|idToken|M|IdToken|Object|The identification token, e.g. of the RFID card to be swiped.|
|readerId|O|EVSEId|Number (Integer)|The optional RFID reader identification, when the charging station has more than one EVSE and therefore more than one RFID reader or an additional user interface process to select a specific EVSE/connector before or after swiping the RFID card (0 > ReaderId ≤ MaxEVSEId).|
|simulationMode|O|IdTokenSimulationMode|String|An optional simulation mode: `Software\|Hardware\|...`|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SwipeRFIDCardResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|





## CCS Diagnostics

The following messages define diagnostics for the *Combined Charging System (CCS)*.

### AttachCable

This request simulates the connection of a detached charging cable to the EVSE socket of an AC charging station.

The request includes a **Proximity Pilot (PP) resistor value**, which represents the EV driver's ***AC charging cable maximum permissible current*** according to IEC 61851-1 and IEC 62196-2. This resistor is physically located within the plug between PP and PE. The EVSE uses a voltage divider to detect the maximum allowed current of the cable by placing a voltage (typically +5 V) on the PP line via a pull-up resistor. The EVSE then reads the resulting voltage and infers the PP resistor value. The following lookup table translates the resistor value to the maximum allowed current.

|PP Resistor|Max Current|Voltage at PP|Tolerance|
|-|-|-|-|
| ∞ Ω | *Cable not connected<br>EV unplugged* | +5.0 V | — |
| 1500 Ω | 13 A | +2.0 V  | ±5% |
|  680 Ω | 20 A | +1.8 V  | ±5% |
|  220 Ω | 32 A | +0.9 V  | ±5% |
|  100 Ω | 63 A | +0.45 V | ±5% |
| Other / Out-of-spec | *Invalid / undefined* | < 0.25 V or unrecognized value | — |

Even when to charging cable is first connected to the EV and afterwards to an EVSE socket of a charging station, the attachment of this cable does not imply that an EV will be detected. 

#### OCPP v1.6

*AttachCableRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|connectorId|M|ConnectorId|Number *(Integer)*|The connector identification, when the charging station has more than one connector (0 > ConnectorId ≤ MaxConnectorId).|
|resistorValue|M|Ohm|Number *(Double)*|The resistor value >0 to indicate the cable's maximum permissible current.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*AttachCableResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

*AttachCableRequest:*

|Property|M/O|Type|JSON Type|Default|Description|
|-|-|-|-|-|-|
|evseId|M|EVSEId|Number *(Integer)*|-|The EVSE identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId).|
|connectorId|O|ConnectorId|Number *(Integer)*|1|The optional connector identification, when the charging station has more than one connector on the given EVSE (0 > ConnectorId ≤ MaxConnectorId(EVSEId)). Default: 1|
|resistorValue|M|Ohm|Number *(Double)*|-|A resistor value >0 to indicate the cable's maximum permissible current.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|-|An (optional) enumeration of cryptographic signatures.|

*AttachCableResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|



### GetPWMValue

This request retrieves the current value of the *Pulse Width Modulation (PWM)* signal generated by the EVSE's *Control Pilot*. The PWM duty cycle represents the **maximum allowable charging current** as defined by IEC 61851-1 and is used by the EV to determine the upper limit of the energy it may draw from the EVSE. Reading this value allows diagnostic systems to verify the dynamic current limits being communicated by the charging station to the vehicle in real-time, which is essential for safe and standards-compliant operation.

#### OCPP v1.6

*GetPWMValueRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|connectorId|M|ConnectorId|Number *(Integer)*|The connector identification, when the charging station has more than one connector (0 > ConnectorId ≤ MaxConnectorId).|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*GetPWMValueResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

 OCPP v2.x might prefer setting up a Device Model reporting.

*GetPWMValueRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|evseId|M|EVSEId|Number *(Integer)*|The EVSE identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId).|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*GetPWMValueResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### SetCPVoltage

*IEC 61851-1* defines charging states called: A, B, C, D, E, F. They indicate whether the vehicle is connected, ready to charge, charging, or in a fault state.

The EV communicates its charging intend to the EVSE by modifying the voltage on the **Control Pilot (CP)** pin. *Voltages* are measured between the CP line and protective earth (PE) with a typical ±0.5 V tolerance.

For AC charging a **Pulse Width Modulation (PWM) signal** within the states B, C, and D indicates the maximum current the EVSE can supply. The duty cycle of the PWM correlates to the available current.

DC charging a **high-level digital communication** according to *DIN 70121*, *ISO 15118-2* or *ISO 15118-20* is used.

|CP Voltage|State|PWM|EV Condition|Notes|
|-|-|-|-|-|
|+12 V|A|-|Not connected|No EV present|
|+9 V|B|PWM|Connected, not requesting energy|EV connected, ready for negotiation, not charging|
|+6 V|C|PWM|Connected and ready to charge|EV requests charging, internal contactor closed. Locked cable on EV side|
|+3 V|D|PWM|Charging with ventilation required (rare)|EV requests charging, requires external ventilation (e.g. battery gas exhaust)|
0 V|E|-|Error, CP short to PE or GND|Fault or disconnected EVSE|
|< 0 V|F|-|Error, reverse polarity or other fault|Communication fault / Invalid voltage detected|
|>12 V|-|-|Error, overvoltage fault|Out-of-specification error / Invalid voltage detected|

The following table shows all legal transitions between EV *Charge Pilot* states.

|State Transition|Allowed|Description|
|-|-|-|
|A → B|✅|EV plugged in. EVSE detects vehicle, prepares for charging. No power is supplied yet.|
|A → C|❌|GoTo B first!|
|A → D|❌|GoTo B first!|
|A → E|⚠️|Implies hard fault (e.g., CP shorted to PE or GND), likely due to broken cable or EV.|
|A → F|⚠️|Illegal CP signaling (e.g., negative voltage); could indicate reverse wiring or short.|
|B → A|✅|EV unplugged.|
|B → C|✅|EV ready to charge, closes internal contactor. EVSE maybe locks detached charging cable, supplies power to the vehicle.|
|B → D|✅|Like state `C`, but EV requires ventilation (rare, obsolete in most modern EVs). EVSE activates ventilation.|
|B → E|⚠️|Possible fault if CP pulled to GND unexpectedly.|
|B → F|⚠️|Illegal CP voltage (e.g. < 0 V); wiring fault or hardware defect.|
|C → A|❌|Direct transitions from charging to disconnected are not possible without passing through B, as unplugging during charging is detected as a fault (→ E).|
|C → B|✅|EV pauses charging, e.g. due to *State-of-Charge (SoC)* or thermal reasons.|
|C → D|⚠️|Direct switching between ventilation and non-ventilation charging states is not standard; the EV typically returns to state B first!|
|C → E|⚠️|Implies unexpected CP fault during active charging – possibly unplugged during charge. EVSE stops power supply.|
|C → F|⚠️|Implies invalid signal level during charge – usually treated as fault. EVSE stops power supply or can no longer supply energy.|
|D → A|❌|Direct transitions from charging to disconnected are not possible without passing through B, as unplugging during charging is detected as a fault (→ E).|
|D → B|✅|Ventilation no longer required.|
|D → C|⚠️|Direct switching between ventilation and non-ventilation charging states is not standard; the EV typically returns to state B first!|
|D → E|⚠️|Implies CP pulled to GND during ventilation-required charging. Fault condition. EVSE stops power supply.|
|D → F|⚠️|Implies invalid signal level during charge – usually treated as fault. EVSE stops power supply or can no longer supply energy.|
|E → A|✅|Error resolved. EV unplugged.|
|E → B|✅|Error resolved. EV still connected.|
|E → C|⚠️|Error state requires resolution (often returning to A or B) before charging can resume.|
|E → D|⚠️|Error state requires resolution (often returning to A or B) before charging can resume.|
|E → F|⚠️|Usually irrelevant but can occur during unstable or cascading errors and faults.|
|F → A|✅|EVSE fault resolved. EV unplugged.|
|F → B|✅|EVSE fault resolved. EV still connected.|
|F → C|⚠️|Fault state requires resolution (often returning to A or B) before charging can resume.|
|F → D|⚠️|Fault state requires resolution (often returning to A or B) before charging can resume.|
|F → E|⚠️|Usually irrelevant but can occur during unstable or cascading errors and faults.|

```
  +-----+     Plug-In      +-----+    Contactor Close    +-----+
  |  A  | ---------------> |  B  | --------------------> | C/D |
  +-----+                  +-----+     Supply Energy     +-----+
     ^                       | ^                            |
     |        Unplug         | |      Pause Charging        |
     +-----------------------+ +----------------------------+
```

#### OCPP v1.6

*SetCPVoltageRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|voltage|M|Volt|Number (Double)|The voltage on the *Charge Pilot*.|
|voltageError|O|Percent|Number (Double)|An optional random variation within ±n% to simulate real-world analog behavior.|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|transitionTime|O|TimeSpan|Number (ms)|An optional gradual voltage change over the given time span avoiding instantaneous jumps to simulate real-world analog behavior.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetCPVoltageResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP 2.x

*SetCPVoltageRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|voltage|M|Volt|Number (Double)|The voltage on the *Charge Pilot*.|
|voltageError|O|Percent|Number (Double)|An optional random variation within ±n% to simulate real-world analog behavior.|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|transitionTime|O|TimeSpan|Number (ms)|An optional gradual voltage change over the given time span avoiding instantaneous jumps to simulate real-world analog behavior.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetCPVoltageResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### SendEVMessage

This message sends an ISO 15118 data structure, as if they would be send by an electric vehicle.

This method uses the **OCPP v2.1** ***SEND*** **message type**, therefore there will be no direct response to this message. Nevertheless, when the the charging station can not parse this message, an error message might be send.

#### Text Message Format

The ISO 15118 message can be encoded as JSON, when only the processing of the messages shall be tested, or as *Efficient XML(EXI)* or even *Ethernet frames*, when lower layer parsing shall also be tested.

*SendEVMessage (text):*

|Property|M/O|Type|JSON Type|Default|Description|
|-|-|-|-|-|-|
|evse|O|EVSE|Object|-|The optional EVSE and connector identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId) and (0 > ConnectorId ≤ MaxConnectorId(EVSEId)).|
|processingDelay|O|TimeSpan|Number (ms)|-|An optional processing delay before the request is processed by the charging station.|
|message|M|JSON Object or encoded binary data as a *text*|Object or String|-|The *ISO 15118 EV message*. Either as a JSON object **or** an encoded string representation of the EXI format.|
|messageType|O/M|ISO15118SimulationContentType|String|-|The content type of the *ISO 15118 EV message* when it is a string, e.g. *EXI*, *EthernetFrame*, ...|
|messageEncoding|O/M|ISO15118SimulationEncoding|String|BASE64|When the *ISO 15118 EV message* is e.g. encoded as EXI (binary), which additional encoding was used to transform it into a string.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|-|An (optional) enumeration of cryptographic signatures.|

#### Binary Message Format

A more efficient way of sending binary data is to make use of HTTP WebSocket binary frames. 

*SendEVMessage (binary):*

|Property|Type|Binary Type|Default|Description|
|-|-|-|-|-|
|type|BinaryDataMessageType|UInt32|-|`0x00000100`|
|evseId|EVSEId|Byte|`0x00`|The optional EVSE identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId).|
|connectorId|ConnectorId|Byte|`0x00`|The optional connector identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId) and (0 > ConnectorId ≤ MaxConnectorId(EVSEId)).|
|processingDelay|TimeSpan|UInt32 *(ms)*|`0x00000000`|An optional processing delay before the request is processed by the charging station.|
|messageType|ISO15118SimulationContentType|Byte|-|The content type of the *ISO 15118 EV message* when it is a string, e.g. *EXI*, *EthernetFrame*, ...|
|messageLength|Integer|UInt32|-|The length of the serialized *ISO 15118 EV message*|
|message|Array&lt;Byte&gt;|Array&lt;Byte&gt;|-|The *ISO 15118 EV message* as array of bytes.|
|signatureCount|Integer|Byte|`0x00`|Number of signatures|
|signatures|Array&lt;Signature&gt;|Array&lt;Byte&gt;|-|An (optional) enumeration of cryptographic signatures.|












## MCS Diagnostics

The following messages define diagnostics for the *Megawatt Charging System (MCS)*.

The Megawatt Charging System is conceptually similar to the old *Combined Charging System (CCS)*, but instead of *Pulse Wide Modulation (PWM)* and *Power LAN Communication (PLC)* it uses ***Single-Pair Ethernet*** *(Multi-Drop 10BASE-T1S, IEEE 802.3cg / IEEE 802.3-2022)* to communicate with the EV (*ISO 15118-10*) and possible other auxiliary devices between EVSE and EV. Those devices can be e.g. micro controllers, temperature, and coolant flow sensors within the charging plug and cable.

### SetCEVoltage

The *Charge Enable (CE)* pin replaces the *Charge Pilot (CP)* pin of *CCS*, but has a similar approach to signal the current charging state (A, B, C, D, E, F) of the electric vehicle via discrete voltage levels. The voltage is measured between *Charge Enable* and the *Protective Earth (PE)*, with a typical tolerance of ±0.5 volt.

Because of the high voltages and currents *IEC 61851-23-3* and *SAE J3271* require a strict monitoring of errors (state E) and faults (state F). Tests should explicitly verify the behaviour when the liquid cooling fails or the cable is unplugged unexpectedly.

| CE Voltage | State | 10BASE-T1S | EV Condition | Notes |
|------------|-------|------------|--------------|-------|
| +12 V      | A     | -          | Not connected | No vehicle connected. |
| +9 V       | B     | Active     | Connected, not requesting energy | Vehicle connected (ID-Pin confirmation). EVSE activates 10BASE-T1S link, establishing a network connection with the cable’s embedded electronics and the EV. Ready for negotiation. Not charging. |
| +6 V       | C     | Active     | Connected and ready to charge | EV requests charging, internal contactor closed. Locked cable on EV side. |
| +3 V       | D     | Active     | Charging with ventilation required (rare) | EV requests charging, requires external ventilation (e.g. battery gas exhaust). |
| 0 V        | E     | -          | Error, CE short to PE or GND | Fault or EVSE disconnected. Charging stops immediately. |
| < 0 V      | F     | -          | Error, reverse polarity or other fault | Communication error or invalid voltage detected. |
| >12 V      | -     | -          | Error, overvoltage fault | Voltage out of specification. |


The following table shows all legal transitions between EV *Charge Enable* states.

| State Transition | Allowed | Description |
|------------------|---------|-------------|
| A → B            | ✅       | Vehicle plugged in. EVSE detects vehicle via ID-Pin, 10BASE-T1S communication initiated. No power supplied yet. |
| A → C            | ❌       | Direct transition not allowed, must go through B. |
| A → D            | ❌       | Direct transition not allowed, must go through B. |
| A → E            | ⚠️      | Hard fault (e.g., CE shorted to PE), possibly due to damaged cable or vehicle. |
| A → F            | ⚠️      | Invalid CE signal (e.g., negative voltage), possibly due to wiring fault. |
| B → A            | ✅       | Vehicle unplugged. ID-Pin signals disconnection. |
| B → C            | ✅       | Vehicle ready to charge, closes internal contactor. EVSE locks cable, activates cooling, and supplies power. |
| B → D            | ✅       | Like C, but vehicle requests additional cooling (rare). EVSE adjusts cooling parameters. |
| B → E            | ⚠️      | Unexpected fault if CE pulled to GND. |
| B → F            | ⚠️      | Invalid CE voltage (e.g., < 0 V), possibly hardware defect. |
| C → A            | ❌       | Direct transition not possible, as unplugging during charging is detected as a fault (→ E). |
| C → B            | ✅       | Vehicle pauses charging, e.g., due to SoC or thermal reasons. Cooling remains active. |
| C → D            | ⚠️      | Direct switching between cooling modes not standard; vehicle typically returns to B. |
| C → E            | ⚠️      | Unexpected CE fault during charging, e.g., cable unplugged. EVSE stops power. |
| C → F            | ⚠️      | Invalid signal during charging, treated as a fault. EVSE stops power. |
| D → A            | ❌       | Direct transition not possible, as unplugging during charging is detected as a fault (→ E). |
| D → B            | ✅       | Additional cooling no longer required. |
| D → C            | ⚠️      | Direct switching between cooling modes not standard; vehicle typically returns to B. |
| D → E            | ⚠️      | CE pulled to GND during charging with increased cooling. Fault condition. EVSE stops power. |
| D → F            | ⚠️      | Invalid signal during charging, treated as a fault. EVSE stops power. |
| E → A            | ✅       | Fault resolved, vehicle unplugged. |
| E → B            | ✅       | Fault resolved, vehicle remains connected. |
| E → C            | ⚠️      | Fault state requires resolution (usually return to A or B) before charging can resume. |
| E → D            | ⚠️      | Fault state requires resolution (usually return to A or B) before charging can resume. |
| E → F            | ⚠️      | Irrelevant, may occur during unstable or cascading faults. |
| F → A            | ✅       | EVSE fault resolved, vehicle unplugged. |
| F → B            | ✅       | EVSE fault resolved, vehicle remains connected. |
| F → C            | ⚠️      | Fault state requires resolution (usually return to A or B) before charging can resume. |
| F → D            | ⚠️      | Fault state requires resolution (usually return to A or B) before charging can resume. |
| F → E            | ⚠️      | Irrelevant, may occur during unstable or cascading faults. |


```
  +-----+     Plug-In      +-----+    Contactor Close    +-----+
  |  A  | ---------------> |  B  | --------------------> | C/D |
  +-----+                  +-----+     Supply Energy     +-----+
     ^                       | ^                            |
     |        Unplug         | |      Pause Charging        |
     +-----------------------+ +----------------------------+
```


#### OCPP v1.6

*SetCEVoltageRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|voltage|M|Volt|Number (Double)|The voltage on the *Charge Enable* pin.|
|voltageError|O|Percent|Number (Double)|An optional random variation within ±n% to simulate real-world analog behavior.|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|transitionTime|O|TimeSpan|Number (ms)|An optional gradual voltage change over the given time span avoiding instantaneous jumps to simulate real-world analog behavior.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetCEVoltageResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP 2.x

*SetCEVoltageRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|voltage|M|Volt|Number (Double)|The voltage on the *Charge Enable* pin.|
|voltageError|O|Percent|Number (Double)|An optional random variation within ±n% to simulate real-world analog behavior.|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|transitionTime|O|TimeSpan|Number (ms)|An optional gradual voltage change over the given time span avoiding instantaneous jumps to simulate real-world analog behavior.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetCEVoltageResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### SetIDVoltage

The *Insertion Detection (ID)* pin detects, whether a cable is plugged into an electric vehicle or not. The exact voltage levels are not standardized, just a value range is specified. Most implementations use +5V or +12V.

| Voltage | Description    | Action          |
|---------|----------------|-----------------|
| `null`  | Not connected  |                 |
| > 0V    | Connected      |                 |
| 0V      | *Short to PE*  | Error State (E) |
| < 0V.   | *Wiring Fault* | Fault State (F) |

#### OCPP v1.6

*SetIDVoltageRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|voltage|M|Volt|Number (Double)|The voltage on the *Insertion Detection* pin.|
|voltageError|O|Percent|Number (Double)|An optional random variation within ±n% to simulate real-world analog behavior.|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|transitionTime|O|TimeSpan|Number (ms)|An optional gradual voltage change over the given time span avoiding instantaneous jumps to simulate real-world analog behavior.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetIDVoltageResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP 2.x

*SetIDVoltageRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|voltage|M|Volt|Number (Double)|The voltage on the *Insertion Detection* pin.|
|voltageError|O|Percent|Number (Double)|An optional random variation within ±n% to simulate real-world analog behavior.|
|processingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|transitionTime|O|TimeSpan|Number (ms)|An optional gradual voltage change over the given time span avoiding instantaneous jumps to simulate real-world analog behavior.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*SetIDVoltageResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|



### SendSPEMessage

This message sends an ISO 15118 or IEC 61851-23-3 data structure over the *Single-Pair Ethernet (10BASE-T1S)*, as if they would be send by the electric vehicle or other embedded electronics, e.g. within the charging cable. As multi-drop 10BASE-T1S is a half-duplex protocol the EVSE is specified as dedicated "bus master" which coordinates the *Physical Layer Collision Avoidance (PLCA)* on the communication bus.

| Device    | Node Id | Description      |
|-----------|---------|------------------|
| EVSE      | 0       | Bus Master       |
| EV        | 1       | Electric Vehicle |
| Connector | 2       | -                |
| Inlet     | 3       | -                |
| Adaptor   | 4       | -                |
| -         | 5-7     | *reserved*       |

After the ID-Pin confirms the EVSE-to-EV connection and the EV signals state B via the *Charge Enable*-Pin, the EVSE provides auxiliary power to the cable’s communication module(s) and sends a discovery message via 10BASE-T1S to identify connected devices *(IEC 61851-23-3)*.

Alternatively the **auxiliary power** can be **always on**, to monitor whether the charging cable "still exists". This helps to detect "cable theft", a common costly problem for *Charging Station Operators (CSOs)* worldwide.

According to *ISO 15118-20* and *IEC 61851-23-3* **IPv6 with Link-Local Addressing** must be used for the 10BASE-T1S communication, aligning it with automotive Ethernet standards. There is a dedicated 10BASE-T1S network per EVSE. Charging stations with multiple EVSEs have to support **IPv6 Link-Local Routing** with additional ethernet/EVSE device information.

The standards also define, the EVSE (SECC) as the initiator of the *Single-Pair Ethernet* communication, with cable electronics and EV (EVCC) only responding to EVSE requests. Yet, during charging states C or D, the EV and cable continuously monitor and report conditions like coolant temperature, flow rate, or electrical faults. If a fault is detected, e.g., coolant leak or overheating, the EV or cable sends an **unsolicited alert**, triggering a transition to fault state E or F. The microcontrollers use dedicated time slots for this kind of urgent communication.

Currently the cable communication is not yet standardized, but such a cable information might look like this:
```
{
  "cableId":           "MCS-3000A-LC-001",
  "cableCertificate":  "0x00...",
  "maxVoltage":         1250,
  "maxCurrent":         3000,
  "coolingType":       "liquid",
  "coolantStatus":     "operational",
  "temperature":        25.5
}
```


## Diagnostic Monitoring

Diagnostic Monitoring shall allow e.g. CPOs to monitor the communication of for example a charging station with internal and external connected devices like the electric vehicle (ISO 15118 communication), energy meters (Modbus RTU/TCP/UDP), time servers (NTP/NTS) and so on.

Important for efficient monitoring and to avoid an overload of the charging station to CSMS connection are **monitoring filters** and the ability to support more than one monitor for each device or communciation flow. 


### GetDiagnosticMonitorDevices

This request will return a list of all devices or communication flows, that support *Diagnostic Monitoring* and their mandatory and optional configuration parameters.

*GetDiagnosticMonitorDevicesRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|match|O|String|String|An optional include filter for string matching monitor names or descriptions.|
|evseId|O|EVSEId|String|The optional EVSE Id filter (0 > EVSEId ≤ MaxEVSEId)|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|-|An (optional) enumeration of cryptographic signatures.|

*GetDiagnosticMonitorDevicesResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|devices|M|Array&lt;MonitoringDevice&gt;|Array&lt;Object&gt;|The list of all matching *Diagnostic Monitor Devices*.|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


*MonitoringDevice:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|id|M|MonitoringDeviceId|String|The identification/name of the *Diagnostic Monitor Devices*.|
|description|O|I18NString|Array&lt;String&gt;|A multi-language description of the device.|
|filters|O|Array&lt;MonitoringDeviceFilter&gt;|Array&lt;Object&gt;|An optional list of available filters.|
|maxInstances|O|UInt16|Number *(Integer)*|Maximum number of concurrent monitors of this type.|
|runningInstances|O|UInt16|Number *(Integer)*|Current number of running monitors of this type.|


*ToDo: Would a mapping to the device model make sense?*

### SetupDiagnosticMonitor

This message sends some ISO 15118 data structure as if they would be send by an electric vehicle. Maybe JSON encoding, as this is for testing anyway. Maybe also EXI when also lower layer decoding shall be tested.

*SetupDiagnosticMonitorRequest:*

|Property|M/O|Type|JSON Type|Default|Description|
|-|-|-|-|-|-|
|monitoringDeviceId|M|MonitoringDeviceId|String|-|The identification/name of the *Diagnostic Monitor Devices*.|
|evse|O|EVSE|Object|-|The optional EVSE and connector identification, when the charging station has more than one EVSE (0 > EVSEId ≤ MaxEVSEId) and (0 > ConnectorId ≤ MaxConnectorId(EVSEId)).|
|format|O|DiagnosticMonitoringStreamFormat|String|`JSON` \| `BINARY`|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|-|An (optional) enumeration of cryptographic signatures.|

*SetupDiagnosticMonitorResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|diagnosticMonitorId|M|DiagnosticMonitorId|String|The identification of the *Diagnostic Monitor* instance.|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### DisableDiagnosticMonitor

*DisableDiagnosticMonitorRequest:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|monitoringDeviceId|M|MonitoringDeviceId|String|The identification/name of the *Diagnostic Monitor Devices*.|
|diagnosticMonitorId|M|DiagnosticMonitorId|String|The identification of the *Diagnostic Monitor* instance.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

*DisableDiagnosticMonitorResponse:*

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|status|M|GenericStatus|String|The response status.|
|statusInfo|O|StatusInfo|Object|Optional extended status information.|
|signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|



## Diagnostic Tools

Diagnostic Tools are small asynchronous applications running e.g. on the charging station for **self-** and **integration testing** and **diagnoses**. They follow the concept of AI applications using the *Model Context Protocol (MCP)* and thus might not only return a single response, but also multiple intermediary responses or status updates.

These tools might be very vendor specific and AI agents should be able to consume then without requiring external tool specifications. Therefore all tools provide their own extensive meta data about their input and output data formats.

### Ping

Send one or multiple ICMP echo request to the specified DNS name or IP address. Optional with the *Record Route* extension.

### Traceroute

Trace the IP route to the specified DNS name or IP address using the traceroute approach.

### TestCSMSNetworking

This tool will test whether the network configuration to access a CSMS is complete, free of contradictions, report TLS parameters and test whether the tools can successfully log into the (new) CSMS. This will in particular avoid costly downtimes caused by CSMS migrations which often fail because of unexpected configuration or network issues.

### TestNetworkTimeSecure

This tool will test whether the configured *Network Time Secure* time server are configured correctly (complete, free of contradictions) and the time server can be reached. The last response will also include the *NTP/NTS* time information received.



