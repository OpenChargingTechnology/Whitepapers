# OCPP Advanced Diagnostics

As the complexity and criticality of electric vehicle (EV) charging infrastructure increases, the need for robust and transparent **diagnostic capabilities** in charging stations and other OCPP enabled devices becomes paramount. Currently, the *Open Charge Point Protocol (OCPP)* lacks a standardized mechanism to ***explicitly*** **define, trigger, and monitor** e.g. **self and integration tests** within its device model and message set. This gap leads to proprietary extensions, inconsistent implementations, and reduced interoperability across manufacturers and management systems on top of the specified generic device model reporting, diagnostic and logging mechanisms.

An explicit diagnostics model, tightly integrated into the OCPP device model and messsage framework, would enable charging station operators to reliably enumerate, parameterize, and execute a wide range of diagnostics — ranging from simple **software integrity self checks**, over **complex hardware validation routines** to **integration tests within the charging station operator network**. By describing available tests, their required parameters, operational constraints, intermediate reports, and expected outcomes in a **machine-readable** and discoverable manner, operators gain better tools for remote maintenance, troubleshooting, and regulatory compliance.

Importantly, self tests should not only be accessible for manual execution by human operators or for periodic automated routines, but also be available to intelligent software agents and **AI-based diagnostic systems**. Such agents can proactively trigger or sequence self tests in response to anomalies, performance degradation, or security incidents, enabling more effective root cause analysis and faster problem resolution within the charging infrastructure.

Moreover, standardized test models support automation of periodic health checks, real-time fault isolation, and evidence-based reporting for quality assurance and **cybersecurity audits**. It also facilitates seamless backend integration, future-proofing OCPP deployments against evolving reliability and safety requirements in critical infrastructure like the upcoming ***European Network and Information Systems 2 (NIS2) Directive***. Therefore, the introduction of a formal self test model in OCPP and related protocols is essential for improving the transparency, resilience, and maintainability of EV charging networks.

## Scope

This subchapter provides a differentiation between various diagnostic test types that can be performed by charging stations and other OCPP devices. By clearly outlining the purpose and scope of each test type, this section ensures consistent terminology and lays the foundation for advanced diagnostics and automated monitoring of the entire charging infrastructure.

| Test Type | Support | Role and Description | Example |
|------------------|--|----------------------------------|----------------------------------|
| Diagnostic Control | yes | A normal OCPP request sent to read or set internal state or simulate interactions that are out-of-scope of the normal OCPP communication. | Simulate the swipping of a RFID card for starting an authorization and charging process. |
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


### SetVariables *(extended)*

This request extends the existing *SetVariables* request functionality by adding support for structured, **recursive transactions**. It allows multiple individual SetVariable operations to be grouped into a single atomic unit, with clearly defined semantics for **concurrent execution**, **dependency ordering**, and **error handling**.

In addition, the extension addresses a critical limitation of the current SetVariable operation: In standard OCPP, **variables are unconditionally overwritten**, regardless of their previous state. While this is acceptable in centralized or single-writer environments, it poses risks in modern distributed or concurrent control architectures, where multiple systems (e.g., CSMS, local controllers, or operator tools) may attempt to update the same variable concurrently.

To improve safety in such contexts, this extension introduces **conditional update semantics**. A SetVariable entry may optionally specify the expected current value, and the update is only applied if the value on the target system matches this expectation at the time of execution. This mechanism is conceptually equivalent to *HTTP constraint-based updates* using *If-Match* headers or *Compare-and-Swap (CAS)* operations in distributed systems.

Such conditional updates reduce the risk of unintended overwrites, support optimistic concurrency control, and enable reliable configuration workflows in asynchronous and multi-actor environments.


### SwipeRFIDCard

This request simulates the **swiping of an RFID card** triggering RFID UID detection, authorization, and maybe the start of a charging session without requiring physical presence or hardware interaction. The same mechanism can also be used to terminate an active charging session, either by simulating the swipe of the same RFID card used to initiate the session, or by simulating a swipe of another card that belongs to the same authorization group.

#### OCPP v1.6

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|IdTag|M|IdTag|String|The identification tag, e.g. of the RFID card to be swiped.|
|ProcessingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|Signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|

#### OCPP v2.x

|Property|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|IdToken|M|IdToken|Object|The identification token, e.g. of the RFID card to be swiped.|
|ProcessingDelay|O|TimeSpan|Number (ms)|An optional processing delay before the request is processed by the charging station.|
|Signatures|M/O|Array&lt;Signature&gt;|Array&lt;Object&gt;|An (optional) enumeration of cryptographic signatures.|


### AdjustTimeScale

This request is a diagnostic extension to OCPP that enables external test tools or validation frameworks to temporarily **alter the rate at which simulated time progresses** within a charging station or associated components. This feature is particularly valuable in testing scenarios that depend on elapsed time, such as the automatic stop of a charging session after a specified duration, authorization timeouts, or inactivity handling. By accelerating or decelerating the passage of time for internal logic, **long-running tests can be executed significantly faster**, or timers can be frozen for controlled debugging.

The request specifies a timeScale value, which is a positive decimal number representing the multiplier applied to simulated time. A value of 1.0 indicates normal time progression, while a value of 2.0 causes internal time to progress twice as fast as real time. A value of 0.5 slows time down by half, and a value of 0.0 effectively pauses all time-based logic in the affected domain. To prevent unintended permanent changes, the request may optionally include a duration parameter (in seconds), after which the time scale automatically reverts to the normal value of 1.0.

This request is intended solely for testing and validation purposes in non-production environments. Charging stations operating in production mode may reject this request unless explicitly configured to permit it under controlled conditions. The response to such a request includes a status field indicating whether the operation was accepted, rejected, or not supported, and may optionally return the actually applied time scale, which might be capped or adjusted internally for implementation or safety reasons.


### TimeTravel

This request enables controlled manipulation of the system clock on a charging station or related component. Unlike the *AdjustTimeScale* request, which affects only the relative flow of internal time, *TimeTravel* allows the system to temporarily **jump forward or backward in time**, for example to simulate behavior under certificate expiration, daylight saving changes, authorization token expiry, **dynamic tariff changes**, or to validate metrological timestamp boundaries. Optionally, it may also define a duration, after which the system clock reverts to the original (real) time source. If no duration is specified, the simulated time remains active until explicitly reset or overridden by a subsequent request.

This request is intended solely for testing and validation purposes in non-production environments. Charging stations operating in production mode may reject this request unless explicitly configured to permit it under controlled conditions. 
