# OCPP Advanced Diagnostics

As the complexity and criticality of electric vehicle (EV) charging infrastructure increases, the need for robust and transparent diagnostic capabilities in charging stations and other OCPP enabled devices becomes paramount. Currently, the Open Charge Point Protocol (OCPP) lacks a standardized mechanism to *explicitly* define, trigger, and monitor e.g. self or integration tests within its core message set and device model. This gap leads to proprietary extensions, inconsistent implementations, and reduced interoperability across manufacturers and management systems on top of the specified generic device model reporting, diagnostic and logging mechanisms.

An explicit diagnostics model, tightly integrated into the OCPP device model and request/response/messsage framework, would enable charging station operators to reliably enumerate, parameterize, and execute a wide range of diagnostics — ranging from simple software integrity self checks, over complex hardware validation routines to integration tests within the charging station operator network. By describing available tests, their required parameters, operational constraints, and expected outcomes in a machine-readable and discoverable manner, operators gain better tools for remote maintenance, troubleshooting, and regulatory compliance.

Importantly, self tests should not only be accessible for manual execution by human operators or for periodic automated routines, but also be available to intelligent software agents and AI-based diagnostic systems. Such agents can proactively trigger or sequence self tests in response to anomalies, performance degradation, or security incidents, enabling more effective root cause analysis and faster problem resolution within the charging infrastructure.

Moreover, standardized test models support automation of periodic health checks, real-time fault isolation, and evidence-based reporting for quality assurance and cybersecurity audits. It also facilitates seamless backend integration, future-proofing OCPP deployments against evolving reliability and safety requirements in critical infrastructure. Therefore, the introduction of a formal self test model in OCPP is essential for improving the transparency, resilience, and maintainability of EV charging networks.

## Scope

This subchapter provides a differentiation between various diagnostic test types that can be performed by charging stations and other OCPP devices. By clearly outlining the purpose and scope of each test type, this section ensures consistent terminology and lays the foundation for advanced diagnostics and automated monitoring of the entire charging infrastructure.

| Test Type | Support | Role and Description | Example |
|------------------|--|----------------------------------|----------------------------------|
| Self Test          | yes | A test executed locally and autonomously by the charging station to verify the integrity and correct functioning of its internal hardware and software components, independent of external systems. Self-tests can be triggered on demand, scheduled, or during startup, and provide detailed diagnostic results on the internal health status of the device. | Testing the reachability of the internal energy meter connected via RS485 and Modbus/RTU. |
| Integration Test   | yes | A test performed by the charging station to verify the correct operation and connectivity of external interfaces, dependencies, and services such as backends, network infrastructure, or peripheral devices. Integration tests ensure the station is correctly embedded in its operational environment and can communicate as expected. | Testing the reachability and rootCAs of Network Time Secure legal servers. |
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

