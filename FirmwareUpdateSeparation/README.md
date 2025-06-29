# OCPP 2.x Firmware Updates with Software Separation

The firmware update mechanism currently standardized within the *Open Charge Point Protocol (OCPP)* assumes that each charging station or local controller hosts **exactly one firmware image**, and that the entire image will be replaced during an update process. While this **monolithic assumption** may have been sufficend in early deployments of simple AC wallboxes, it is increasingly misaligned with the technical, regulatory, and security realities of the modern EV charging infrastructure.

In practice, a charging station comprises multiple independent software and firmware components, often running on separate microcontrollers, operating systems, or isolated environments. These components control distinct subsystems such as user interface, communication modules, power electronics, vehicle communication stacks, and the metrological measuring devices responsible for energy billing. These diverse subsystems are governed by different legal domains. The most prominent domain, energy metering, is e.g. regulated under the ***EU Measuring Instruments Directive (MID)***. MID-compliant software components typically require type approval, source sealing, and third-party certification with in-field test samples, which will most often take multiple weeks or even months.

This leads to a critical regulatory conflict. As the ***EU Cyber Resilience Act (CRA)*** and ***Network and Information Security 2 Directive (NIS2)*** come into force, operators will be required to roll out security-critical updates within extremely short timeframes, often in less than 24 or 72 hours after a critical vulnerability had been disclosed. However, when the firmware is treated as a single monolithic blob, any update—no matter whether it touches a regulated function or not—would fall under the most strict regulatory requirements, effectively blocking timely updates until the entire firmware image was re-certified.

To resolve this tension between **legal traceability** and **agile security responses**, we propose a new modular firmware update concept and corresponding extensions to OCPP. Instead of assuming a single firmware image, the charging station should be able to report a structured **Firmware Component Model**, where each component represents a logically and legally distinct firmware image. For each component, the device reports metadata such as the firmware name, current version, functional role, regulatory classification (e.g., metrologically relevant), compatibility with other firmware components, software bill of materials (SBOM), multiple digital signatures, update policy, where to find updates, where and how to report vulnerabilities. This enables selective updating of non-sensitive components such as parts of the user interface without interfering with regulated software.

Additionally, this extension enables the **Charging Station Operator (CPO)** to track firmware provenance, maintain a cryptographic audit trail, and fulfill all lifecycle transparency requirements, including software bill of materials (SBOM) tracking and vulnerability disclosure.


## Device Model Information

- Only overview information, as details are lengthy!
- *Firmware Component Controller*, with Instance = Firmware Name
- Per Firmware *(mostly read-only)*:
  - Name
  - Version
  - Functional Role
  - Regulatory Classification (list)
  - Cryptographic hash
  - Release Date
  - Installation Date
  - Audit trail hash

## Requests/Respones

### GetFirmwareComponents

#### GetFirmwareComponentsRequest

Request a detailed list of all firmware components.    
Maybe optional filter parameters e.g. *Regulatory Classification  == "EU MID"*.


#### GetFirmwareComponentsResponse

Return a list of all (matching) firmware components.


### UpdateFirmware

#### UpdateFirmwareComponentsRequest

Initialize an update of the specified firmware components.    
Multiple at once as there might be dependencies.

#### UpdateFirmwareComponentsResponse

Information about how to track this asynchronous process.



## Metrological Transparency Software

**Metrological regulation** like the ***German Eichrecht*** requires a so called ***Transparency Software*** which enables EV drivers to validate the metrological and billing aspects of a charging session via an independent application on their own computers or smartphones. **This software is legal part of the charging station** and has dependencies with othere firmware components. Even when this software is never installed onto the charging station itself, it should be part of the *Firmware Components List* provided by the charging station. By this the *Charging Station Operator* can easily track its correct version and provide this information to the EV driver, e.g. by showing this information within an app and by printing it onto the invoice.

For EV roaming use cases it is expected, that the *Charging Station Operator* will forward this information to all *EV Roaming Networks* and *E-Mobility Service Providers (EMPs/EMSPs)*.

On request, the manufacturer should also provide a link to the correct transparency software version, e.g. as QR-Code on the display of the charging station.


## Migration

The update of an existing monolithic firmware image can result in a firmware supporting software separation. It is not assumed, that this will have any side effects.


## Backwards Compatibility

The current monolithic firmware of a charging station will always be identified as `default` firmware component. ***Default*** implies, that there are **no other firmware components**. Therefore this firmware component name must not be used when there is more than one firmware component.

When the old firmware update requests are used and more than just the *default* firmware exists, a charging station should respont with ***Rejected*** and explain that the new requests must be used.




##### ToDo's

Some of those ToDo's are "just" related and might later be part of other specifications!

- How to specify the PKI for the firmware download process?
- Firmware upload via binary OCPP channels.
- Declaration which services run per firmware component as "save default"
- Support of multiple "safe default"-configurations for different CPO use cases
- Is the Bootloader an (updateable) "OCPP firmware component"? Can it be updated independently?
- How to update certificates for booting?
- Declaration whether downgrading is allowed and/or to which extend.
- How to add 3rd party certificates for booting?
- Declaration whether alternative firmware trees and 3rd party firmware can be installed.
- Send hash and validate it against cert chains, before sending the entire software update?!
- How to support in-place firmware updates (including a 2nd partition) ((Bianry) streaming required).
- How to support "public" vs. "personalized" firmware images?
- How to support automatic scheduled updates? Is this configurable?
- Link to risk assesment / threat modelling documentation.
- Declaration whether the disc provides encryption (EU CRA)
- Declaration whether the disc provides integrity guarantees/resilience against bit and burst errors? (EU CRA)
- Declaration about the quality of the hardware random number generator.
- Declaration what sensitive data is and how it is protected and stored (tamper protected storage?).
- SBOM or signed link to SBOM
- Deep links to firmware update informations/Where to find new versions automatically.
- Links/description how to report errors and which workflow can be expected
- Links/description how to report vulnerabilities and which workflow can be expected
- Compact export of hardware infos, firmware infos and configuration to support backups, error and vulnerability reports
- Digital Declaration/Certification of Conformity
- Digital Declaration/Certification of Calibration
- Is there a default password? Is it required to be changed during commissioning?
- Are there passwords unique per device?
- Is there a unique root public key per device? Where can the private key be found (QR-Code et.al)?
- How can all TLS parameters be cryptoagil?
- Is there a manufacturer telemetry service? What does it do? How to review it? How to disable it?
- How is "Reset to factory defaults" implemented in case of multiple "safe default configurations".
- How is "remove all privacy sensitive data (after XX days)" achievable?
- Guidance on how to check whether the device is securely set up and maintained in a secure state.
- Provide clear and transparent information about what personal data is processed and for what purposes, by whom, and for how long, also for associated services (CPOs, EV Roaming, EMPs, ...).
- How is "constent" to privacy relevant data processing recorded?
