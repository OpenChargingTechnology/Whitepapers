# Secure Dynamic QR-Codes for OCPP

The [EU Alternative Fuels Infrastructure Regulation (AFIR)](https://transport.ec.europa.eu/transport-themes/clean-transport/alternative-fuels-sustainable-mobility-europe/alternative-fuels-infrastructure_en) mandates a **secure and user-friendly ad hoc payment process** for **publicly accessible electric vehicle charging stations**. A critical vulnerability in the current system arises from the widespread use of *Static QR-Code Stickers*, which are often affixed to the housing of the charging station. These static codes are trivial to counterfeit, replace, or obscure. This poses a significant security and trust risk for EV drivers and operators.

To mitigate this risk, a more robust solution is to use ***Secure Dynamic QR Codes***, rendered in real-time ***on the display of the charging station*** itself. These dynamic codes are time-limited, are context-aware, use shared secrets and cryptographic algorithms, and could in the future even be cryptographically signed, thus eliminating any possibility of fraudulent redirection of EV drivers.

Support for *Secure Dynamic QR Codes* is already specified in ***Open Charge Point Protocol v2.1***, particularly in the context of local payment workflows and enhanced user experience for ad hoc charging. However, the adoption of OCPP v2.1 across the ecosystem is still limited due to the existing large-scale deployments of OCPP v1.6.

The Objectives of this paper are:
1. Detailed **technical description** of the Secure Dynamic QR-Code mechanism, including security properties, data structure, and display update logic.
2. Proposal for a **backwards-compatible** extension to **OCPP v1.6** that enables the same Secure Dynamic QR-Code functionality on legacy charging stations.
3. Specification how to use the exact same QR-Code-URL via alternative technologies like **Bluetooth LE** or **Near Field Communication** for supporting charging stations without a display.
4. Discussion of future-proof enhancements, potentially for inclusion in OCPP v2.2+ or beyond.



------------

*ToDo's:*

#### Diagnostic Toools

...


#### Test Cases

...

