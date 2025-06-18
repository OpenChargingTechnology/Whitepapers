# Secure Dynamic QR-Codes for OCPP

The [EU Alternative Fuels Infrastructure Regulation (AFIR)](https://transport.ec.europa.eu/transport-themes/clean-transport/alternative-fuels-sustainable-mobility-europe/alternative-fuels-infrastructure_en) mandates a **secure and user-friendly ad hoc payment process** for **publicly accessible electric vehicle charging stations**. A critical vulnerability in the current system arises from the widespread use of *Static QR-Code Stickers*, which are often affixed to the housing of the charging station. These static codes are trivial to counterfeit, replace, or obscure. This poses a significant security and trust risk for EV drivers and operators.

To mitigate this risk, a more robust solution is to use ***Secure Dynamic QR Codes***, rendered in real-time ***on the display of the charging station*** itself. These dynamic codes are time-limited, are context-aware, use shared secrets and cryptographic algorithms, and could in the future even be cryptographically signed, thus eliminating any possibility of fraudulent redirection of EV drivers.

Support for *Secure Dynamic QR Codes* is already specified in ***Open Charge Point Protocol v2.1***, particularly in the context of local payment workflows and enhanced user experience for ad hoc charging. However, the adoption of OCPP v2.1 across the ecosystem is still limited due to the existing large-scale deployments of OCPP v1.6.

The Objectives of this paper are:
1. Detailed **technical description** of the Secure Dynamic QR-Code mechanism, including security properties, data structure, and display update logic.
2. Proposal for **backwards-compatible** extensions to **OCPP v1.6** that enables the same Secure Dynamic QR-Code functionality for legacy charging stations.
3. Specification how to use the exact same QR-Code-URL via alternative technologies like **Bluetooth LE** or **Near Field Communication** for supporting charging stations without a display.
4. Discussion of future-proof enhancements, potentially for inclusion in OCPP v2.2+ or beyond.


------------

*ToDo's:*

#### Introduction

...

#### Data Structures

##### NotifyWebPaymentStartedRequest

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|evseId|M|EVSE Id|Integer, 0 ⇐ val|EVSE id for which transaction is requested.|
|timeout|M|TimeSpan|Integer (seconds)|Timeout after which the web payment process is considered aborted or failed.|
|customData|O|-|Object||

##### NotifyWebPaymentStartedResponse

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||


#### OCPP v2.1

*NotifyWebPaymentStartedRequest:*
```
{
    "evseId":      1,
    "timeout":     60
    "customData":  null
}
```

*NotifyWebPaymentStartedResponse:*
```
{
    "customData":  null
}
```


#### OCPP v2.0.1

For OCPP v2.0.1 the NotifyWebPaymentStartedRequest/-Response will be serialized as a `DataTransfer` message:

*DataTransfer.req:*
```
{
    "vendorId":    "cloud.charging.open",
    "messageId":   "NotifyWebPaymentStarted",
    "data":        {
                     "evseId":  1,
                     "timeout": 60
                   },
    "customData":  null
}
```

*DataTransfer.conf:*
```
{
    "status":      "Accepted",  // DataTransferStatus
    "data":         null,
    "statusInfo":   null,
    "customData":   null
}
```

#### OCPP v1.6

For OCPP v1.6 the NotifyWebPaymentStartedRequest/-Response will be serialized as a `DataTransfer` message. Please be cautious, that the `data` property within OCPP v1.6 DataTransfer messages is of **type** ***String***, not a structured object!

*DataTransfer.req:*
```
{
    "vendorId":   "cloud.charging.open",
    "messageId":  "NotifyWebPaymentStarted",
    "data":       "{
                     "evseId":  1,
                     "timeout": 60
                  }"
}
```

*DataTransfer.conf:*
```
{
    "status":      "Accepted",  // DataTransferStatus
    "data":         null
}
```


#### Diagnostic Tools

...


#### Test Cases

...


#### Implementations

- https://github.com/OpenChargingCloud/DynamicQRCodes/
- https://github.com/OpenChargingCloud/DynamicQRCodes.Android

