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

CSMS optionally sends a NotifyWebPaymentStartedRequest message with evseId and
timeout to notify Charging Station of the event.

Charging Station displays feedback to EV Driver and prevents that a transaction is started locally on the EVSE in evseId for as long as timeout seconds, or until the RequestStartTransactionRequest from CSMS is received.


#### Data Structures

##### NotifyWebPaymentStartedRequest

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|evseId|M|EVSE Id|Integer, 0 ⇐ val|EVSE id for which transaction is requested.|
|timeout|M|TimeSpan|Integer (seconds)|Timeout after which the web payment process is considered aborted or failed. Should be <= 5 minutes.|
|customData|O|-|Object||

##### NotifyWebPaymentStartedResponse

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||


#### OCPP v2.1

OCPP v2.1 has native support for NotifyWebPaymentStartedRequests and -responses. Request errors are signaled via the normal *CALLERROR* response. Response errors can use the new *CALLRESULTERROR* message.

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
Request Error Handling:

|Error|Response|
|-|-|
|**evseId** is missing or *null*.|The charging station SHALL return a *CALLERROR* with **errorCode** = `OccurrenceConstraintViolation` and an optional **ErrorDescription** ~= `"Missing 'evseId' value!"`.|
|**evseId** is not an *Integer*.|The charging station SHALL return a *CALLERROR* with **errorCode** = `TypeConstraintViolation` and an optional **ErrorDescription** ~=`"Property 'evseId' must be of type Integer!"`.|
|**evseId** is not between *0 < evseId <= MaxEVSEId*.|The charging station SHALL return a *CALLERROR* with **errorCode** = `PropertyConstraintViolation` and an optional **ErrorDescription** ~=`"Invalid value '{value}' for property 'evseId'!"`.|
|**timeout** is missing or *null*.|The charging station SHALL return a *CALLERROR* with **errorCode** = `OccurrenceConstraintViolation` and an optional **ErrorDescription** ~= `"Missing 'timeout' value!"`.|
|**timeout** is not an *Integer*.|The charging station SHALL return a *CALLERROR* with **errorCode** = `TypeConstraintViolation` and an optional **ErrorDescription** ~=`"Property 'timeout' must be of type Integer!"`.|
|**timeout** is not between *0 < timeout <= 300 seconds*.|The charging station SHALL return a *CALLERROR* with **errorCode** = `PropertyConstraintViolation` and an optional **ErrorDescription** ~=`"The 'timeout' must be >0 and <= 300 seconds!"`.|

The **ErrorDetails** should contain an optinal JSON object consiting of *property*, *value* and a copy of the entire received *NotifyWebPaymentStartedRequest*.

*CALLERROR:*
```
[
     4,
    "162376037",
    "PropertyConstraintViolation",
    "Invalid value '999999999' for property 'timeout'!",
    {
        "property":   "timeout",
        "value":      999999999,
        "request":    {
           "evseId":      1,
           "timeout":     999999999
           "customData":  null
        }
    }
]
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
                   }
}
```

*DataTransfer.conf:*
```
{
    "status":      "Accepted",
    "data":         null,
    "statusInfo":   null
}
```

Request Error Handling:

|Error|Response|
|-|-|
|The **VendorId** is missing, *null*, or unknown on the charging station.|The charging station SHALL return a status = DataTransferStatus.**UnknownVendor**.|
|The charging station has no implementation for the given VendorId.**MessageId**.|The recipient SHALL return a status = DataTransferStatus.**UnknownMessageId**.|
|data.**evseId** is missing, *null*, `0` or *invalid*.|The charging station SHALL return a status = DataTransferStatus.**Rejected**, data.**reasonCode** = `"invalidTimeout"` and an optional data.**additionalInfo** ~= `"Invalid 'evseId' value!"`.|
|data.**timeout** is missing, *null*, not a *positive Integer > 0* or larger than 5 minutes.|The charging station SHALL return a status = DataTransferStatus.**Rejected**, data.**reasonCode** = `"invalidTimeout"` and an optional data.**additionalInfo** ~= `"Invalid 'timeout' value!"`.|

```
{
    "status":      "Rejected",
    "statusInfo":  {
                      "reasonCode":     "invalidTimeout",
                      "additionalInfo": "Invalid 'timeout' value!"
                   }
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
                     \"evseId\":  1,
                     \"timeout\": 60
                  }"
}
```

*DataTransfer.conf:*

```
{
    "status":  "Accepted"
}
```

Request Error Handling:

|Error|Response|
|-|-|
|The **VendorId** is missing, *null*, or unknown on the charging station.|The charging station SHALL return a status = DataTransferStatus.**UnknownVendor**.|
|The charging station has no implementation for the given VendorId.**MessageId**.|The recipient SHALL return a status = DataTransferStatus.**UnknownMessageId**.|
|data.**evseId** is missing, *null*, `0` or *invalid*.|The charging station SHALL return a status = DataTransferStatus.**Rejected** and data.**message** ~= `"Invalid 'evseId' value!"`.|
|data.**timeout** is missing, *null*, not a *positive Integer > 0* or larger than 5 minutes.|The charging station SHALL return a status = DataTransferStatus.**Rejected** and data.**message** ~= `"Invalid 'timeout' value!"`.|

```
{
    "status":  "Rejected",
    "data":    "{ \"message\": \"Invalid 'timeout' value!\" }"
}
```

#### Diagnostic Tools

...


#### Test Cases

...


#### Implementations

- https://github.com/OpenChargingCloud/DynamicQRCodes/
- https://github.com/OpenChargingCloud/DynamicQRCodes.Android

