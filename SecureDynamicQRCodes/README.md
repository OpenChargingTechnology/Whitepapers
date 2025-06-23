# Ad hoc Payments via Secure Dynamic QR-Codes for OCPP and OCPI

The [EU Alternative Fuels Infrastructure Regulation (AFIR)](https://transport.ec.europa.eu/transport-themes/clean-transport/alternative-fuels-sustainable-mobility-europe/alternative-fuels-infrastructure_en) mandates a **secure and user-friendly ad hoc payment process** for **publicly accessible electric vehicle charging stations**. A critical vulnerability in the current system arises from the widespread use of *Static QR-Code Stickers*, which are often affixed to the housing of the charging station. These static codes are trivial to counterfeit, replace, or obscure. This poses a significant security and trust risk for EV drivers and operators.

To mitigate this risk, a more robust solution is to use ***Secure Dynamic QR Codes***, rendered in real-time ***on the display of the charging station*** itself. These dynamic codes are time-limited, are context-aware, use shared secrets and cryptographic algorithms, and could in the future even be cryptographically signed, thus eliminating any possibility of fraudulent redirection of EV drivers.

Support for *Secure Dynamic QR Codes* is already specified in ***Open Charge Point Protocol v2.1***, particularly in the context of local ad hoc payment workflows *(Part 2 C25)*. However, the adoption of OCPP v2.1 across the ecosystem is still limited due to the existing large-scale deployments of OCPP v1.6. Therefore this paper also specifies **compatible** extensions for **OCPP v2.0.1** and **OCPP v1.6** that enables the same *Secure Dynamic QR-Code* functionality for legacy charging stations.



The paper concludes with a discussion of possible future-proof enhancements, which might be included in OCPP v2.2+ or beyond.


## Introduction

When an EV driver wants to charge and pay via an ad hoc payment method, one possible option is, that he scans a QR code shown on the display of the charging station with his smartphone. This QR code is unique per charging station and in time, as its URL is secured by a ***time-based one-time password*** based on a shared secret between the charging station and the QR code backend. On the charging station display additional optional charging session parameters like *maxTime*, *maxPrice* or *maxKWh* could be shown. When the EV driver has selected some of them, these selections will be added to the URL template of the QR code.

When the EV driver opens the web page the QR code backend will decode all given URL parameters according to the URL template and validate at least the *time-based one-time password* and the *charging station* or *EVSE identification*. An optional *NotifyWebPaymentStartedRequest* can be send to the CSMS via OCPI and from there to the charging station via OCPP. This messages allows the CSMS to block all remote start methods for this charging station and/or EVSE for a given amount of time. Further it allows the charging station to disable all local authentication methods at the given EVSE for a given amount time and to give the EV driver some visible or auditable feedback, that the QR code indeed started at the right charging station and EVSE. When the timeout was reached and no session was started at this EVSE this shall again be indicated in an appropriate way.

On the QR code web page the EV driver might configure additional optional charging session parameters like *maxTime*, *maxPrice* or *maxKWh* and finally authenticate the payment via a payment or e-mobility service provider.

After the payment process returned successfully with some additional information like an unique payment reference identification *pspRef*, the QR code backend will start a charging session via a *RemoteStart (OCPI)* and/or *RequestStartTransaction (OCPP)* request with ***idToken***  = `pspRef` and ***type*** = `DirectPayment`. This request can have optional charging session configuration parameters like *maxTime*, *maxPrice* or *maxKWh* to define a *cost limit* *(see also: OCPP v2.1 part 2 F07 Remote start with cost limit)*. This allows the charging station to stop the charging session automatically when one of the criteria was reached.

*See also: OCPP v2.1 Edition 1 Part 2 "C25 Ad hoc payment via QR code"*

## QR Code URL Templates

The QR code contains the URL to the QR code backend web page for ad hoc payments. This backend can be provided directly from a CSMS, but also from an external 3rd party. The exact format of the URL is up to bilateral agreements, as long as certain mandatory URL parameters exist that are needed to support the use case.

The URL is a defined as a template that contains parts ("variables") that are filled in by the charging station. These variables are put between curly braces as path parameters in the URL template. The case of the variable names shall be ignored. For example:

Example URL without EVSE Id
https://qr.mycsms.com/{totp}/{version}/{chargingStationId}/

Example URL with EVSE
https://qr.mycsms.com/{chargingStationId}/{evse}/{totp}?v={version}

The URL may contain additional parameters that are filled in by the charging station e.g. based upon EV driver input. This would allow an EV driver to specify, for example, a maximum amount of energy to charge. By this the maximum energy/time/cost request is also communicated towards the payment provider which might include this information into its payment process metadata and final payment invoice.

The following variables are specified. 

| Variable | M/O | Type | Description |
|-|-|-|-|
| chargingStationId | M | String | Charging Station Identity |
| evse | M | Integer | The EVSE for which the payment is requested |
| roamingCSId | O | String | The charging station for which the payment is requested (Format: ISO 15118 like) |
| roamingEVSEId | O | String | The EVSE for which the payment is requested (Format: ISO 15118) |
| totp | M | String | The calculated time-based one-time password |
| version | M | String | The version of the time-based one-time password algorithm |
| maxEnergy | O | Integer | Maximum energy in Wh |
| maxTime | O | Integer | Maximum charging time in seconds |
| maxCost | O | Currency | Maximum cost in currency of the charging station |


## Time-Based One-Time Password Algorithm

The algorithm to calculate the *time-based one-time password* uses the HMAC-SHA256 cryptographic hash function on the byte representation of the start of the current time interval (UTC) in seconds. The bytes are mapped to digits and characters according a given alphabet. For added security the mapping starts not at the first byte, but at a semi-random offset that is calculated from the last byte of the hash.

A reference implementation in C#:
```
// Input parameters
var validityTime  = TimeSpan.FromSeconds(ValidityTime);
var totpLength    = Length;
var sharedSecret  = SharedSecret;  // for charging station/EVSE
var base62        = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Get time interval
var timeInSeconds = DateTime.UtcNow - new DateTime(1970, 1, 1);
var timeInterval  = (UInt64) (timeInSeconds.TotalSeconds / validityTime.TotalSeconds);
var timeBytes     = BitConverter.GetBytes(timeInterval);

if (BitConverter.IsLittleEndian)
    Array.Reverse(timeBytes);

using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(sharedSecret)))
{

    var hash          = hmac.ComputeHash(timeBytes);

    // Convert hash bytes to characters starting at random offset
    var offset        = hash[^1] & 0x0F;
    var stringBuilder = new StringBuilder();

    for (var i = 0; i < totpLength; i++)
        stringBuilder.Append(base62[hash[(offset + i) % hash.Length] % base62.Length]);

    return stringBuilder.ToString();

}
```

The QR code backend validates the time-based one-time password (TOTP) in the URL against the TOTP that it calculates for the current time and given charging station and/or EVSE identification.

The TOTP in the URL (URL-TOTP) is considered valid if it equals the TOTP calculated by the QR code backend (Backend-TOTP). If the TOTPs are not equal backend shall try to compare the URL-TOTP against a Backend-TOTP for the previous time interval and the next time interval. This overcomes failed validation as a result processing delays or small differences in clock time.
If URL-TOTP and Backend-TOTP still do not match in any of these cases, then Backend shall consider the URL as invalid.


## Device Model Information




## Requests/Respones

### NotifyWebPaymentStarted

With the *NotifyWebPaymentStarted* request the QR code backend can inform the CSMS and by this the charging station about a just started *web payment process* at a given *EVSE identification* and block concurrent processes for a given timeout. The request can be sent multiple times, e.g. to update the timeout. A timeout value of `0` can be seen as a silent revocation of a previous request.


#### OCPI NotifyWebPaymentStarted

The QR Code backend sends an optional NotifyWebPaymentStarted command including the EVSE identification and a timeout to the **OCPI command module of the CSMS** in order to inform the CPO about a started web payment process. This command is similar to its OCPP counterpart with the only difference, that the *EVSE Identifcation* will use the ISO 15118 (eMI3) EV Roaming data format like e.g.: `DE*GEF*E12345678*1`. Optionally the command can also use the OCPI `location_id` and `evse_uid` for legacy use cases. The `rquest_url` is optional, as in most cases there will be no interesting response from the CSMS and charging station.

For improved compatibility with OCPP v2.x this OCPI request/response also allows a *CustomData* JSON object.

**OCPI NotifyWebPaymentStarted Command**

```
POST https://ocpi.example.com/cpo/2.3.0/commands/NOTIFY_WEB_PAYMENT_STARTED
```

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|response_url|O|URL|String|URL that the CommandResult POST should be sent to. This URL might contain a unique Id to be able to distinguish between NotifyWebPaymentStarted commands.
|evse_id|M|EVSE Id|String|EVSE Identification for which transaction is requested (ISO 15118 format).|
|location_id|O|Location Id|String|OCPI Location Identification for which transaction is requested.|
|evse_uid|O|EVSE UId|String|OCPI EVSE Unique Identification for which transaction is requested.|
|timeout|M|TimeSpan|Integer (seconds)|Timeout after which the web payment process is considered aborted or failed. Should be <= 5 minutes.|
|customData|O|-|Object||

**OCPI NotifyWebPaymentStarted Command Result**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||



#### OCPP NotifyWebPaymentStarted

The CSMS sends an optional NotifyWebPaymentStarted request including the EVSE identification and a timeout to the charging station in order to inform the station about a started web payment process.

Charging Station displays feedback to EV Driver and prevents that a concurrent charging session is started locally on the given EVSE for the given timeout, or until the RequestStartTransaction request from CSMS was received.

**NotifyWebPaymentStartedRequest**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|evseId|M|EVSE Id|Integer, 0 ⇐ val|EVSE id for which transaction is requested.|
|timeout|M|TimeSpan|Integer (seconds)|Timeout after which the web payment process is considered aborted or failed. Should be <= 5 minutes.|
|customData|O|-|Object||

**NotifyWebPaymentStartedResponse**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||


##### OCPP v2.1

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


##### OCPP v2.0.1

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


##### OCPP v1.6

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


### NotifyWebPaymentFailed

*ToDo: Do we need this?*


## Diagnostic Tools

...


## Test Cases

...


## Implementations

- https://github.com/OpenChargingCloud/DynamicQRCodes/
- https://github.com/OpenChargingCloud/DynamicQRCodes.Android

