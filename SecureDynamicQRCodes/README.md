# Ad hoc Payments via Secure Dynamic QR-Codes for OCPP and OCPI

The [EU Alternative Fuels Infrastructure Regulation (AFIR)](https://transport.ec.europa.eu/transport-themes/clean-transport/alternative-fuels-sustainable-mobility-europe/alternative-fuels-infrastructure_en) mandates a **secure and user-friendly ad hoc payment process** for **publicly accessible electric vehicle charging stations**. A *critical vulnerability* in the current system arises from the widespread use of *static QR-Code Stickers*, which are often sticked to the housing of the charging station. These static codes are trivial to counterfeit, replace, or obscure. This poses a significant security and trust risk for EV drivers and operators.

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
| roamingCSId | O | String | The charging station for which the payment is requested<br>*(Format: ISO 15118 like, e.g. DE\*GEF\*S12345678)*|
| roamingEVSEId | O | String | The EVSE for which the payment is requested<br>*(Format: ISO 15118, e.g. DE\*GEF\*E12345678\*1)*|
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


## Device Model Information / Configuration

The configuration mechanisms in OCPP 1.6 and OCPP 2.x differ fundamentally in structure and semantics. To ensure compatibility and clarity, both approaches are explicitly described in the following sections.

In OCPP 1.6, configuration is handled via the GetConfiguration and ChangeConfiguration messages, operating on flat key-value pairs. Each configuration key is predefined, and their names and behavior are mostly implementation-specific beyond the OCPP core specification.

In contrast, OCPP 2.x introduces a hierarchical structured configuration model. It uses the GetVariables, SetVariables, and GetBaseReport messages, in conjunction with component-variable pairs and optional attribute types (Actual, Target, MinSet, etc.). Configuration items are semantically grouped into components, with detailed metadata about mutability, persistence, and applicability, allowing fine-grained control, validation, and introspection.

Because of these architectural differences, any implementation or specification that aims to support both versions must define separate handling logic and configuration schemas tailored to the respective protocol version. The next sections outline the corresponding configuration methods and expected data structures for both OCPP 1.6 and OCPP 2.x in detail.

### OCPP 2.x

The OCPP 2.x Device Model introduces the **Web Payments Controller** *(WebPaymentsCtrlr)* as a dedicated component for managing the generation of **Time-Based One-Time Password** and for configuring additional **QR-Code rendering parameters** related to web-based payment flows.

The controller supports **instantiation per EVSE**, enabling charging stations with multiple EVSEs to render independent web payment QR codes, each with its own configuration parameters. This facilitates parallel and isolated payment flows per connector. However, it is equally possible to configure a single shared QR code for all EVSEs. In this case, the specific EVSE (Id) can be selected either directly on the charging station’s display before initiating the payment process or later on the web payment web site.

|Variable|M/O|Type|JSON Type|RW/RO|Description|
|-|-|-|-|-|-|
|Enabled|M|Boolean|Boolean|RW||
|URLTemplate  |M|URL       |String|RW|The URL Template|
|URLParameters|O|MemberList|Array |RO|List of supported URL template parameters: *"maxTime"*, *"maxEnergy"* and *"maxCost"*.<br><br>valuesList: *"maxTime"*, *"maxEnergy"*, *"maxCost"*. When absent, none of these are supported.|
|TOTPVersion|M|OptionList|Array|RW|The version of the TOTP algorithm to use.|
|RoamingEvseId|O|15118 EVSE Id|String|RW|Roaming EVSE Id (ISO 15118 format) to be used when URL is pointing to an external party.|
|ValidityTime|M|TimeSpan|Integer|RW|Validity of a one-time password in seconds. Acceptable range between 6 seconds up to 3600 seconds.|
|SharedSecret|M|String|String|RW|A *random text* initialized to a random value on first boot. Must be >16 characters.|
|Length|M|Unsigned Integer|Integer|RW|Length of the TOTP. Must be >16 characters.|
|HashAlgorithm|O|OptionList|Array|RO/RW|The hash algorithm to use: *HMACSHA256*, *HMACSHA512*, ...
|Encoding|O|String|String|RO/RW|The alphabet used for encoding the TOTP, e.g. all charachters of *[a-zA-Z0-9]*|
|QRCodeQuality|O|OptionList|Array|RO/RW|The QR Code error correction level: *Low*, *Medium*, *Quartile*, *High*|


### OCPP v1.6

The OCPP 2.x Device Model is backported to the OCPP v1.6 Key-Value-Pair configuration settings. It uses the following *prefix* to distinguish between multiple *connectors*.

```
webPaymentsCtrlr.{ConnectorId}.{Setting}
```

 The *settings* are the same as for OCPP v2.x. The following would define the **URL Template** for the **first connector**:

```
webPaymentsCtrlr.1.URLTemplate = „https://qr-pay.example.org/v1/fe9jv39X9x2A9Bsv/{evseId}“
```





## Requests/Respones

### NotifyWebPaymentStarted

With the *NotifyWebPaymentStarted* request the QR code backend can inform the CSMS and by this the charging station about a just started *web payment process* at a given *EVSE identification* and block concurrent processes for a given timeout. The request can be sent multiple times, e.g. to update the timeout. A timeout value of `0` can be seen as a silent revocation of a previous request.


#### OCPI NotifyWebPaymentStarted

The QR Code backend sends an optional NotifyWebPaymentStarted command including the EVSE identification and a timeout to the **OCPI command module of the CSMS** in order to inform the CPO about a started web payment process. This command is similar to its OCPP counterpart with the only difference, that the *EVSE Identifcation* will use the ISO 15118 (eMI3) EV Roaming data format like e.g.: `DE*GEF*E12345678*1` as default. Optionally the command can also use the OCPI `location_id` and `evse_uid` for legacy use cases. The `rquest_url` is optional, as in most cases there will be no interesting response from the CSMS and/or charging station back to the QR code backend.

For improved compatibility with OCPP v2.x this OCPI request/response also allows a *CustomData* JSON object. This field should be forwarded as it is from the CSMS to the charging station and vice versa.

**OCPI NotifyWebPaymentStarted Command**

```
POST https://ocpi.example.com/cpo/2.3.0/commands/NOTIFY_WEB_PAYMENT_STARTED
```

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|response_url|O|URL|String|URL that the CommandResult POST should be sent to. This URL might contain a unique Id to be able to distinguish between NotifyWebPaymentStarted commands.
|evse_id|M|EVSE Id|String|EVSE Identification for which transaction is requested *(ISO 15118 format, e.g. DE\*GEF\*E12345678\*1)*.|
|location_id|O|Location Id|String|OCPI Location Identification for which transaction is requested.|
|evse_uid|O|EVSE UId|String|OCPI EVSE Unique Identification for which transaction is requested.|
|timeout|M|TimeSpan|Integer (seconds)|Timeout after which the web payment process is considered aborted or failed. Should be <= 5 minutes.|
|customData|O|-|Object|To be forwarded to the charging station.|

**OCPI NotifyWebPaymentStarted Command Result**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||



#### OCPP NotifyWebPaymentStarted

The CSMS sends an optional NotifyWebPaymentStarted request including the EVSE identification and a timeout to the charging station in order to inform the station about a started web payment process. Charging Station now prevents that a concurrent charging session is started locally on the given EVSE for the given timeout and displays some sort of feedback to EV Driver indicating, that his web payment process started successfully. It does so until the RequestStartTransaction request or a NotifyWebPaymentFailed from CSMS was received, or the timeout was reached.

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

For OCPP v1.6 the NotifyWebPaymentStartedRequest/-Response will be serialized as a `DataTransfer` message. When *customData* is available, then it will also be added to the `data` property! Please be cautious, that the `data` property within OCPP v1.6 DataTransfer messages is of **type** ***String***, not a structured JSON object!

*DataTransfer.req:*
```
{
    "vendorId":   "cloud.charging.open",
    "messageId":  "NotifyWebPaymentStarted",
    "data":       "{
                     \"connectorId\":  1,
                     \"timeout\":     60,
                     \"customData\":  null
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
|data.**connectorId** is missing, *null*, `0` or *invalid*.|The charging station SHALL return a status = DataTransferStatus.**Rejected** and data.**message** ~= `"Invalid 'connectorId' value!"`.|
|data.**timeout** is missing, *null*, not a *positive Integer > 0* or larger than 5 minutes.|The charging station SHALL return a status = DataTransferStatus.**Rejected** and data.**message** ~= `"Invalid 'timeout' value!"`.|

```
{
    "status":  "Rejected",
    "data":    "{
                  \"reasonCode\":    \"invalidTimeout\",
                  \"additionalInfo": \"Invalid 'timeout' value!\"
                }"
}
```


### NotifyWebPaymentFailed

With the *NotifyWebPaymentFailed* request the QR code backend can inform the CSMS and by this the charging station about a canceled or failed *web payment process*. The intention is to release the blocking of the EVSE done previously by a *NotifyWebPaymentStarted* request. While you could also just send a NotifyWebPaymentStarted with a timeout of `0` seconds, this optional request allows you to send an additional multi-language error message.

#### OCPI NotifyWebPaymentFailed

The QR Code backend sends an optional NotifyWebPaymentFailed command including the EVSE identification and an additional multi-language error message to the **OCPI command module of the CSMS** in order to inform the CPO about a canceled or failed web payment process. This command is similar to its OCPP counterpart with the only difference, that the *EVSE Identifcation* will use the ISO 15118 (eMI3) EV Roaming data format like e.g.: `DE*GEF*E12345678*1` as default. Optionally the command can also use the OCPI `location_id` and `evse_uid` for legacy use cases. The `rquest_url` is optional, as in most cases there will be no interesting response from the CSMS and/or charging station back to the QR code backend.

For improved compatibility with OCPP v2.x this OCPI request/response also allows a *CustomData* JSON object. This field should be forwarded as it is from the CSMS to the charging station and vice versa.

**OCPI NotifyWebPaymentFailed Command**

```
POST https://ocpi.example.com/cpo/2.3.0/commands/NOTIFY_WEB_PAYMENT_FAILED
```

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|response_url|O|URL|String|URL that the CommandResult POST should be sent to. This URL might contain a unique Id to be able to distinguish between NotifyWebPaymentStarted commands.
|evse_id|M|EVSE Id|String|EVSE Identification for which transaction is requested (ISO 15118 format).|
|location_id|O|Location Id|String|OCPI Location Identification for which transaction is requested.|
|evse_uid|O|EVSE UId|String|OCPI EVSE Unique Identification for which transaction is requested.|
|error_message|O|DisplayText[]|Array&lt;Object&gt;|An error message why the process was aborted or failed.|
|customData|O|-|Object||

**OCPI NotifyWebPaymentFailed Command Result**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||


#### OCPP NotifyWebPaymentFailed

The CSMS sends an optional NotifyWebPaymentFailed request including the EVSE identification and an additional multi-language error message to the charging station in order to inform the station about a canceled or failed web payment process. The intention is to release the blocking of the EVSE done previously by a *NotifyWebPaymentStarted* request. While you could also just send a NotifyWebPaymentStarted with a timeout of `0` seconds, this optional request allows you to send an additional multi-language error message.

**NotifyWebPaymentFailedRequest**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|evseId|M|EVSE Id|Integer, 0 ⇐ val|EVSE id for which transaction is requested.|
|errorMessage|M|I18NText|Array&lt;I18NString&gt;|An error message why the process was aborted or failed.|
|customData|O|-|Object||

**NotifyWebPaymentFailedResponse**

|Property Name|M/O|Type|JSON Type|Description|
|-|-|-|-|-|
|customData|O|-|Object||


##### OCPP vNext

OCPP vNext might have native support for NotifyWebPaymentStartedRequests and -responses and a simplified way to communicate multi-language text. Request errors are signaled via the normal *CALLERROR* response. Response errors can use the *CALLRESULTERROR* message.



*NotifyWebPaymentFailedRequest:*
```
{
    "evseId":        1,
    "errorMessage":  {
                         "en": "Payment network unreachable!"
                     },
    "customData":    null
}
```

*NotifyWebPaymentFailedResponse:*
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
|**errorMessage** is invalid.|The charging station SHALL return a *CALLERROR* with an **errorCode** indicating the exact problem.|

The **ErrorDetails** should contain an optinal JSON object consiting of *property*, *value* and a copy of the entire received *NotifyWebPaymentStartedRequest*.

*CALLERROR:*
```
[
     4,
    "162376037",
    "PropertyConstraintViolation",
    "Invalid language value 'xx'!",
    {
        "property":   "timeout",
        "value":      999999999,
        "request":    {
           "evseId":        1,
           "errorMessage":  {
                                "xx": "Payment network unreachable!"
                            },
           "customData":    null
        }
    }
]
```

##### OCPP v2.0.1 - v2.1

For OCPP v2.1 and OCPP v2.0.1 the NotifyWebPaymentFailedRequest/-Response will be serialized as a `DataTransfer` message. Multi-language text will be serialized as `Array<MessageContent>`:

*DataTransfer.req:*
```
{
    "vendorId":    "cloud.charging.open",
    "messageId":   "NotifyWebPaymentFailed",
    "data":        {
                     "evseId":        1,
                     "errorMessage":  [
                                          {
                                              "format":   "UTF8",
                                              "language": "en",
                                              "content":  "Payment network unreachable!"
                                          }
                                      ]
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
|data.**errorMessage** is invalid.|The charging station SHALL return a status = DataTransferStatus.**Rejected**, data.**reasonCode** = `"invalidMessageContent"` and an optional data.**additionalInfo** ~= `"Invalid format '{propertyKey}' for the message content!"`.|

```
{
    "status":      "Rejected",
    "statusInfo":  {
                      "reasonCode":     "invalidMessageContent",
                      "additionalInfo": "Invalid format 'UTFx' for the message content!"
                   }
}
```


##### OCPP v1.6

For OCPP v1.6 the NotifyWebPaymentFailedRequest/-Response will be serialized in the same way as in OCPP 2.0.1 - v2.1 as a `DataTransfer` message. Please be cautious, that the `data` property within OCPP v1.6 DataTransfer messages is of **type** ***String***, not a structured JSON object!

*DataTransfer.req:*
```
{
    "vendorId":   "cloud.charging.open",
    "messageId":  "NotifyWebPaymentStarted",
    "data":       "{
                     \"connectorId\":   1,
                     \"errorMessage\":  [
                                            {
                                                \"format\":   \"UTF8\",
                                                \"language\": \"en\",
                                                \"content\":  \"Payment network unreachable!\"
                                            }
                                        ]
                  }"
}
```

*DataTransfer.conf:*

```
{
    "status":  "Accepted"
}
```


## Diagnostic Tools

tba.


## Test Cases

tba.


## Implementations

- https://github.com/OpenChargingCloud/DynamicQRCodes/
- https://github.com/OpenChargingCloud/DynamicQRCodes.Android

