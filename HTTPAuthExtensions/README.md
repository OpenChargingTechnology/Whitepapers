White Paper

# HTTP Authentication Extensions for OCPP

This white paper offers a technical guide for supporting and configuring electric vehicle (EV) charging stations compliant with [Open Charge Point Protocol (OCPP)](https://openchargealliance.org/protocols/open-charge-point-protocol/) v1.6 (+ [Security Whitepaper Edition 3+](https://openchargealliance.org/whitepapers/)) and OCPP v2.x to enable **alternative HTTP Authentication Methods** for the **HTTP WebSocket Connection** between e.g. a charging station and a backend (CPMS/CSMS). This should solve multiple problems the EV charging infrastructure faces today:

1. Using **HTTP Basic Authentication** is no longer considered *state-of-the-art* when operating large-scale charging networks. Existing and upcoming Cybersecurity Regulations like the [EU Radio Equipment Directive (RED)](https://single-market-economy.ec.europa.eu/sectors/electrical-and-electronic-engineering-industries-eei/radio-equipment-directive-red_en), [EU Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) and [EU Network and Information Systems Directive 2 (NIS2)](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive) already demand higher security and privacy on different layers of the charging infrastructure. While passwords can easily be protected within the CSMS they are still required as cleartext on e.g. the charging station and will also be transmitted in cleartext over the transport channel. While Transport Layer Security (TLS) ensures basic security for the transmission, many attack vectors remain when TLS is used insecurely, e.g. in combination with too many RootCAs.

2. Even when TLS is used correctly, **passwords are often too weak and not changed regularly**, which opens up many attack vectors for internal and external adversaries. Operators also often dislike the idea of changing HTTP Basic Auth passwords regularly, as charging stations are remote devices and an error in the password change routine can take an entire charging station or even large parts of the entire charging network offline, leading to expensive service costs. OCPP currently does not offer very detailed approaches how to configure and test changed network settings and safe fallbacks.

3. **TLS Mutual Authentication** via **TLS Client Certificates** are on the other end of the cybersecurity spectrum and offer secure authentication without any shared secret beeing transmitted. The cryptographic material used for authentication can even be stored in specialized hardware and thus be protected even from software bugs on the charging station itself. **Yet, this additional security does not come for free.** Using certificates demands to operate a *Public Key Infrastructure* and understand the ongoing demand of changing certificates and private keys regularly, especially within the context of *crypto agility*. Also smaller embedded charging station microcontrollers often do not support mutual authentication *out-of-the-box* and thus a proprietary implementation might result in more risks than benefits.

## HTTP WWW Authentication Flow

### 1. Initial Client Request without *Auth Header*

The client (charging station, local controller, etc.) initiates a HTTP request to a resource requiring authentication but does not send any Authorization header.

```
GET /private/data HTTP/1.1
Host: example.com
```

This situation rarly exists within OCPP charging networks, as it is expected, that a charging station always supports at least *HTTP Basic Authentication* and sends the initial *HTTP WebSocket* request with a proper *Authorization*  header.

### 2. Initial Client Request with *Auth Header*

The client (charging station, local controller, etc.) initiates a HTTP request to a resource requiring authentication, includes an Authorization header, but the password is wrong or expired or the CSMS does no longer allow to use *HTTP Basic Authentication* for this charging station.

```
GET /private/data HTTP/1.1
Host: example.com
Authorization: Basic Y3MxOnRvdGFsLXMzY3VyMyE=
```


### 3. HTTP 401 Unauthorized Server Response

The server receives the request, detects missing or insufficient credentials, and must respond with *HTTP Status Code* ***401 Unauthorized***.
The current OCPP specification does not demand any more details about why the request failed, nor what to do now. Nevertheless the IETF has standardized error responses in [RFC 9110 Section 11](https://datatracker.ietf.org/doc/html/rfc9110#section-11), that will inform the client which alternative authentication options are available. For this the server includes a *WWW-Authenticate* header to inform the client which authentication scheme(s) are supported and which parameters (realm, etc) are required.

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic  realm="example"
WWW-Authenticate: Bearer realm="example", error="invalid_token"
WWW-Authenticate: Digest realm="example", nonce="abc123", qop="auth", algorithm=SHA-256
```

## Configuration

### CSMS Configuration

A charging station operator should support to **include *WWW-Authenticate* headers into *401 Unauthorized* responses** whenever a successful authentication based on this information seems possible. The only reason not to include this additional information might be reasons other than the correct usage of *HTTP Authentication methods*, e.g. *application level IP filter rules* when a request was send from an unknown IP address or subnet.

A charging station operator should **support the configuration of *HTTP Authentication Methods* per charging station or charging station groups**, so that only the methods supported by at least the charging station model/firmware and allowed by the operator cybersecurity policy are returned. Other criteria like e.g. the current firmware version or the current IP subnet of the client could also influence the list of allowed methods.

In order to prevent ***Downgrade Attacks*** the charging station operator **must enforce** the correct use of *HTTP Authentication Methods*. Is *HTTP Basic Auth* is not within the *WWW-Authenticate* method list the CSMS must always return *401 Unauthorized*, even when the request was sent using a valid password for this charging station.

*ToDo: What about the realm?* 

*ToDo:* The CSMS must maintain a list of supported HTTP Auth methods for a charging station. This list might be inherited from the charging station model and the installed firmware.

*ToDo:* The CSMS must maintain a list of allowed HTTP Auth methods for a charging station. This list might be inherited from charging station groups and further security policies.




### Charging Station Configuration

The charging station should support multiple *HTTP Authentication Methods*. For this it must store a list of available methods ordered by their priority. For backards compatibility the **default value** of this list is just ***Basic Auth***.

When an authentication fails the charging station should compare its list with the list of methods provided by the CSMS and **select a shared method having the highest priority**.

When a method fails multiple times (default: 3 times) the charging station should switch to the 2nd best method... then to the 3rd best...

Once an authentication succeded the charging station should store the method as ***negotiated method*** for this network configuration. This variable must be read-only for normal OCPP configuration operations by operators. A renegotiation is triggered by the next *HTTP 401 Unauthorized* response received.

When there are no shared methods the current authentication process fails finally and the charging station must log this as a reason why no further authentication was tried. As this kind of authentication failures can also be caused by rare software problems at the CSMS, the charging station may retry the authentication process after a longer waiting period. The intended time span of 1-2 hours (+-30 minutes) might be larger than the normal retry periods caused by random network errors (minutes).


*ToDo:* A charging station must maintain a read-only list of available HTTP Auth methods.

*ToDo:* A charging station must maintain an list of configured HTTP Auth methods ordered by their priority.

#### OCPP vNext

...

#### OCPP v2.x

...

#### OCPP v1.6

...


### HTTP Basic Auth

HTTP Basic Auth as defined in [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617) is **mandatory** for all versions of OCPP. It defines a simple authentication mechanism using a username and a password.

```
Authorization: Basic {base64(username:password)}
```

Within OCPP the username is normally defined as *charging station name*. This white paper relaxes this strict definition and also allows to use different usernames/logins to avoid information leakage and to improve the privacy of the EV infrastructure. The CSMS can easily adopt this by adding a mapping table from (multiple) logins to real charging station names. Supporting multiple logins per charging station is also a simple work-around to apply different run-time configuration settings to the WebSocket connection or to the further OCPP protocol processing.

The main **cybersecurity risk** of *Basic Auth* are that the login and password will be send in cleartext over the communication channel. Therefore the use of an **authenticated and encrypted underlying transport channel is mandatory**. Nevertheless passwords might easily end up in logfiles or when TLS is secured poorly end up in 3rd party systems. When OCPP Local Controllers are used passwords can easily be collected at this *single-point-of-abuse*. The username offers additional privacy risks. The charging station manufacturer also has to provide evidence, that the password is at least not stored in cleartext on the device.

Some of those risks can be solved operationally by changing passwords regularly. Nevertheless the reality shows us, that charging station operators rarely change passwords, as the passwords changes always offer the risk of mistakes and erros leading to offline charging stations and high service costs.

Charging Station Operators are strongly encuraged to use password hashing techniques when storing HTTP Basic Auth passwords within databases and provide masqing techniques so that passwords do not end up in logfiles or data analytic platforms, where they can be found and stolen by attackers.

#### OCPP vNext

...

#### OCPP v2.x

...

#### OCPP v1.6

...


### HTTP Token Auth

HTTP Token Auth is not defined by RFCs, but quite popular in IT. Therefore this method is **optional**. It defines a simple authentication mechanism using an application defined opaque token.

```
Authorization: Token aabbccdd...
```

HTTP Token Authentication can be seen as simplified version of Basic Auth. A token can easily be mapped to a charging station within the CSMS. Also multiple token can exist for the same charging station. Tokens should use at least 20 characters and at least 128 characters should be supported by all clients and servers.

There are **no security benefits over HTTP Basic Auth**, but some privacy benefits exists, as Token Auth does not have a seperate *username* field.

#### OCPP vNext

...

#### OCPP v2.x

...

#### OCPP v1.6

...


### HTTP Digest Auth

HTTP Digest Auth as defined in [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616) is **optional** for all versions of OCPP. It defines a challenge-response authentication mechanism to avoid sending a clear-text password over the wire.

```
Authorization: Digest username="user",
                      realm="example.com",
                      nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                      uri="/resource",
                      response="6629fae49393a05397450978507c4ef1",
                      algorithm=SHA-256
```

The authentication flow is different to HTTP Basic Auth, as first the charging station must send a request without any authentication in order to get a response including a *challenge* parameter and a *nonce* which will be used in a second authentication request. This means, that this method is **not a simple replacement** for HTTP Basic Auth.

The Digest Authentication method also offers additional configuration parameters which have to be taken into account. The `algorithm` parameter allows the CSMS to define the HMAC hashing algorithm that should be used. For OCPP `SHA-256` must be used as default algorithm. When client and server both are 64 bit systems `SHA-512-256` should be considered, as it is faster and more secure on those systems. As `SHA-384` and `SHA-512` are very common in e-mobility CSMSs should support them, while they stay optional for charging stations. Algorithmic variants like `SHA-256-sess` are more secure, but as they introduce additional complexity and todays library support is weak, they are optional. `MD5`, `SHA-1` and any variant are not allowed for OCPP.

#### OCPP vNext

...

#### OCPP v2.x

...

#### OCPP v1.6

...


### HTTP TOTP Auth

HTTP TOTP Auth uses **Time-Based One-Time-Passwords** to generate tokens for authentication what will change e.g. every couple of seconds. This technique is already used for *Web Payments* in OCPP v2.1. This method combines the simplicity of HTTP Basic Auth with an improved security close the HTTP Digest Auth. Support of HTTP TOTP Auth is **optional**.

```
Authorization: TOTP {login} {totp(timestamp, shared_secret, ...)}
```

#### OCPP vNext

...

#### OCPP v2.x

...

#### OCPP v1.6

...




## Diagnostics

The charging station should provide an ***optional*** diagnostics tool that allows to simulate a HTTP WebSocket connection establishment using different HTTP Authentication methods.

**Input**: All required HTTP parameters shall be configurable via tool parameters including the URL, login (default: charging station name), password, shared keys, ...

**Output**: The tool shall record all HTTP headers and bodies and return then with additional sent and received timestamps.

***Side-Effects***: The tool should operate without causing side-effects on the charging station and CSMS. This means the tools work independently from the normal charging station HTTP WebSocket connection logic. To avoid conflicts on the CSMS side, the tool must require an additional "--force" parameter when it detects, that the exact same URL, login, password and user-agent as the current WebSocket connection shall be used. The tool shall provide a configuration parameter to set the *HTTP User-Agent* to help the CSMS to distinguish a real connection from diagnostic connections and to avoid closing the main WebSocket connection by mistake.


## Test-Cases

### Server-Side (CSMS)

- CSMS-1: 401 Response Without Authorization
  - Test: Request a protected resource without any Authorization header.
  - Expect: 401 Unauthorized with maybe multiple methods
- CSMS-2: 401 Response With Only Basic Credentials
  - Test: Send a request with an invalid or malformed Basic Auth header.
  - Expect: 401 Unauthorized with both WWW-Authenticate headers.
- CSMS-3: 401 Response With Only Token Credentials
  - Test: Send a request with an invalid or malformed Token Auth header.
  - Expect: 401 Unauthorized with both WWW-Authenticate headers.
- CSMS-4: 401 Response With Both Auth Headers Present (Mixed)
  - Test: Send a request with both an invalid Basic and invalid Token header.
  - Expect: 401 Unauthorized with both WWW-Authenticate headers.
- CSMS-5: Missing Scheme
   - Test: Send an Authorization header with an unsupported scheme (e.g., Foo ...).
   - Expect: 401 Unauthorized with both WWW-Authenticate headers.
- CSMS-6: Realm Consistency
  - Test: Realms in WWW-Authenticate are correct, descriptive, and consistent.
- CSMS-8: Case-Insensitive Methods
  - Test: Send back list of methods having random casing, e.g. "BASic"
  - Expect: Client parses the method case-insensitive
- CSMS-7: Case-Insensitive Methods RFC vs. Reality
  - Test: Check whether random variants of a method are still accepted by the server, e.g. "BASIC" or "basic". RFC defines it as case-insensitive, but many implementations are case-sensitive.
- CSMS-8: Extra Whitespaces
  - Test: Authorization header with extra spaces at the start, in the middle and at the end of a header line.
  - Expect: Server should trim and still correctly parse.
- CSMS-9: Incorrect Base64 encoding
  - Test: Send Basic Auth with invalid Base64 encoding
- CSMS-10: Extra header data
  - Test: Send `Authorization: Basic Y3MxOnRvdGFsLXMzY3VyMyE= randomdata`
  - Expect: HTTP 400 Bad Request
- CSMS-11: Login too short
  - Test: Send a 1 character login
  - Expect: HTTP 400 Bad Request
- CSMS-11: Password too short
  - Test: Send a 1 character password
  - Expect: HTTP 400 Bad Request
- CSMS-12: Long Headers / Buffer Overflow
  - Test: Oversized or malformed Authorization headers.
  - Expect: HTTP 400 Bad Request


### Client-Side (Charging Station)

- CS-1: Select Basic If Both Offered
  - Test: On 401 with both WWW-Authenticate: Basic ... and Token ..., verify the client can select Basic, add correct header
  - Expect: 200 OK if credentials are valid.
- CS-2: Select Token If Both Offered
  - Test: On 401 with both WWW-Authenticate: Basic ... and Token ..., verify the client can select Token, add correct header
  - Expect: 200 OK if credentials are valid.
- CS-3: Fallback Behavior
  - Test: If the first attempt fails with one scheme...
  - Expect: The client retries with the alternative scheme.
- CS-4: Case-Insensitive Methods RFC vs. Reality
  - Test: Check whether the client uses the normative spelling of the methods, e.g. "Basic", not "BASIC". RFC defines it as case-insensitive, but many implementations are case-sensitive.
- CS-5: Extra Whitespaces
  - Test: Authorization header with extra spaces.
  - Expect: Client should still correctly parse.
- CS-6: Switching methods
  - Test: Client authenticates with Basic Auth. Reauthentication fails. Basic Auth is no longer supported.
  - Expect: Client switches to Token Auth.
- CS-7: TOTP Auth unaligned clocks (previous TOTP)
  - Test: The client sends a TOTP of the privious time span
  - Expect: The server accepts the authentication
- CS-8: TOTP Auth unaligned clocks (next TOTP)
  - Test: The client sends a TOTP of the next time span
  - Expect: The server accepts the authentication

