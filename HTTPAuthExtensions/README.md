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
WWW-Authenticate: Digest realm="example", nonce="abc123"
```
