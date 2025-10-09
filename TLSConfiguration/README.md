# TLS Client/Server Configuration for OCPP v2.x+

The current OCPP client configuration model for Charging Stations or Local Controllers connecting to the CSMS lacks the flexibility to specify detailed *Transport Layer Security (TLS)* parameters and options. For Local Controllers acting as *OCPP HTTP Web Socket* servers, OCPP does not define any mechanism to configure its TLS listener at all, making secure multi-hop communication effectively unsupported. This gap also extends to other OCPP-related network components such as *OCPP Gateways* deployed within a CPO infrastructure.

Beyond the core OCPP communication channel, several other use cases rely on additional protocols that must also support fine-grained TLS configuration:

- **Firmware Download Servers** and **Logfile Upload Servers** must be securely contacted over HTTPS, often requiring distinct certificate chains, hostname validation rules, and endpoint-specific TLS configurations.

- **Network Time Security (NTS)** will soon be a regulatory requirement (e.g. for metrological traceability under PTB guidelines), necessitating precise client-side TLS configuration for NTS over TLS/UDP.

- In **Smart Home** integration scenarios, TLS is also relevant during device onboarding, pairing, and authentication, particularly when e.g. the **EEBus** protocol is used.

Furthermore, many of these endpoints will require support for **high-availability**, **redundancy** and **failover**. This means that multiple endpoints (e.g., firmware servers in different availability zones) must be configurable, each potentially with unique certificates, trust anchors, and supported cipher policies. The current OCPP data model is insufficient to describe such topologies.


## 1. Requirements

The following requirement for the configuration of TLS clients and servers are based on:
- wget CLI
- curl CLI ✅
- libcurl ✅
- mbedtls ✅
- .NET9 ✅
- BouncyCastle.NET ✅
- nginx
- Apache HTTP 2


### 1.1 Multiple TLS Engines

Not every TLS feature or extension is universally supported across all libraries. To maximize interoperability and ensure both client and server can negotiate at least a secure, mutually acceptable baseline, it’s best to architect your system so that **multiple TLS engines** can be used interchangeably.


### 1.2 Supported TLS Versions

A client/server should be able to use one or more TLS version, e.g. `TLS v1.2` and `TLS v1.3`. To inhibit downgrade attacks it might also be beneficial when support of e.g. `TLS v1.2` can be deactivated. For better compatibility the configured list of TLS versions should be a priority list, even when some implementations will ignore the order of versions.

- The charging station firmware should provide a list of available versions.    
- The values should be implemented as predefined strings to simplify updates.
- MinVersion
- MaxVersion


### 1.3 Supported TLS Ciphers

A client/server should be able to use TLS ciphers depending on its risk profile and hardware constraints. For better compatibility the configured list of TLS ciphers should be a priority list, even when some implementations will ignore the order of ciphers.

The firmware should provide a list of available ciphers, but it is important to understand, that this list depends on the allowed **TLS versions**.    
The values should be implemented as predefined strings to simplify updates.

***Note:*** Should version and cipher be a JSON hierarchy?

- Should the OpenSSL syntax be supported? `curl --ciphers 'HIGH:!aNULL:!MD5'`
- Honor server cipher preference?


### 1.4 Supported Signature Algorithms

- Controls what your side advertises for certificate‐based authentication.


### 1.5 Supported Compression Methods

- Might be security relevant!


### 1.6 RootCAs

- RootCA groups like within the *Network Time Secure* paper


### 1.7 Mutual TLS with Self-Signed Certificates

Some smart home protocols like *EEBus* use TLS, but without a *Public Key Infrastrucrture (PKI)*. They use external methods to *"pair"* two devices and then *"pin"* the certificates. *Crypto Agility* is achieved by *"re-pairing"* both devices. For some use cases this might also be a valid option, e.g. for Charging Station to Local Controller communication.


### 1.8 Certificate *"Pinning"*

- Pinning of server certificates?
  - How to release a "pinned" server certificate?
- Pinning of intermediate certificates?
  - How to release a "pinned" intermediate certificate?
- Pinning of an entire certificate or just by the public key fingerprint (maybe less secure, as the key usage is unclear or just defined by a broader context)?


### 1.9 Notification on Certificate Changes

- Configurable warnings when certificates/public keys change?


### 1.10 TLS Client Crypto Key Settings

- Client private key file
- Client private key password/passphrase?
- Client certificate file/chain


### 1.11 TLS Certificate Checks

- Disable certificate revocation checks
- Disable certificate `notBefore` and `notAfter` checks, when the RTC is out-of-sync
- Use Certificate Revocation Lists (CRLs)


### 1.12 TLS Online Certificate Status Protocol
- Use OCSP
- Use OCSP Stapling
- OCSP Timeout
- OCSP Response Cache
- OCSP Error Behavior (continue, fatal, ...)
- OCSP DNS Resolvers
- TLS extension 5: `status_request`: Allows the server to include (staple) an OCSP response for certificate revocation checking during the handshake.


### 1.13 TLS Session Settings

- TLS Session Tickets (RFC 5077)
- TLS Session Cache Timeout
- TLS Session Resumption
- Use bundled DH parameters for DHE ciphers via PEM file
- TLS Renegotiation


### 1.14 TLS Application‑Layer Protocol Negotiation

The ALPN extension (RFC 7301) allows clients and servers to negotiate the application-layer protocol (like HTTP/1.1, HTTP/2, ...) during the initial TLS handshake.

- The list is a priority list explicitly prescribing a preference order.
- The handshake picks the first common element according to the server’s preference order.
- The values are registered with IANA and must be 1-255 octets long
- Disable ALPN


### 1.15 (Encrypted) Server Name Indication

TLS servers and clients should support Server Name Indication (SNI) and optional (Encrypten) Server Name Indication (ESNI).


### 1.16 Heartbeat Extension

The Heartbeat Extension gives you a protocol‑level ping over TLS itself. It is negotiated in the handshake, sent in its own record type, echoing back arbitrary payloads—so you can keep connections alive and verify peer liveness without renegotiation or external timers.

Same idea as OCPP heart beats or HTTP WebSocket Pings, but at TLS, not at OCPP request/response or HTTP WebSocket level. Similar as HTTP WebSocket Pings not end-to-end like OCPP heart beats.

This extension is not widely supported within TLS libraries.


### 1.17 Signed Certificate Timestamp Extension

TLS Extension 18: Provides Signed Certificate Timestamps (SCTs) for Certificate Transparency logging.


### 1.18 TLS Buffer Size

A client/server should be able to configure its internal buffer size for cryptographic operations. For embedded devices this can save RAM, for bigger machines this can improve network througput in combination with *Ethernet Jumpo Frames / Maximum Transfer Unit* and larger *TCP Maximum Seqment Size* settings.

Buffer sizes must align with TLS record limits to avoid overflows or errors like "record_overflow" alerts; misconfiguration can lead to vulnerabilities if buffers are too small for certain operations like renegotiation.

- Max plaintext record length (default 16 KB)
  - 16 KB
  - 8 KB
  - 4 KB
- Max encrypted input buffer?
- Max encrypted output buffer?
- Disable buffering, means that smaller packets are send to the application asap, not when the buffer is full or a maximum delay was reached.


### 1.19 MaxFragmentLength / RecordSizeLimit Extension

The `max_fragment_length` TLS v1.2 extension (extension type 1, RFC 6066 obsoleting RFC 3546) enables clients and servers to negotiate a smaller maximum plaintext fragment length for TLS records than the default of 2^14 bytes (16,384 bytes), which is particularly useful in constrained environments where devices have limited memory or bandwidth. Only sizes of 2^9(1), 2^10(2), 2^11(3), 2^12(4) are allowed.

The `record_size_limit` TLS v1.3 extension (extension type 28, RFC 8449) offers more flexibility: asymmetric limits (different send/receive sizes), values up to the protocol maximum (2^14+1 bytes), and no fixed enum—endpoints advertise a 16-bit integer for the max plaintext size they will receive.

If both extensions are present in a handshake, clients should abort with a fatal error to avoid conflicts.


### 1.20 Padding Extension

The `padding` TLS extension (extension type 21) adds padding to handshake messages to obscure message lengths and therefore helps to mitigate traffic analysis.


### 1.21 Connection Timeout

Waiting time until giving up or retry.


### 1.22 Retry Behavior

- Retry on all errors?
- Retry on connection refused or fail?
- Max Number of retries
- Retry delay (increasing?)
- Retry max_time?


### 1.23 Limit Transfer Speed

Limit the speed of a connection.


### 1.24 DNS Servers to use

Which DNS servers should be used for this connection. System defaults otherwise.

- DNS-over-HTTPS?


### 1.25 IPv4 vs. IPv6

- IPv4 only
- IPv6 only
- IPv6 prefered
- IPv4 prefered


### 1.26 TCP-KeepAlive, FastOpen, NoDelay

- KeepAlive Auto
- KeepAlive Enable it
- KeepAlive Disable it
- FastOpen Auto
- FastOpen Enable it
- FastOpen Disable it
- NoDelay Auto
- NoDelay Enable it
- NoDelay Disable it


### 1.27 Key types

- Support of other type beside PEM?
- DER, ENG


### 1.28 Follow HTTP Redirects

- **301 Moved Permanently** The resource has permanently moved to the URL given by the `Location` header. Clients should update their links to the new URL. *Do we really want to allow this?*
- **302 Found** The resource is temporarily under a different URL. Clients should continue to use the original request URL for future requests. *Do we really want to allow this? Might be good for H/A!*
- **303 See Other** Not really useful for our use cases.
- Max redirects to follow?
- Ignore all of them and fail... but how to support H/A then?
- Allow **302**, but limit to redirects under the same domain name: 


### 1.29 Concurrent TLS connections

- Disallowed
- Allowed, max n
- Send ConnectionId (proprietary vendor extension)


### 1.30 HTTP Server Name

- Allow to set the HTTP server name.


### 1.31 HTTP User Agent

- Allow to set the HTTP client (user agent) name.


### 1.32 Logging and Tracing

Enable logging of all messages:
- on TLS level
- on HTTP level
(- on HTTP WebSocket frame level)


### 1.33 PreShared Keys *(limited)*

Client and server share a symmetric key ahead of time. `TLS_PSK_*` and `TLS_ECDHE_PSK_*` suites (RFC 4279, RFC 8446).

*Warning: Limited library support!*


### 1.34 Raw Public Key *(limited)*

Instead of full X.509 certificates, you use bare public keys (e.g. an EC point) carried in a lightweight TLS extension (RFC 7250).

*Warning: Limited library support!*


### 1.35 TLS Secure Remote Password *(experimental)*

TLS Secure Remote Passwords (RFC 5054) lets client and server prove to one another that they share a secret (your password) without ever sending the password in the clear, and without relying on certificates. Instead of verifying a server’s X.509 cert, you perform an SRP handshake in which both sides compute a shared key derived from your password and ephemeral values.

*Warning: Weak library support!*


### 1.36 Delegated Credentials *(experimental)*

Delegated Credentials (or "token‑bound credentials” or just "DCs") are a mechanism to allow a TLS server to “delegate” short‑lived signing authority to a separate key, without touching its long‑term private key or issuing a new certificate. Delegated Credentials are standardized in RFC 9345 and are being rolled out in large‑scale deployments (e.g., CDNs) to improve key agility and limit the blast radius of key compromise..

Long‑lived certificates (e.g. 90 days or more) require frequent reissuance to rotate keys. Delegated Credentials let you rotate the signing key on a much shorter schedule (hours), without issuing a new CA‑signed certificate each time.

Delegated Credentials ensure that your certificate’s long‑term private key is never used on the edge or CDN at all—only short‑lived “delegated” keys are. If a delegated‐credential key is stolen, its maximum validity (e.g. 6 h) bounds the attacker’s window; your true certificate key remains safely offline.

With Delegated Credentials, leakage of an edge’s delegated key only affects that key’s brief lifetime; you simply stop serving it and issue a fresh DC without touching your origin certificate.

Note: *Perfect Forward Security* rotates session keys so that adversaries can’t retroactively decrypt old sessions. *Delegated Credentials* do not copy the long-term private key on e.g. edge servers, only delegates short-lived private keys do. So both solve two different threat models, and they’re complementary rather than interchangeable. 

*Warning: Weak library support!*


### 1.37 Subject Alternative Names within X.509 Certificates

- Multiple DNS Names, IP Addresses, ... per X.509 certificate
- RFC 5280
- RFC 6125
- Recommendations for the (old) Common Name?


### 1.38 DNS‑Based Authentication of Named Entities

DNS‑Based Authentication of Named Entities (DANE, RFC 7671) is a framework that lets domain owners assert which TLS certificates or public keys are valid for their services via DNS, secured by DNSSEC, rather than relying solely on external Certificate Authorities.

```
# Extract the SubjectPublicKeyInfo (SPKI) in DER form:
openssl x509 -in server.pem -noout -pubkey \
  | openssl pkey -pubin -outform der \
  > spki.der

# Compute the SHA‑256 digest of that DER blob, in hex:
openssl dgst -sha256 -binary spki.der | xxd -p -c 256
# → e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

DNS Record:
```
_443._tcp.www.example.com.  3600  IN  TLSA  3 1 1 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Breakdown of the fields (RFC 6698):

- Usage = 0 (PKIX‑TA), 1 (PKIX-EE), 2 (DANE-TA), 3 (DANE‑EE):
0: Ensure that CA’s cert matches the TLSA record.
1: Ensure the leaf cert matches the TLSA record.
2: Accept any chain as long as one CA in it matches the TLSA record. Validate the rest of the chain below that matched CA in the usual PKIX manner.
3: Simply check the leaf cert (or its SPKI) against the TLSA data. Ignore the PKIX chain.
- Selector = 0 (Full Certificate), 1 (SPKI):
We’re matching against the SubjectPublicKeyInfo portion of the certificate.
- Matching Type = 0 (exact), 1 (SHA‑256), 2 (SHA‑512):
The provided data is the SHA‑256 hash of the SPKI.
- Certificate Association Data:
The hex‑encoded 32‑byte hash computed above.
- TTL = 3600 s:
How long resolvers may cache this record.

*"PKIX"* stands for Public Key Infrastructure with X.509 certificates.


DANE‑aware TLS clients will now do:
1. Fetch `_port._transport.name` TLSA via DNSSEC.
2. Validate DNSSEC proofs (RRSIG).
3. During the TLS handshake, compares the server’s certificate or public key per the TLSA tuple (usage, selector, matching).
4. Enforces the pinning rules (e.g. reject if no matching TLSA).

Note: SRV+TLSA (RFC 7673): Use TLSA with SRV‑discovered services (e.g. XMPP, SIP).


### 1.39 DNS-Service Records

A DNS SRV (“service”) record lets you publish the location (hostname and port) of servers for a given service and protocol under your domain. It’s defined in RFC 2782 and has these fields:

```
_service._proto.name. TTL  CLASS  SRV  priority  weight  port  target

; _ocpp._tcp.example.com SRV records for OCPP pool
_ocpp._tcp.example.com. 3600 IN SRV 10 60 5060 ocpp1.example.com.
_ocpp._tcp.example.com. 3600 IN SRV 10 20 5060 ocpp2.example.com.
_ocpp._tcp.example.com. 3600 IN SRV 10 20 5060 ocpp3.example.com.
_ocpp._tcp.example.com. 3600 IN SRV 20  0 5060 ocpp-fallback.example.com.
```

| Field | Type | Description |
|-------|------|-------------|
|service|String|The symbolic name of the service, prefixed with an underscore. Examples: _sip, _ldap, _xmpp-server, _kerberos.|
|proto|String|The transport protocol, also prefixed with an underscore: usually _tcp or _udp.|
|name|String|The domain under which you’re publishing.|
|TTL|UInt32|Time‑to‑live in seconds for this record.|
|CLASS|String|Almost always IN for Internet.|
|SRV|String|The record type.|
|priority|UInt16|Lower values mean higher preference. A client MUST try all records of the lowest-numbered priority first.|
|weight|UInt16|Relative weight for records with the same priority. Clients use this for load balancing: If there are N records at the same priority, each has a chance proportional to its weight. A weight of 0 still participates (but only if all weights are 0, clients SHOULD pick randomly).|
|port|UInt16|TCP or UDP port on which the service is running on the target host.|
|target|String|The canonical hostname of the machine providing this service. MUST not be “.” for service records.|


1. Construct the query
Client looks up _service._proto.name (e.g. _ldap._tcp.dc.example.com).
2. Sort by priority
Group records by ascending priority. Start with the lowest.
3. Select by weight
Within that priority group, select one record via a weighted random algorithm:
3.1 Sum all weights W *(should be 100, to keep it simple)*.
3.2 Generate a random number R in [0, W).
3.3 Walk the records, subtracting each record’s weight from R; when R < 0, choose that record.
4. Attempt connection
Connect to the selected record’s target on its port.
If it fails, retry with the same priority group (re‑running the weighted selection among the remaining records).
Only when all records of that priority fail does the client move to the next‑higher priority.




## 2. Regulatory Cybersecurity Requirements

The following requirments are grounded in applicable cybersecurity regulations and in other predominantly *horizontal* cybersecurity standards.

### 2.1 CEN, CENELEC and ETSI Work Programme

The following requirements are based on horizontal requirements coming from EU CRA, EU RED, EN 18031, ...

- Related EN 18031 requirements:
  - Access control mechanism (ACM)
  - Authentication mechanism (AUM)
  - Secure update mechanism (SUM)
  - Secure communication mechanism (SCM)
  - Logging Mechanism (LGM)
  - Resilience mechanism (RLM)
  - Confidential cryptographic keys (CCK)
  - Cryptography (CRY)
- IEC 62443
- EN 18037:2023 Guidelines on a sectoral cybersecurity assessment


### 2.2 Minimal Attack Surface

- TLS clients and server must also work without external services like DNS, OCSP, DANE, ..., just with a secure configuration of IP addresses and crypto keys.
- Secure subset of TLS algorithms only
- Most TLS servers are disabled on default


### 2.3 Secure Defaults

- Secure subset of TLS algorithms only


### 2.4 Crypto Agilty

- All crypto keys and certificates must be replaceable.





-----------------

*ToDo's:*



...

- DTLS? *Out-of-Scope?*
