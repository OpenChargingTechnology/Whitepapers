# TLS Client/Server Configuration for OCPP v2.x+

The current OCPP client configuration model for Charging Stations or Local Controllers connecting to the CSMS lacks the flexibility to specify detailed *Transport Layer Security (TLS)* parameters and options. For Local Controllers acting as *OCPP HTTP Web Socket* servers, OCPP does not define any mechanism to configure its TLS listener at all, making secure multi-hop communication effectively unsupported. This gap also extends to other OCPP-related network components such as *OCPP Gateways* deployed within a CPO infrastructure.

Beyond the core OCPP communication channel, several other use cases rely on additional protocols that must also support fine-grained TLS configuration:

- **Firmware Download Servers** and **Logfile Upload Servers** must be securely contacted over HTTPS, often requiring distinct certificate chains, hostname validation rules, and endpoint-specific TLS configurations.

- **Network Time Security (NTS)** will soon be a regulatory requirement (e.g. for metrological traceability under PTB guidelines), necessitating precise client-side TLS configuration for NTS over TLS/UDP.

- In **Smart Home** integration scenarios, TLS is also relevant during device onboarding, pairing, and authentication, particularly when e.g. the **EEBus** protocol is used.

Furthermore, many of these endpoints will require support for **high-availability**, **redundancy** and **failover**. This means that multiple endpoints (e.g., firmware servers in different availability zones) must be configurable, each potentially with unique certificates, trust anchors, and supported cipher policies. The current OCPP data model is insufficient to describe such topologies.


## 1. Requirements

### 1.1. Supported TLS Versions

A client/server should be able to use one or more TLS version, e.g. `TLS v1.2` and `TLS v1.3`. To inhibit downgrade attacks it might also be beneficial when support of e.g. `TLS v1.2` can be deactivated. For better compatibility the configured list of TLS versions should be a priority list, even when some implementations will ignore the order of versions.

1.1. The charging station firmware should provide a list of available versions.    
1.2. The values should be implemented as predefined strings to simplify updates.


### 1.2. Supported TLS Ciphers

A client/server should be able to use TLS ciphers depending on its risk profile and hardware constraints. For better compatibility the configured list of TLS ciphers should be a priority list, even when some implementations will ignore the order of ciphers.

The firmware should provide a list of available ciphers, but it is important to understand, that this list depends on the allowed **TLS versions**.    
The values should be implemented as predefined strings to simplify updates.

***Note:*** Should version and cipher be a JSON hierarchy?


### 1.3. RootCAs

- RootCA groups like within the *Network Time Secure* paper



### 1.4. Mutual TLS with Self-Signed Certificates

Some smart home protocols like *EEBus* use TLS, but without a *Public Key Infrastrucrture (PKI)*. They use external methods to *"pair"* two devices and then *"pin"* the certificates. *Crypto Agility* is achieved by *"re-pairing"* both devices. For some use cases this might also be a valid option, e.g. for Charging Station to Local Controller communication.


### 1.5. Certificate *"Pinning"*

- Pinning of server certificates?
  - How to release a "pinned" server certificate?
- Pinning of intermediate certificates?
  - How to release a "pinned" intermediate certificate?


### 1.6. Notification on Certificate Changes

- Configurable warnings when certificates/public keys change?



### 1.X. TLS Buffer Size

A client/server should be able to configure its internal buffer size for cryptographic operations. For embedded devices this can save RAM, for bigger machines this can improve network througput in combination with *Ethernet Jumpo Frames / Maximum Transfer Unit* and larger *TCP Maximum Seqment Size* settings.


-----------------

*ToDo's:*
- TLS Session Tickets
- TLS Session Timeouts
- TLS Certificate Checks

- Look at wget CLI
- Look at curl CLI
- Look at libcurl
- Look at mbedtls


