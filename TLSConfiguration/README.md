# Transport Layer Security Configuration

The current OCPP client configuration for Charging Stations or Local Controllers towards the CSMS dose not allow a detailed configuration of Transport Layer Security (TLS) parameters and options.

## 1. Supported TLS Versions

A client should be able to use one or more TLS version, e.g. `TLS v1.2` and `TLS v1.3`. To inhibit downgrade attacks it might also be beneficial when support of e.g. `TLS v1.2` can be deactivated. For better compatibility the configured list of TLS versions should be a priority list, even when some implementations will ignore the order of versions.

The charging station firmware should provide a list of available versions.    
The values should be implemented as predefined strings to simplify updates.


## 2. Supported TLS Ciphers

A client should be able to use TLS ciphers depending on its risk profile and hardware constraints. For better compatibility the configured list of TLS ciphers should be a priority list, even when some implementations will ignore the order of ciphers.

The charging station firmware should provide a list of available ciphers, but it is important to understand, that this list depends on the allowed **TLS versions**.    
The values should be implemented as predefined strings to simplify updates.

***Note:*** Should version and cipher be a JSON hierarchy?


## 3. TLS Buffer Size

A client should be able to configure its internal buffer size for cryptographic operations. For embedded devices this can save RAM, for bigger machines this can improve network througput in combination with *Ethernet Jumpo Frames / Maximum Transfer Unit* and larger *TCP Maximum Seqment Size* settings.

-----------------

*ToDo's:*
- TLS Session Tickets
- TLS Session Timeouts
- TLS Certificate Checks
