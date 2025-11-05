# HTTP Basic Authentication with Time-Based One-Time Passwords

In the current OCPP protocol, communication between charging stations, local controllers and backends relies on the `Authorization: Basic <login:password>` HTTP header for authentication. This static parameters are initially configured during commissioning process and can later be updated using OCPP requests or Device Model updates. However, in practice, this authentication functions as a long-lived shared secret even when transmitted over a TLS-secured channel.

When **public Root CAs** are used for TLS, the risk of token leakage increases significantly due to potential certificate impersonation, compromised CA trust chains, or improper certificate validation within implementations. Once a static token is exposed, it provides full OCPP access until detected and changed manually.

To mitigate this security weakness, the password shall be replaced by a ***Time-Based One-Time Password (TOTP)***. This approach reduces *backward incompatibilities* with existing OCPP implementations while adding a dynamic verification layer resistant to replay and credential theft, as no static password is longer send over *"the wire"*.


## Prerequisites

Implementing TOTP-based two-factor authentication requires rough time synchronization between both communicating OCPP nodes. As TOTP validity depends on short-lived time slots (typically 30 s), even minor clock drift can lead to authentication failures.

To ensure reliable operation:

1. **Network Time Synchronization**
Each OCPP node must maintain its system clock via a trusted and authenticated time source, ideally using **Network Time Secure** (RFC 8915).

2. **Tolerance Policy**
The receiving system should accept TOTP values from the current time slot and its immediate predecessor/successor (± 1 slot), to compensate for minimal drift or network latency.

3. **Clock Drift Monitoring**
Implementations should continuously monitor time offset between peers and issue warnings if drift exceeds 10 seconds *(ToDo)*.

4. **Shared Secret Management**
The TOTP shared secret is a critical element for both generating and validating one-time passwords. While TOTP itself prevents credential reuse or replay, the shared secret remains a long-term static secret that must be stored and protected with the same rigor as a static OCPP password.

5. **System Log Integrity**
Time synchronization must be part of the system’s overall security audit trail.


## Design Concept

- **Transmission**: Reuse the traditional HTTP Basic Authorization mechanism, but exchange the password with a synchronized TOTP value derived from a shared secret: `Authorization: Basic <login:TOTP>`
- **Time Window**: e.g. 30 seconds per slot, with ±1 slot tolerance to handle minor clock skews.
- **Derivation**: TOTP is generated according to OCPP v2.1 WebPayments.
- **Validation**: The receiver must validate both the static login and the TOTP value. Requests failing either check are rejected with HTTP 401 Unauthorized.


## Compatibility and Migration

- *ToDo*


## Security Benefits

- Eliminates pure reliance on static plaintext credentials sent over the wire.
- Prevents replay attacks outside the time window, even when TLS or OCPP logs are compromised.
- Enables incremental rollout with minimal protocol changes.
- Strengthens authentication between OCPP peers without introducing complex *Public Key Infrastructure (PKI)* dependencies.
- Automatic changes of the TOTP improves security, while regular (manual) changes of the HTTP Basic Authentication Login improves privacy.

## Security Operations

- The initial transfer of the ***TOTP Shared Secret*** must use secure out-of-band provisioning mechanisms.
- The shared secret must be stored encrypted using a symmetric encryption key or protected inside a Hardware Security Module (HSM), TPM, or secure enclave.
- The shared secret must be protected from unauthorized modification (e.g., via HMAC or integrity-checks).
- Only the process responsible for generating or validating OCPI requests shall have read access.
- User access to the tokens and the shared secrets must be restricted via strict ***Role-Based Access Control (RBAC)***.
- Shared secrets must never be exposed in unauthenticated application logs or configuration dumps.
- ***Periodic automatic regeneration*** of the shared secrets should be supported by the software implementation, e.g. through the OCPP Device Model or other *out-of-band* mechanisms.
