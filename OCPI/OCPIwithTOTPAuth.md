# Time-Based One-Time Passwords as 2nd Factor Authentication

In the current OCPI v2.x protocol, communication between OCPI nodes relies on the `Authorization: Token <value>` HTTP header for authentication. This static token is initially exchanged during the `CREDENTIALS` registration process and can later be updated using the same module. However, in practice, this token functions as a long-lived shared secret even when transmitted over a TLS-secured channel.

When **public Root CAs** are used for TLS, the risk of token leakage increases significantly due to potential certificate impersonation, compromised CA trust chains, or improper certificate validation within implementations. Once a static token is exposed, it provides full OCPI access until detected and changed manually.

To mitigate this security weakness, an additional ***Time-Based One-Time Password (TOTP) mechanism*** shall be used as a second factor for OCPI authentication. This approach maintains *backward compatibility* with all existing OCPI v2.x deployments while adding a dynamic verification layer resistant to replay and credential theft, as no longer just a static token is send over *"the wire"*.


## Prerequisites

Implementing TOTP-based two-factor authentication requires rough time synchronization between both communicating OCPI nodes. As TOTP validity depends on short-lived time slots (typically 30 s), even minor clock drift can lead to authentication failures.

To ensure reliable operation:

1. **Network Time Synchronization**
Each OCPI endpoint must maintain its system clock via a trusted and authenticated time source, ideally using **Network Time Secure** (RFC 8915).

2. **Tolerance Policy**
The receiving system should accept TOTP values from the current time slot and its immediate predecessor/successor (± 1 slot), to compensate for minimal drift or network latency.

3. **Clock Drift Monitoring**
Implementations should continuously monitor time offset between peers and issue warnings if drift exceeds 10 seconds *(ToDo)*.

4. **Shared Secret Management**
The TOTP shared secret is a critical element for both generating and validating one-time passwords. While TOTP itself prevents credential reuse or replay, the shared secret remains a long-term static secret that must be stored and protected with the same rigor as the OCPI token itself.

5. **System Log Integrity**
Time synchronization must be part of the system’s overall security audit trail.


## Design Concept

- **Primary Factor**: Existing `Authorization: Token <static token>` mechanism.
- **Second Factor**: A synchronized TOTP value derived from a shared secret negotiated during the initial credential exchange.
- **Transmission**: The TOTP value is included in every HTTP request via a dedicated custom header: `TOTP: <TOTP value>`
- **Time Window**: e.g. 30 seconds per slot, with ±1 slot tolerance to handle minor clock skews.
- **Derivation**: TOTP is generated according to OCPP v2.1 WebPayments.
- **Validation**: The receiver must validate both the static OCPI token and the TOTP value. Requests failing either check are rejected with HTTP 401 Unauthorized.


## Compatibility and Migration

- Existing OCPI nodes not supporting TOTP simply ignore the TOTP header and just rely on the known OCPI token.
- A capability flag (e.g. supports_totp_authentication = true) may be announced in the CREDENTIALS response to signal TOTP support *(ToDo)*.
- The TOTP shared secret can be provisioned once via a secure out-of-band channel or integrated as an additional property within the CREDENTIALS exchange *(ToDo)*.


## Security Benefits

- Eliminates pure reliance on static plaintext credentials sent over the wire.
- Prevents replay attacks outside the time window, even when TLS or OCPI logs are compromised.
- Enables incremental rollout without protocol breaking changes.
- Strengthens authentication between OCPI peers without introducing complex *Public Key Infrastructure (PKI)* dependencies.
- Automatic changes of the TOTP improves security, while regular (manual) changes of the OCPI token (still) improves privacy.


## Security Operations

- The initial transfer of the ***OCPI Token*** and the ***TOTP Shared Secret*** must use secure out-of-band provisioning mechanisms.
- Both the token and the shared secret must be stored encrypted using a symmetric encryption key or protected inside a Hardware Security Module (HSM), TPM, or secure enclave.
- The stored token and the shared secret must be protected from unauthorized modification (e.g., via HMAC or integrity-checks).
- Only the process responsible for generating or validating OCPI requests shall have read access.
- User access to the tokens and the shared secrets must be restricted via strict ***Role-Based Access Control (RBAC)***.
- Tokens and secrets must never be exposed in unauthenticated application logs or configuration dumps.
- ***Periodic automatic regeneration*** of tokens and the shared secrets should be supported by the software implementation, e.g. through a CREDENTIALS update or other *out-of-band* mechanisms.
