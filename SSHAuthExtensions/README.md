# SSH Authentication Extensions for OCPP

**Version 0.2, Draft**, 2026-11-26
[CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) · reference implementations: [Vanaheimr/Hermod](https://github.com/Vanaheimr/Hermod) (SSH stack, `totp@open.charging.cloud`), [OpenChargingCloud/WWCP_OCPP](https://github.com/OpenChargingCloud/WWCP_OCPP) (the node that dials)

This white paper describes how an OCPP node that dials its back end over **SSH** - a charging station, a local controller - proves who it is, beyond the public key every SSH implementation knows. It extends section 4 of [OCPP over SSH](../OCPP-over-SSH/README.md), is the counterpart of [HTTP Authentication Extensions for OCPP](../HTTPAuthExtensions/README.md) for connections whose URL begins with `ssh://`, and it defines one new SSH authentication method: **`totp@open.charging.cloud`**, a time-based one-time password bound to the SSH connection it is sent in, through the [SSH Keying Material Exporter](../SSHKeyExporter/README.md).

It answers three questions:

1. A back end that takes **passwords** over SSH exists, however little anybody likes it. How does a node sign in there, and what does it never do?
2. HTTP TOTP Auth replaced a password that travels by a shared secret that does not. How is the **same shared secret** used over SSH, with servers that know nothing of this paper?
3. A one-time password that is read on the way is still good until it runs out. How is it made good **in one session only**?

Public keys remain the method to prefer. Everything here is for the deployments that cannot, or not yet, give every node a key the back end knows.


## The four ways to sign in

| | Method on the wire | What travels | Good for whoever reads it | Needs on the server |
|---|---|---|---|---|
| Public key | `publickey` ([RFC 4252 §7](https://datatracker.ietf.org/doc/html/rfc4252#section-7)) | a signature over the session identifier | nothing | the node's public key |
| Password | `password` ([RFC 4252 §8](https://datatracker.ietf.org/doc/html/rfc4252#section-8)) | the password | as long as the password is not changed | the password, or its hash |
| One-time password, unbound | `keyboard-interactive` ([RFC 4256](https://datatracker.ietf.org/doc/html/rfc4256)) or `password` | a one-time password | until it runs out, typically 30 to 90 seconds | the shared secret |
| One-time password, bound | `totp@open.charging.cloud` (this paper) | a one-time password of this session | nothing | the shared secret, and this method |

A node is configured with **what it has** - keys, a login and password, a login and TOTP shared secret - and not with a method. Which method is used follows what the server lists as able to continue ([RFC 4252 §5.1](https://datatracker.ietf.org/doc/html/rfc4252#section-5.1)), in this order:

1. `publickey`, with every key the connection names, one after another
2. `totp@open.charging.cloud`
3. `keyboard-interactive`
4. `password`

What cannot be replayed goes before what can. A method the server does not list is never sent, so a password is never offered to a server that does not ask for one.


## Rules for everything that is not a key

- **The host key first.** Nothing of this paper is sent before the server proved itself with a host key the node believes: pinned, or learned on first use and confirmed. A node that believes a host key *in spite of* a mismatch - a setting for test benches - must not send a password or an unbound one-time password over that connection.
- **One login.** The login of the URL (`ssh://cs001@csms.example.org`) and the login of the credentials are the same one. A node refuses to dial where the two differ.
- **No key at all** is something a connection says explicitly. By default a node offers its key before anything else, also to a server that takes passwords alone: an unknown key is turned away and costs one attempt. A connection may be configured to offer none, where a server counts attempts too strictly or the operator does not want the key shown.
- **A secret is never logged**, neither by the node nor by the server, and never returned by a configuration API.


## Password

The `password` method as [RFC 4252 §8](https://datatracker.ietf.org/doc/html/rfc4252#section-8) defines it. The node does not change an expired password by itself: `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` ends the attempt.

Password authentication is **optional** on both sides and should be switched off on a server once its nodes have keys. Where it is on, the server must ration guesses per client address.


## One-time password, unbound

The node holds a login and a **shared secret**, exactly as for HTTP TOTP Auth, and works out a one-time password at the moment it is asked for one:

```
slot  = floor(unixtime / validity)                      // 8 bytes, big-endian
inner = HMAC(hash, key = shared_secret (UTF-8), slot)
totp  = length characters of the alphabet, read off inner
```

with `offset = inner[last] & 0x0F` and character `i` being `alphabet[ inner[(offset + i) mod |inner|] mod |alphabet| ]`. The defaults are a validity of 30 seconds, 12 characters, the alphabet `0-9a-zA-Z` and HMAC-SHA256. This is the token of [Time-Based One-Time Passwords (TOTP) for M2M Authentication](../TimeBasedOneTimePasswords/totp-token-format.md), which is the normative description of it, and so the token of HTTP TOTP Auth; a node and a back end that already share a secret for `wss://` can use the same one for `ssh://`.

It is carried in one of two standard methods, whichever the server lists:

**`keyboard-interactive`.** The server sends one prompt without echo; the node answers it with the one-time password. A node answers every prompt of a request with a freshly worked-out one-time password and does not interpret the prompt text. This is how the SSH world carries one-time codes, and what a server should prefer.

**`password`.** The one-time password is sent in the password field. This needs nothing of the server but a password check that knows this login takes a one-time password - which makes it the way with the fewest moving parts, and the one to choose for a server whose SSH implementation offers no hook for `keyboard-interactive`.

The server accepts the one-time password of the current time slot and of the slots before and after it, for clocks that do not agree to the second, and **accepts each one once**.

> This token is *not* the six digits of [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) that authenticator apps and `pam_google_authenticator` produce: it is longer, drawn from a larger alphabet, and uses HMAC-SHA256 and a different truncation. A server verifies it with an implementation of this paper or of HTTP TOTP Auth.

An unbound one-time password is read by whoever the SSH session ends at. A server that is not the one meant, having been believed by mistake, can sign in at the real server with it until it runs out. That is what the next section removes.


## One-time password, bound: `totp@open.charging.cloud`

### What it is bound to

Over TLS v1.3, the token format binds a one-time password with **exporter material** of the connection ([section 6](../TimeBasedOneTimePasswords/totp-token-format.md)): 32 bytes under the label `EXPORTER-Time-Based-One-Time-Password-v1` and an empty context. Over SSH, the [SSH Keying Material Exporter](../SSHKeyExporter/README.md) gives the same: 32 bytes under the same label, which only the two ends of this one connection can work out ([section 4](../SSHKeyExporter/README.md#4-the-ssh-exporter) of that paper). Its nonce is the **session identifier**, the exchange hash `H` of the first key exchange ([RFC 4253 §7.2](https://datatracker.ietf.org/doc/html/rfc4253#section-7.2)): both ends have it without sending anything, and two different connections never share it.

```
exporter_material = SSH-Exporter(nonce   = session_identifier,
                                 label   = "EXPORTER-Time-Based-One-Time-Password-v1",
                                 context = "" (empty),
                                 L       = 32)

slot  = floor(unixtime / validity)                      // 8 bytes, big-endian
inner = HMAC(hash, key = shared_secret (UTF-8), slot)
bound = HMAC(hash, key = exporter_material,     inner)
totp  = length characters of the alphabet, read off bound
```

The characters are read off `bound` exactly as an unbound token is read off `inner`. Everything after `exporter_material` is the token of the TLS v1.3 binding: an implementation has one function that binds a token, and the exporter of TLS or of SSH as the source of what it binds with. The test vectors of the token format therefore apply to SSH unchanged, with the exporter material as input.

- **Why the session identifier is the nonce.** User authentication has no place where one end could send a nonce to the other before the password is sent, least of all with `password`. The exporter allows a nonce that neither end sends where a protocol has none ([section 4.3](../SSHKeyExporter/README.md#43-the-nonce)), and the session identifier is one both ends already have. Its length is that of the hash of the key exchange, fixed and within the block size, as section 4.3 requires.
- **The same material for every attempt.** Every login attempt on one connection derives the same exporter material, as over TLS. That is what a binding needs, and the server accepts each one-time password once anyway.
- **There before user authentication.** The exporter exists from the first `SSH_MSG_NEWKEYS` on ([section 4.4](../SSHKeyExporter/README.md#44-lifetime)), so it is there when the one-time password is sent. A key re-exchange does not change it.

> Version 0.1 of this paper keyed the second HMAC with the session identifier itself. That bound the token as well, since the session identifier differs for every connection, but the session identifier is no secret: SSH agents are handed it and debug logs show it. The exporter material is a secret of the two ends, and the binding is now the same over TLS and SSH. A token of version 0.1 is not accepted by version 0.2.

### On the wire

```
byte      SSH_MSG_USERAUTH_REQUEST (50)
string    user name
string    service name ("ssh-connection")
string    "totp@open.charging.cloud"
string    one-time password (UTF-8)
```

The server answers with `SSH_MSG_USERAUTH_SUCCESS` or `SSH_MSG_USERAUTH_FAILURE`, as for every method. There are no method-specific messages, and nothing to change: the method has no "expired" state.

The method name follows [RFC 4251 §6](https://datatracker.ietf.org/doc/html/rfc4251#section-6): a name that is not registered with IANA carries the domain of whoever defined it.

### Verifying

The server works out the bound one-time password for the exporter material **of the connection the request arrived on**, for the current time slot and the slots before and after it, and compares in constant time. It needs no memory of tokens it has seen: a token is good in one session, and a session is authenticated once.

A server lists `totp@open.charging.cloud` among its methods only for logins it holds a shared secret for, or for all, as it lists `password`. It may require it after `publickey` as a second factor, with a partial success ([RFC 4252 §5.1](https://datatracker.ietf.org/doc/html/rfc4252#section-5.1)).

### What it gives, and what it does not

- A one-time password read on the way, or by a server that is not the one meant, **opens no other session**. Relaying it to the real server fails: that connection has other exporter material.
- The shared secret **never travels**, as with every TOTP.
- The **server is still authenticated by its host key**. The method does not prove to the node that the server knows the shared secret; a node must not treat a successful login as a reason to believe a host key.
- Both ends need this method, and an SSH implementation that gives it the exporter of the connection. No stock SSH server or client has either; a node falls back to the unbound ways only where its credentials allow that (below). A server can offer the method only on an SSH implementation of its own, which holds `K` and `H` anyway. OpenSSH would need both the exporter and a new method in `sshd-auth` and its monitor ([section 10.2](../SSHKeyExporter/README.md#102-openssh-why-the-subsystem-sees-neither-k-nor-h) of the exporter paper).

### Bound, or unbound

Whether a one-time password may travel unbound is a property of the **credentials**, as TLS channel binding is for HTTP TOTP Auth:

| Credentials | Server lists `totp@open.charging.cloud` | Server lists `keyboard-interactive` or `password` only |
|---|---|---|
| bound   | sent bound | **nothing is sent**; the login fails |
| unbound | sent bound | sent unbound |

Credentials that are bound are never sent less than they were told. Credentials that are unbound use the stronger method wherever the server offers it.

### Test vector

| | |
|---|---|
| shared secret | `a-shared-secret-of-enough-length` |
| time | `1700000000` (slot `56666666`, `00 00 00 00 03 60 aa 2a`) |
| validity, length, alphabet, hash | 30 s, 12, `0-9a-zA-Z`, HMAC-SHA256 |
| `inner` | `8f52075e3bb97d00c4671891689a815e2f3f54f6c1f7d8489c6c84698687a7f7` |
| unbound one-time password | `0aFolGu5wL1m` |
| exporter material | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `bound` | `ae0c05ece1be93e3273ee0bc8e18d91857310bc89c913c6a49deaf36637cbeb4` |
| bound one-time password | `D4nFD0C2iovo` |

From a connection on, with the connection of Appendix A.2 of the [SSH Keying Material Exporter](../SSHKeyExporter/README.md#a2-curve25519-sha256-hash--sha-256) (`curve25519-sha256`) and the same secret and time; [Appendix A.4](../SSHKeyExporter/README.md#a4-the-session_id-as-nonce) there spells out the export:

| | |
|---|---|
| `K` | `000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742` |
| session identifier | `202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f` |
| PRK (HKDF-Extract, salt = session identifier) | `f5946f03655cf4695f6ed02af80a71f01dd70ab666670396cf655786b0e410b0` |
| exporter material | `40f294c52877ab676e1c139752f7be2d2d3ed650e5f1eb7069cdc036e9492c04` |
| `bound` | `0fa69e4a5db2577a7433de2023de96cc2b5813eab02a589c63049d400abc9436` |
| bound one-time password | `pYSPAwzAqiHq` |


## Configuration

### Charging Station

A connection names the credentials it signs in with, and the keys it offers:

```json
{
  "url":              "ssh://cs001@csms.example.org:2222",
  "authenticationId": "csms-over-ssh",
  "identities":       [ { "id": "none" } ]
}
```

- `identities` are the SSH keys offered, in order; empty means the node's own key, and `[ { "id": "none" } ]` means no key at all - allowed only together with `authenticationId`.
- The credentials are a login with a password, or a login with a TOTP shared secret, validity, length, alphabet and hash algorithm - and, for a TOTP, whether it is **bound**.

### CSMS

For every login: whether a password, a one-time password or neither is taken beside its keys; for a one-time password its shared secret and parameters, and which of `totp@open.charging.cloud`, `keyboard-interactive` and `password` it is taken in.

#### OCPP vNext

...

#### OCPP v2.x

...

#### OCPP v1.6

...


## Diagnostics

A connection test - the node dials once, signs in, asks for a Heartbeat and lets go - should say which host key the server showed, which methods it listed, and which one let the node in, without ever printing a password, a one-time password or a secret.


## Test-Cases

### Server-Side (CSMS)

- CSMS-1: Methods listed
  - Test: Send a `none` request for a login with a shared secret.
  - Expect: `SSH_MSG_USERAUTH_FAILURE` listing `totp@open.charging.cloud`.
- CSMS-2: Bound one-time password of this session
  - Test: Send the bound one-time password of the connection's exporter material and the current time.
  - Expect: `SSH_MSG_USERAUTH_SUCCESS`.
- CSMS-3: Bound one-time password of another session
  - Test: Send the bound one-time password worked out with the exporter material of another connection.
  - Expect: `SSH_MSG_USERAUTH_FAILURE`.
- CSMS-4: Unbound one-time password in the bound method
  - Test: Send the unbound one-time password as `totp@open.charging.cloud`.
  - Expect: `SSH_MSG_USERAUTH_FAILURE`.
- CSMS-5: Unaligned clocks
  - Test: Send the one-time password of the previous and of the next time slot.
  - Expect: Both are accepted; the one of two slots away is not.
- CSMS-6: Replay of an unbound one-time password
  - Test: Sign in twice with the same unbound one-time password, on two connections.
  - Expect: The second is refused.
- CSMS-7: Another login
  - Test: Send a valid one-time password of one login under another login.
  - Expect: `SSH_MSG_USERAUTH_FAILURE`.
- CSMS-8: Guesses are rationed
  - Test: Send wrong passwords and one-time passwords until the attempt budget is spent.
  - Expect: The connection is closed; further attempts from the same address are delayed or refused.
- CSMS-9: Test vector
  - Test: Verify the test vectors of this paper.
- CSMS-10: Bound as in version 0.1
  - Test: Send the one-time password bound with the session identifier itself instead of the exporter material.
  - Expect: `SSH_MSG_USERAUTH_FAILURE`.

### Client-Side (Charging Station)

- CS-1: Order of methods
  - Test: The server lists `publickey`, `totp@open.charging.cloud`, `keyboard-interactive` and `password`, and turns the key away.
  - Expect: The node sends the bound one-time password next, and no password.
- CS-2: A method not listed is not sent
  - Test: The server lists `publickey` only.
  - Expect: Neither a password nor a one-time password is sent.
- CS-3: Bound credentials are not sent unbound
  - Test: Credentials are bound; the server lists `keyboard-interactive` and `password` only.
  - Expect: Nothing is sent in either; the login fails and is not tried again.
- CS-4: Unbound credentials, keyboard-interactive
  - Test: The server sends one prompt.
  - Expect: It is answered with the one-time password of the current time.
- CS-5: Unbound credentials, password
  - Test: The server lists `password` only.
  - Expect: The one-time password is sent in the password field; the shared secret never is.
- CS-6: No key
  - Test: The connection is configured to offer no key.
  - Expect: No `publickey` request is sent, not even an unsigned query.
- CS-7: Host key mismatch
  - Test: The server shows a host key the node does not believe; the node is configured to connect all the same.
  - Expect: The node does not dial where a password or an unbound one-time password would be sent.
- CS-8: Login of the URL and of the credentials differ
  - Expect: The connection is not dialled, and says why.
- CS-9: Test vector
  - Test: Generate the test vectors of this paper.
