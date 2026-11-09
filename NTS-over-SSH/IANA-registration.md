# IANA registration of the NTS-KE record type "SSH Key Binding"

**Status: draft, not yet submitted.**

This document holds the registration request for the NTS-KE record type *SSH Key Binding* in
the IANA registry
["Network Time Security Key Establishment Record Types"](https://www.iana.org/assignments/nts/nts.xhtml#nts-key-establishment-record-types),
as it is to be sent, and what is to be done once IANA has assigned a value. It is kept after
the assignment, as [the one of MetrologicalCBOR](../MetrologicalCBOR/IANA-registration.md)
is: the request is what the entry means.

The record is specified in [nts-ke-ssh-key-binding.md](nts-ke-ssh-key-binding.md), the
specification of section 5 of the white paper [NTS Key Establishment over SSH](README.md).
Until the assignment it uses the provisional value 16386 (`0x4002`) from the private range.


## Why this is possible without an RFC

The registry defines three registration policies ([RFC 8915], Section 7.6):

| Record types | Policy |
|---|---|
| 0..1023 | IETF Review |
| 1024..16383 | **Specification Required** |
| 16384..32767 | Private or Experimental Use |

*Specification Required* ([RFC 8126], Section 4.6) needs a specification that is permanent
and readily available to the public, detailed enough for independent implementations to
interoperate, and the approval of the designated experts. It needs no RFC and no working
group. The experts of this registry are Miroslav Lichvar and Daniel Franke.

**Precedent:** record type 1024, *Compliant AES-128-GCM-SIV Exporter Context*, registered
2024-09-25, whose reference is a specification on the web site of chrony
(<https://chrony-project.org/doc/spec/nts-compliant-128gcm.html>).

**Availability check (2026-11-10):** 1025..16383 are unassigned. 0..14 and 1024 are
assigned, 8..14 of them temporarily for draft-ietf-ntp-nts-keyexchange-pool, until
2027-06-02. With Specification Required, IANA assigns the value; the request only suggests
one.


## The request

Submit exactly this template:

```
Registry:            Network Time Security Key Establishment Record Types
                     https://www.iana.org/assignments/nts/nts.xhtml#nts-key-establishment-record-types

Record Type Number:  TBD, from the range 1024-16383 (Specification Required);
                     the next unassigned value, currently 1025, is suggested

Description:         SSH Key Binding

Reference:           https://github.com/OpenChargingTechnology/Whitepapers/blob/master/NTS-over-SSH/nts-ke-ssh-key-binding.md

Point of contact:    Achim Friedland <achim.friedland@graphdefined.com>
```

The fields are those of RFC 8915, Section 7.6: Record Type Number, Description and Reference.

And, for the designated experts, in the free text of the request:

```
The record lets NTS-KE (RFC 8915) run in an SSH subsystem instead of over
TLS, for private networks without a PKI, such as the charging infrastructure
of electric vehicles: the server is authenticated by its SSH host key, the
client by its SSH user key. An SSH connection has no TLS exporter, so this
record negotiates where the keys of the NTP association come from instead:
from an exporter of the SSH connection with a nonce for every exchange, or
from a 32-octet secret that the server sends inside the encrypted SSH
channel (mandatory to implement). All other records, the cookies and NTP
itself are unchanged; an NTP server cannot tell over which transport the keys
inside a cookie were agreed.

The record is critical. It is sent only over SSH; over TLS, a server
according to RFC 8915 refuses it with Unrecognized Critical Record, so it does
not affect existing deployments.

The specification has test vectors for both methods (Appendix A). Norn
(https://github.com/Vanaheimr/Norn, AGPL-3.0) implements client and server
with both methods; until the assignment it uses the value 16386 from the
private range.
```

### How to submit

Use the IANA request form for protocol parameter assignments:

<https://www.iana.org/form/protocol-assignment>

Select the registry "Network Time Security Key Establishment Record Types" and paste the
template and the text above. Alternatively, the request can be mailed to <iana@iana.org>
with the registry name in the subject line. IANA confirms by mail, assigns a ticket number
and passes the request to the designated experts. Unlike a First Come First Served
registration, this takes an expert review, and the experts may come back with questions on
the specification before they approve it.

### Please check before sending

- **The specification calls itself a draft.** Its header reads *Version 1.0 — Draft*, and
  Specification Required asks for a permanent specification. Proposed: publish it as
  *Version 1.0*, without *Draft*, on the day of the request. `TBD` stays until the
  assignment. A later version that adds methods does not change the record type.
- ~~**The white paper is a normative reference of the specification, and its status line is
  out of date.**~~ Done 2026-11-10: the status line of [README.md](README.md) no longer reads
  that nothing is implemented, but that Norn implements both options on Hermod, as
  Appendix C of the specification says, and it points to the specification and to this
  request.
- ~~**[RFC8446] in the specification is obsolete.**~~ Done 2026-11-10: the specification
  cites RFC 9846, which obsoletes RFC 8446 (July 2026), for the KeyUpdate of TLS 1.3.
- **The contact details become public.** IANA publishes the contact name in the registry and
  the mail address in the archived template. The address is the one of the registration of
  MetrologicalCBOR, so nothing new is disclosed.
- **The URL is a `master` branch link.** It stays valid as long as the file keeps its path,
  and always shows the current specification, as with MetrologicalCBOR. If the experts ask
  for an immutable reference, give them a commit permalink in addition.


## After the assignment

The value assigned below is written `N`; on the wire the record starts with `0x8000 | N`,
the type with the Critical Bit set (`8401` for 1025, instead of `c002` today).

1. **This file:** the status above set to *registered*, with the date, the ticket number and
   what the registry entry says.
2. **The specification** ([nts-ke-ssh-key-binding.md](nts-ke-ssh-key-binding.md)): `TBD`
   replaced by `N` in the introduction, the figure and the field list of Section 3.1,
   Section 7 and Appendix B; Appendix C says that Norn uses `N`.
3. **The white paper** ([README.md](README.md)): the record type of the table in section 5
   with its bullet on the private range, and the record type in A.2, both in the hex dumps
   (`c002`) and in the captions (*record type 16386*).
4. **Norn**: `NTSKE_RecordTypes.SSHKeyBinding` and its entry in `Description()`
   (`Norn/NTS-KE/Records/NTSKE_RecordTypes.cs`), and the tests that expect `c002`
   (`NornTests/NTS/NTSKE_SSH_Tests.cs`). The copy of Norn in ntswebui follows Norn.
5. **The transition:** a client that sends 16386 to a server that knows only `N` is refused
   with *Unrecognized Critical Record*, as the record is critical. Where clients and servers
   are not updated together, a server can accept 16386 as well for a while and answer with
   the type the request used. Clients send only `N`. To be decided when Norn changes.

[RFC 8126]: https://www.rfc-editor.org/rfc/rfc8126
[RFC 8915]: https://www.rfc-editor.org/rfc/rfc8915
