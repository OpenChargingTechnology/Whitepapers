# A signed metrological record, end to end

A worked example of a charging transaction carried as CBOR: two meter readings
expressed as [metrological values](README.md), signed by the meter, bundled
by the charging station, and endorsed by the operator before the customer
receives them.

Everything below is real output. The 713 bytes of Section 6 are pinned by
[`SignedMetrologyExampleTests`](https://github.com/Vanaheimr/Styx/blob/master/StyxTests/Illias/COSE/SignedMetrologyExampleTests.cs),
which derives every other listing in this document from them and verifies all
three signatures against the published public keys. The document is generated
from that constant, never retyped.

Every signature here is **deterministic** ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)):
the nonce is derived from the private key and the message rather than drawn at
random. So this document is not merely verifiable, it is **recomputable** —
sign the same readings with the same keys and the same 713 bytes come out,
on any implementation. The test does exactly that before it checks anything
else.

## 1. The three layers

| Layer | Who | Mechanism | Says |
|-------|-----|-----------|------|
| 1 | the meter | `COSE_Sign1` per reading | "I measured this" |
| 2 | the charging station | `COSE_Sign1` over a payload of its own | "these readings belong to this transaction at this point" |
| 3 | the operator | countersignature (RFC 9338) | "I saw the station's signature" |

Layers 1 and 2 are **nested**: the station has something of its own to say, so
it signs a new payload that contains the signed readings. Layer 3 is a
**countersignature**: the operator asserts nothing new about the data, so it
endorses the station's signature instead of wrapping it. That distinction
matters for the customer: the station's signature stays verifiable on its own,
and every reading keeps the meter's signature no matter how many parties
handled it afterwards.

## 2. The meter reading

The payload, in CBOR diagnostic notation:

```
{"time": 0("2026-08-15T08:14:00Z"), "meter": "1ISA0000000042",
 "energy": 44252([4([-3, 1234567]), 2, 3,
                  {1: 4([-1, 123]), 2: 2, 3: 4([-2, 95]), 4: 1}]),
 "context": "Transaction.Begin", "transaction": "a4f1c9e2"}
```

The members are in the order a deterministic encoder puts them — sorted by
their encoded key, shortest first — rather than in the order a person would
write them down. That is not decoration. A record like this one is received,
parsed and forwarded, and whoever forwards it re-encodes it; an encoder
following [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) Section 4.2.1
produces exactly these bytes. Had the meter written the members in reading
order instead, the forwarded record would carry a signature over a spelling
nobody downstream reproduces — and that failure is indistinguishable from
tampering.

134 bytes, of which the reading itself is 31:

```
A56474696D65C074323032362D30382D31355430383A31343A30305A656D657465726E31
4953413030303030303030343266656E65726779D9ACDC84C482221A0012D6870203A401
C48220187B020203C48221185F040167636F6E74657874715472616E73616374696F6E2E
426567696E6B7472616E73616374696F6E686134663163396532
```

The `energy` member is the point of this document. Read from the inside out:

| Element | Meaning |
|---------|---------|
| `4([-3, 1234567])` | **1234.567** — a decimal fraction, not a binary float. The instrument showed three decimal places and the wire says so; `1234.567` and `1234.5670` stay distinguishable. |
| `2` | the unit: watt hour |
| `3` | the SI prefix: kilo. It scales the quantity, it is not folded into the value — `1234.567 kWh` never silently becomes `1234567 Wh`. |
| `{1: …, 2: 2, 3: …, 4: 1}` | the measurement uncertainty per [GUM](https://www.bipm.org/en/committees/jc/jcgm/publications): magnitude **12.3**, coverage factor **k = 2**, coverage probability **0.95**, distribution **normal**. The standard uncertainty follows as *u* = *U*/*k* = 6.15 kWh. |

So the whole statement — value, scale, unit, prefix and a complete GUM
uncertainty — is 31 bytes, and a generic CBOR decoder that has never heard of
tag 44252 still sees a well-formed tagged array of integers and standard
decimal fractions.

Signed by the meter with **ESB256** (ECDSA on brainpoolP256r1 with SHA-256),
the reading becomes 221 bytes:

```
D28445A101390108A10448C6738177A6E6D04B5886A56474696D65C074323032362D3038
2D31355430383A31343A30305A656D657465726E31495341303030303030303034326665
6E65726779D9ACDC84C482221A0012D6870203A401C48220187B020203C48221185F0401
67636F6E74657874715472616E73616374696F6E2E426567696E6B7472616E7361637469
6F6E6861346631633965325840A8C6B9738D3A312248D78467C688147EA583170D25E8F2
D14475BA2404C8DE62369749AE5425975F50886C3C7C957A154DA788EF46C45276B1BEC4
FCE2A00FA5
```

- `D2` — CBOR tag 18, a `COSE_Sign1`
- `45 A101390108` — the protected bucket: `{1: -265}`, the algorithm ESB256,
  covered by the signature
- `A1 04 48 C6738177A6E6D04B` — the unprotected bucket: the key identifier,
  the leading 8 bytes of the meter key's [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679)
  thumbprint, which anyone holding the meter's public key can recompute
- `5886 …` — the payload above
- `5840 …` — the signature: *r* ‖ *s*, 32 bytes each

The second reading, `Transaction.End` at 1259.869 kWh, is 219 bytes of the
same shape. The billed quantity is the difference of two independently signed
readings: **25.302 kWh**.

## 3. The charging station's bundle

The station has its own statement to make — which readings belong to which
transaction at which point — so it signs a payload of its own:

```
{"readings": <2 signed readings>, "transaction": "a4f1c9e2",
 "chargingStation": "DE*GEF*E12345678*1"}
```

The readings go in as byte strings, complete with the meter's signatures. That
payload is 511 bytes; signed with **ES256** on P-256 the message is 713.

## 4. The operator's countersignature

The operator adds nothing to the data. It vouches for the station's signature,
and does so with a countersignature in the *unprotected* bucket — which is why
the station's message keeps its bytes and stays verifiable without knowing that
anyone endorsed it:

```
A2                        the unprotected bucket, two parameters
  04 48 4F4E…3440         the station's key identifier
  0B                      11: countersignature (RFC 9338)
    83                      a COSE_Countersignature
      44 A1013822           protected: {1: -35}, ES384
      A1 04 48 6B1F…88BB    the operator's key identifier
      5860 …                the signature, 48 bytes of r and s each
```

The version 2 structure of RFC 9338 is what is used here, and the difference is
not cosmetic. Its predecessor covered the payload but **not** the signature it
was countersigning, so it never actually attested to having seen it. Version 2
appends that signature to the signed structure — replacing the station's
signature, even with another valid signature over the same payload, therefore
invalidates the endorsement.

## 5. Verifying it

```csharp
var record   = COSESign1.Parse(bytes);

// The operator vouched for the station's signature...
record.VerifyCountersignature(record.Countersignatures[0], operatorKey, out var e1);

// ...the station signed the bundle...
record.Verify(stationKey, out var e2);

// ...and the meter signed every reading within it.
foreach (var reading in CBORValue.Parse(record.Payload!)["readings"].AsArray())
    COSESign1.Parse(reading.AsBytes()).Verify(meterKey, out var e3);
```

Each layer answers a different question, and a failure at one does not
invalidate the answers of the others. A single altered digit in a reading is
caught by the meter's signature even if the station's and the operator's
signatures were recomputed around it.

### Recomputing it

```csharp
COSESign1.Sign(payload, meterKey, COSEAlgorithm.ESB256, meterKeyId, Deterministic: true);
```

`Deterministic` derives the ECDSA nonce from the private key and the message
as RFC 6979 defines, so the signature stops being a random value that merely
verifies and becomes a function of what it signs.

The payload is written in the deterministic encoding of RFC 8949 Section
4.2.1 before it is signed, which `COSESign1.Sign` does by default. That is the
other half of the same idea: the nonce is a function of the message, and the
message is a function of the data. Rebuilding this record from the keys of
Section 7 therefore reproduces these exact 713 bytes — and so does any other
implementation given the same readings, which is what makes this a worked
example rather than an illustration.

That is worth having beyond documentation. A meter or a smart card has no
dependable source of randomness, and an ECDSA nonce that repeats hands over
the private key — a determinism that removes the requirement removes the
failure mode with it.

## 6. The complete record

713 bytes:

```
D28443A10126A204484F4E4267CBA434400B8344A1013822A104486B1F337BA0EC88BB58
6061C12A64FC1DB9E8943FCB43F8D9786D2FF7F8FF4EB6BD11AA175068F6DCA81EDC7EF9
38E169461927DF33CC63E2DD90A9247CB85B5D5D95FAC1B24C5E775482E817D331E84878
416C8A43F7C7486692A3CA5F6D8FF8A182D6008BC72B092C595901FFA36872656164696E
67738258DDD28445A101390108A10448C6738177A6E6D04B5886A56474696D65C0743230
32362D30382D31355430383A31343A30305A656D657465726E3149534130303030303030
30343266656E65726779D9ACDC84C482221A0012D6870203A401C48220187B020203C482
21185F040167636F6E74657874715472616E73616374696F6E2E426567696E6B7472616E
73616374696F6E6861346631633965325840A8C6B9738D3A312248D78467C688147EA583
170D25E8F2D14475BA2404C8DE62369749AE5425975F50886C3C7C957A154DA788EF46C4
5276B1BEC4FCE2A00FA558DBD28445A101390108A10448C6738177A6E6D04B5884A56474
696D65C074323032362D30382D31355430393A30323A30305A656D657465726E31495341
3030303030303030343266656E65726779D9ACDC84C482221A0013395D0203A401C48220
187E020203C48221185F040167636F6E746578746F5472616E73616374696F6E2E456E64
6B7472616E73616374696F6E6861346631633965325840008A537E8890CEF6D909BC8324
94718173315CC01E48FD779D6897FCC081E83270FCBE16A5E6939D5F8B1D5B80C1C4EC56
9335D5B175B3B49EB0DEFD994C0A6C6B7472616E73616374696F6E686134663163396532
6F6368617267696E6753746174696F6E7244452A4745462A4531323334353637382A3158
40EE16FB2B5B12407D00DFDC582601AE543AFE062D797CE222A1411A00C92EEEB6D68E3E
B9F259C02531AB438D6CC65BC7CC888C4DC5DE27DE106AF82AD13E89A7
```

| | bytes |
|---|---:|
| one meter reading, unsigned | 134 |
| one meter reading, signed | 221 |
| both readings plus the station's metadata | 511 |
| the station's signed bundle | 713 |
| the operator's countersignature, within those 713 | 96 of signature |

Four signatures by three signers — the meter signs each reading — two complete
metrological statements with their uncertainties, and the identities of all
three signers, in 713 bytes.

### What the same record costs after the quantum transition

The elliptic curve signatures above are 64, 64, 64 and 96 bytes: **288 of those
713 bytes are signature**. ML-DSA
([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204), registered for COSE by
[RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)) replaces each of them with
2420, 3309 or 4627 bytes depending on the parameter set — so the same four
signatures at ML-DSA-87 are **18 508 bytes**, and the record grows by more than
twenty-five times what it carries.

A single reading shows the same thing without the nesting. The 31-byte
metrological value of Section 2, signed on its own, is a 118-byte `COSE_Sign1`
with ESB256 and a 4675-byte one with ML-DSA-87.

None of this changes the tag, and the specification takes no position on which
algorithm anyone should use. It does sharpen the point of Section 6 of the tag
specification: a signature is a byte string, and a byte string costs its bytes
here. The same 4627-byte signature spelled out in base64 within a textual
format is 6172 characters — 1545 bytes of pure overhead on the largest field in
the message, and that penalty grows with exactly the field that post-quantum
cryptography makes grow.

## 7. The keys

Example keys. They were generated for this document, they secure nothing, and
they must never appear anywhere else.

| | curve | algorithm | key identifier |
|---|---|---|---|
| meter | brainpoolP256r1 | ESB256 (−265) | `C6738177A6E6D04B` |
| charging station | P-256 | ES256 (−7) | `4F4E4267CBA43440` |
| operator | P-384 | ES384 (−35) | `6B1F337BA0EC88BB` |

```
meter    x  A734FB1962C381113C746BDDBCBC774801E3B73FA7F73479615D290E91E48889
         y  8A188C8261A560197B37C73044E3009BA1DAED226C324A35FEE76AA144740678
         d  08F001BB03BEF4FBD1C59F10B50555CD37D2B53421331DBFA98815A581326FB3

station  x  7951E32509303CD4DB14127765B3FC9F32F62AC5C0F12350BD3ED7C746C72FE9
         y  A35716031E2C44A942D886626C5D4C41E0FF62E44FED7EDA3ACC1408D90720DC
         d  875E51ECF18073E8B970E6DCC5A115433456E13DF966034A5A782945D2B684D3

operator x  5DEF24F33251A911F43205134D568C1FB3547E2BD0B602D4B18A5FA476FF1FB8
            E6D321CC4ED1DCF754A81159C63389D2
         y  D8298F873104BC9AE145888BB7DC574AB26501E1E78DC4613CCB4B4C1B842720
            724671655551F9E2918C8943EAE8C2FA
         d  6952487A0A16EACE6E9A69EFD062D7671D68D23FF68722326348827C3A94E2A1
            743A1DF8901B948412CCA26CA4372CED
```

Every key identifier above is the leading 8 bytes of the RFC 9679 thumbprint of
its own key, so a verifier can check that the key it was handed is the key the
record names. Because the thumbprint covers the curve, a signer who changes
algorithm necessarily gets a different identifier — an algorithm downgrade
under an unchanged identity is not expressible.

## 8. What this is and is not

This is a proposal for how a digital, signed SI quantity can look on the wire,
and a demonstration that the pieces fit: the metrological content of
[tag 44252](README.md) — value, scale, unit, prefix, GUM uncertainty —
carried through three independent signature layers without losing a decimal
place or a coverage factor.

It is not a conformity statement. In the regulated part of the charging
infrastructure that follows from the type approval of the measuring instrument
and from the data being checkable with the verification software the approval
covers. What this format offers is the part underneath: a representation whose
encoding is a pure function of the measured quantity, so that the same reading
always produces the same bytes and therefore the same signature.

## References

- [README.md](README.md) — The Metrological CBOR Extension
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) — deterministic ECDSA
- [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — CBOR
- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) / [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053) — COSE
- [RFC 9338](https://www.rfc-editor.org/rfc/rfc9338) — COSE countersignatures
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) — ML-DSA for JOSE and COSE
- [FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) — Module-Lattice-Based Digital Signature Standard
- [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679) — COSE Key Thumbprint
- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) — fully-specified algorithms, incl. the brainpool curves
- JCGM 100:2008 — Guide to the expression of uncertainty in measurement
