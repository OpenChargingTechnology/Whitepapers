#!/usr/bin/env node
// Generates SignedMessages/test-vectors/signed-messages-vectors.json.
//
// An implementation of section 4 of "Signed OCPP Messages and Signer Roles" that shares no code
// with the reference implementation (WWCP_Core): RFC 8785 from ECMAScript's own JSON.stringify,
// ECDSA from Node's OpenSSL. Needs Node.js 20 or newer and nothing else.
//
//     node SignedMessages/tools/generate-test-vectors.mjs
//
// ECDSA signatures are randomized, so every run writes other signature values. The keys are
// derived from fixed labels and stay the same.

import crypto from "node:crypto";
import fs     from "node:fs";
import path   from "node:path";
import url    from "node:url";

const here   = path.dirname(url.fileURLToPath(import.meta.url));
const target = path.join(here, "..", "test-vectors", "signed-messages-vectors.json");

// ---- RFC 8785 ---------------------------------------------------------------------------------

function jcs(value) {
    if (value === null || typeof value !== "object")
        return JSON.stringify(value);
    if (Array.isArray(value))
        return "[" + value.map(jcs).join(",") + "]";
    return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + jcs(value[k])).join(",") + "}";
}

const b64u = bytes => Buffer.from(bytes).toString("base64url");

// ---- Keys -------------------------------------------------------------------------------------

function keyFrom(label) {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.setPrivateKey(crypto.createHash("sha256").update(label).digest());
    const pub  = ecdh.getPublicKey();
    const jwk  = { kty: "EC", crv: "P-256", x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)) };
    return {
        label,
        jwk,
        d:        b64u(ecdh.getPrivateKey()),
        rawPoint: pub.toString("hex"),
        kid:      b64u(crypto.createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`).digest()),
        private:  crypto.createPrivateKey({ key: { ...jwk, d: b64u(ecdh.getPrivateKey()) }, format: "jwk" })
    };
}

const csmsKey     = keyFrom("signed-messages test vector key: CSMS operator");
const strangerKey = keyFrom("signed-messages test vector key: stranger");
const stationKey  = keyFrom("signed-messages test vector key: station cs01");

// ---- Signing ----------------------------------------------------------------------------------

const IAT = 1762819200;  // 2025-11-11T00:00:00Z

function sign(key, header, payload, { kidOf = key } = {}) {
    const protectedHeader = { alg: "ES256", kid: kidOf.kid, ...header };
    const crit = Object.keys(protectedHeader).filter(k => k.startsWith("OCPP"));
    if (crit.length) protectedHeader.crit = crit;
    const protectedText = b64u(Buffer.from(JSON.stringify(protectedHeader)));
    const signingInput  = protectedText + "." + b64u(Buffer.from(jcs(payload)));
    const signature     = crypto.sign("sha256", Buffer.from(signingInput), { key: key.private, dsaEncoding: "ieee-p1363" });
    return {
        signature: { protected: protectedText, header: { jwk: key.jwk }, signature: b64u(signature) },
        canonicalPayload: jcs(payload),
        signingInput
    };
}

const requestHeader = (overrides = {}) => ({
    OCPPVersion: "ocpp2.1", OCPPMessageTypeId: 2, OCPPAction: "Reset", OCPPMessageId: "4711",
    OCPPSource: "CSMS", OCPPDestination: "cs01", iat: IAT, ...overrides
});

// A payload exactly as a peer may send it: members in another order, whitespace, a number spelled
// "1.50" - and a field the receiver's parser does not know, which the signature covers all the same.
function frameText(messageTypeId, messageId, action, payloadWithSignatures, extra = "") {
    const sigs = JSON.stringify(payloadWithSignatures.signatures);
    const rest = { ...payloadWithSignatures }; delete rest.signatures;
    const body = Object.entries(rest).map(([k, v]) => `"${k}" : ${JSON.stringify(v)}`).join(" ,  ");
    const payloadText = `{ ${body}${body ? " , " : ""}"signatures": ${sigs}${extra} }`;
    return messageTypeId === 3
        ? `[3,"${messageId}",${payloadText}]`
        : `[${messageTypeId}, "${messageId}", "${action}", ${payloadText}]`;
}

const vectors = [];

function requestVector(id, description, { payload, header, key = csmsKey, kidOf, frame, verifier, expected }) {
    const s = sign(key, requestHeader(header), payload, { kidOf });
    const f = frame ?? { messageId: "4711", action: "Reset" };
    const received = f.payload ?? payload;
    vectors.push({
        id, description,
        frames: [ frameText(2, f.messageId, f.action, { ...received, signatures: [ s.signature ] }) ],
        verifier: { nodeId: "cs01", ocppVersion: "ocpp2.1", now: IAT + 10, acceptFormat0: false, rule: { action: "VerifyAll" }, ...verifier },
        // What the verifier computes from the payload as it received it.
        expected: { canonicalPayload: jcs(received),
                    signingInput:     s.signature.protected + "." + b64u(Buffer.from(jcs(received))),
                    ...expected }
    });
}

const reset = { type: "Immediate", vendorHint: "keep the lights on" };

requestVector("valid-request", "A Reset signed by the CSMS operator for cs01, verified by a rule that names that key.",
              { payload: reset, verifier: { rule: { action: "VerifyAll", key: csmsKey.rawPoint } },
                expected: { results: [ { accepted: true, status: "ValidSignature" } ] } });

requestVector("rule-without-key", "A rule without a key checks the signature against the key the signature carries (its jwk), whose thumbprint is the kid.",
              { payload: reset, expected: { results: [ { accepted: true, status: "ValidSignature" } ] } });

requestVector("tampered-payload", "The reset type was changed after signing.",
              { payload: reset, frame: { messageId: "4711", action: "Reset", payload: { ...reset, type: "OnIdle" } },
                expected: { results: [ { accepted: false, status: "InvalidSignature" } ] } });

requestVector("unknown-field-changed", "A field the receiver's parser does not know is covered too: changing it breaks the signature.",
              { payload: reset, frame: { messageId: "4711", action: "Reset", payload: { ...reset, vendorHint: "turn the lights off" } },
                expected: { results: [ { accepted: false, status: "InvalidSignature" } ] } });

requestVector("other-action", "The signature of an empty ClearCache payload in a GetLocalListVersion frame: the mathematics holds, the header names another action.",
              { payload: {}, header: { OCPPAction: "ClearCache" }, frame: { messageId: "4711", action: "GetLocalListVersion", payload: {} },
                expected: { results: [ { accepted: false, status: "WrongFrame" } ] } });

requestVector("other-message-id", "The same signed payload under another message id.",
              { payload: reset, frame: { messageId: "4712", action: "Reset" },
                expected: { results: [ { accepted: false, status: "WrongFrame" } ] } });

requestVector("other-destination", "A request signed for cs01 arrives at cs02, which trusts the same key.",
              { payload: reset, verifier: { nodeId: "cs02" },
                expected: { results: [ { accepted: false, status: "WrongFrame" } ] } });

requestVector("other-version", "Signed for OCPP 2.0.1, received over OCPP 2.1.",
              { payload: reset, header: { OCPPVersion: "ocpp2.0.1" },
                expected: { results: [ { accepted: false, status: "WrongFrame" } ] } });

requestVector("expired", "Without exp, a signature is valid for maxSignatureAge (900 s) after its iat.",
              { payload: reset, verifier: { now: IAT + 901 },
                expected: { results: [ { accepted: false, status: "OutOfTime" } ] } });

requestVector("from-the-future", "Made further in the future than maxClockSkew (300 s).",
              { payload: reset, verifier: { now: IAT - 301 },
                expected: { results: [ { accepted: false, status: "OutOfTime" } ] } });

requestVector("stranger", "Signed by a key other than the one the rule names.",
              { payload: reset, key: strangerKey, verifier: { rule: { action: "VerifyAll", key: csmsKey.rawPoint } },
                expected: { results: [ { accepted: false, status: "UnknownSigner" } ] } });

requestVector("kid-of-another-key", "The kid is the thumbprint of another key than the jwk the signature carries.",
              { payload: reset, key: strangerKey, kidOf: csmsKey,
                expected: { results: [ { accepted: false, status: "BrokenSignature" } ] } });

// A replay: the same frame twice to the same verifier.
{
    const s = sign(csmsKey, requestHeader(), reset);
    const frame = frameText(2, "4711", "Reset", { ...reset, signatures: [ s.signature ] });
    vectors.push({
        id: "replay", description: "The same signed frame twice: the second time the pair (kid, message id) has been seen.",
        frames: [ frame, frame ],
        verifier: { nodeId: "cs01", ocppVersion: "ocpp2.1", now: IAT + 10, acceptFormat0: false, rule: { action: "VerifyAll" } },
        expected: { canonicalPayload: s.canonicalPayload, signingInput: s.signingInput,
                    results: [ { accepted: true, status: "ValidSignature" }, { accepted: false, status: "Replayed" } ] }
    });
}

// A response, bound to the request it answers.
{
    const request    = sign(csmsKey, requestHeader(), reset);
    const other      = sign(csmsKey, requestHeader({ iat: IAT + 1 }), reset);
    const hashOf     = sigs => b64u(crypto.createHash("sha256").update(Buffer.concat(sigs.map(s => Buffer.from(s.signature, "base64url")))).digest());
    const response   = { status: "Accepted" };
    const header     = { OCPPVersion: "ocpp2.1", OCPPMessageTypeId: 3, OCPPAction: "Reset", OCPPMessageId: "4711",
                         OCPPSource: "cs01", iat: IAT + 2, OCPPRequestHash: hashOf([ request.signature ]) };
    const signed     = sign(stationKey, header, response);
    const frame      = frameText(3, "4711", null, { ...response, signatures: [ signed.signature ] });
    const requestOf  = s => frameText(2, "4711", "Reset", { ...reset, signatures: [ s.signature ] });

    vectors.push({
        id: "response-to-its-request", description: "The station's signed answer, checked by the CSMS against the request it sent.",
        request: requestOf(request), frames: [ frame ],
        verifier: { nodeId: "CSMS", ocppVersion: "ocpp2.1", now: IAT + 10, acceptFormat0: false, rule: { action: "VerifyAll", key: stationKey.rawPoint } },
        expected: { canonicalPayload: signed.canonicalPayload, signingInput: signed.signingInput, results: [ { accepted: true, status: "ValidSignature" } ] }
    });

    vectors.push({
        id: "response-to-another-request", description: "The same answer, checked against another signed request under the same message id: OCPPRequestHash differs.",
        request: requestOf(other), frames: [ frame ],
        verifier: { nodeId: "CSMS", ocppVersion: "ocpp2.1", now: IAT + 10, acceptFormat0: false, rule: { action: "VerifyAll", key: stationKey.rawPoint } },
        expected: { canonicalPayload: signed.canonicalPayload, signingInput: signed.signingInput, results: [ { accepted: false, status: "WrongFrame" } ] }
    });
}

const document = {
    "$comment": "GENERATED by SignedMessages/tools/generate-test-vectors.mjs (OpenChargingTechnology/Whitepapers) - do not edit by hand. Regenerate by rerunning the generator.",
    specification: "Signed OCPP Messages and Signer Roles, version 0.1 (draft), section 4: the protected header in the embedded form",
    description: "Each vector gives OCPP-J frames as a peer received them, the state of the verifying node, and what it must decide. A verifier checks, per signature: the key (the rule's, or the jwk whose RFC 7638 thumbprint is the kid), ES256 over ASCII(protected || '.' || BASE64URL(RFC 8785 form of the payload as received, without 'signatures')), the header against the frame (OCPPVersion, OCPPMessageTypeId, OCPPAction, OCPPMessageId; for a request OCPPDestination is the verifying node; for a response OCPPRequestHash is SHA-256 over the concatenated signature values of the request), the time (iat <= now + maxClockSkew, now <= exp or iat + maxSignatureAge), and that (kid, OCPPMessageTypeId, OCPPNonce or OCPPMessageId) was not accepted before. 'frames' go to the same verifier in order; 'results' has one entry per frame. A frame that arrives over a direct OCPP-J connection carries no destination: the verifying node is it.",
    parameters: { maxClockSkew: 300, maxSignatureAge: 900 },
    keys: Object.fromEntries([ csmsKey, strangerKey, stationKey ].map(k => [ k.label, { jwk: k.jwk, d: k.d, rawPoint: k.rawPoint, kid: k.kid } ])),
    vectors
};

fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, JSON.stringify(document, null, 2) + "\n");
console.log(`${vectors.length} vectors written to ${path.relative(process.cwd(), target)}`);
