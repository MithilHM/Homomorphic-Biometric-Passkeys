import { describe, expect, it } from "vitest";
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import {
  base64UrlToBytes,
  bytesToBase64Url,
} from "@homobio/crypto-utils";
import {
  WebAuthnError,
  credentialCommitment,
  decodeCbor,
  decodeCborMap,
  parseAuthenticatorData,
  verifyAssertionResponse,
  verifyRegistrationResponse,
  type SignatureVerifier,
} from "../src/index.js";
import { SoftwareAuthenticator } from "./software-authenticator.js";

const RP_ID = "app.homobio.test";
const ORIGIN = "https://app.homobio.test";

const nodeVerifier: SignatureVerifier = (data, spkiBase64Url, signature) => {
  const key = createPublicKey({
    key: Buffer.from(base64UrlToBytes(spkiBase64Url)),
    format: "der",
    type: "spki",
  });
  return nodeVerify(
    "sha256",
    Buffer.from(data),
    { key, dsaEncoding: "ieee-p1363" },
    Buffer.from(signature),
  );
};

function authenticator(overrides: Partial<ConstructorParameters<typeof SoftwareAuthenticator>[0]> = {}) {
  return new SoftwareAuthenticator({ rpId: RP_ID, origin: ORIGIN, signCount: 1, ...overrides });
}

describe("CBOR decoder", () => {
  it("decodes the canonical integer encodings", () => {
    expect(decodeCbor(Uint8Array.of(0x00))).toBe(0);
    expect(decodeCbor(Uint8Array.of(0x17))).toBe(23);
    expect(decodeCbor(Uint8Array.of(0x18, 0x18))).toBe(24);
    expect(decodeCbor(Uint8Array.of(0x20))).toBe(-1);
  });

  it("rejects trailing bytes", () => {
    expect(() => decodeCbor(Uint8Array.of(0x00, 0x00))).toThrow(/trailing/);
  });

  it("rejects indefinite lengths", () => {
    expect(() => decodeCbor(Uint8Array.of(0x5f, 0xff))).toThrow(/indefinite/);
  });

  it("rejects truncated input", () => {
    expect(() => decodeCbor(Uint8Array.of(0x42, 0x01))).toThrow(/truncated/);
  });
});

describe("registration", () => {
  it("verifies a well-formed attestation", async () => {
    const auth = authenticator();
    const response = auth.create({ challenge: "Y2hhbGxlbmdl" });

    const result = await verifyRegistrationResponse(
      { clientDataJSON: response.clientDataJSON, attestationObject: response.attestationObject },
      { expectedChallenge: "Y2hhbGxlbmdl", expectedOrigin: ORIGIN, rpId: RP_ID },
    );

    expect(result.publicKeySpki).toBe(auth.publicKeySpkiBase64Url);
    expect(result.alg).toBe(-7);
    expect(result.attestationFormat).toBe("none");
    expect(result.userVerified).toBe(true);
    expect(result.credentialId).toBe(response.credentialId);
  });

  it("rejects a different challenge", async () => {
    const auth = authenticator();
    const response = auth.create({ challenge: "Y2hhbGxlbmdl" });
    await expect(
      verifyRegistrationResponse(response, {
        expectedChallenge: "c29tZXRoaW5nLWVsc2U",
        expectedOrigin: ORIGIN,
        rpId: RP_ID,
      }),
    ).rejects.toMatchObject({ code: "challenge_mismatch" });
  });

  it("rejects a different origin", async () => {
    const auth = authenticator();
    const response = auth.create({ challenge: "Y2hhbGxlbmdl" });
    await expect(
      verifyRegistrationResponse(response, {
        expectedChallenge: "Y2hhbGxlbmdl",
        expectedOrigin: "https://evil.example",
        rpId: RP_ID,
      }),
    ).rejects.toMatchObject({ code: "origin_mismatch" });
  });

  it("rejects a different RP ID", async () => {
    const auth = authenticator({ rpId: "other.example" });
    const response = auth.create({ challenge: "Y2hhbGxlbmdl" });
    await expect(
      verifyRegistrationResponse(response, {
        expectedChallenge: "Y2hhbGxlbmdl",
        expectedOrigin: ORIGIN,
        rpId: RP_ID,
      }),
    ).rejects.toMatchObject({ code: "rp_mismatch" });
  });

  it("enforces user verification when the policy demands it", async () => {
    const auth = authenticator({ userVerified: false });
    const response = auth.create({ challenge: "Y2hhbGxlbmdl" });
    await expect(
      verifyRegistrationResponse(response, {
        expectedChallenge: "Y2hhbGxlbmdl",
        expectedOrigin: ORIGIN,
        rpId: RP_ID,
        requireUserVerification: true,
      }),
    ).rejects.toMatchObject({ code: "user_verification_required" });
  });

  it("rejects garbage in place of an attestation object", async () => {
    await expect(
      verifyRegistrationResponse(
        { clientDataJSON: "e30", attestationObject: bytesToBase64Url(Uint8Array.of(1, 2, 3)) },
        { expectedChallenge: "x", expectedOrigin: ORIGIN, rpId: RP_ID },
      ),
    ).rejects.toBeInstanceOf(Error);
  });
});

describe("assertion", () => {
  async function register(auth: SoftwareAuthenticator) {
    const registration = auth.create({ challenge: "cmVnaXN0ZXI" });
    return verifyRegistrationResponse(registration, {
      expectedChallenge: "cmVnaXN0ZXI",
      expectedOrigin: ORIGIN,
      rpId: RP_ID,
    });
  }

  it("verifies a genuine assertion", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    // A real authenticator advances its counter between operations.
    auth.bumpCounter();
    const assertion = auth.get({ challenge: "YXNzZXJ0" });

    const result = await verifyAssertionResponse(
      { credentialId: credential.credentialId, ...assertion },
      { ...credential, status: "active" },
      { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
      nodeVerifier,
    );

    expect(result.userVerified).toBe(true);
    expect(result.signCount).toBe(6);
  });

  it("rejects a tampered signature", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    const assertion = auth.get({ challenge: "YXNzZXJ0" });
    const flipped =
      assertion.signature.slice(0, -2) + (assertion.signature.endsWith("AA") ? "AB" : "AA");

    await expect(
      verifyAssertionResponse(
        { credentialId: credential.credentialId, ...assertion, signature: flipped },
        { ...credential, status: "active" },
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).rejects.toMatchObject({ code: "signature_invalid" });
  });

  it("rejects an assertion signed over a different challenge", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    const assertion = auth.get({ challenge: "b3RoZXI" });

    await expect(
      verifyAssertionResponse(
        { credentialId: credential.credentialId, ...assertion },
        { ...credential, status: "active" },
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).rejects.toMatchObject({ code: "challenge_mismatch" });
  });

  it("rejects a replayed assertion (counter does not advance)", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    const assertion = auth.get({ challenge: "YXNzZXJ0" });
    const stored = { ...credential, status: "active" as const, signCount: 5 };

    await expect(
      verifyAssertionResponse(
        { credentialId: credential.credentialId, ...assertion },
        stored,
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).rejects.toMatchObject({ code: "counter_regression" });
  });

  it("accepts a zero counter for a synced passkey", async () => {
    const auth = authenticator({ signCount: 0, backupEligible: true });
    const credential = await register(auth);
    const assertion = auth.get({ challenge: "YXNzZXJ0" });

    await expect(
      verifyAssertionResponse(
        { credentialId: credential.credentialId, ...assertion },
        { ...credential, status: "active", signCount: 9 },
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).resolves.toMatchObject({ backupState: false });
  });

  it("rejects a revoked credential", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    const assertion = auth.get({ challenge: "YXNzZXJ0" });

    await expect(
      verifyAssertionResponse(
        { credentialId: credential.credentialId, ...assertion },
        { ...credential, status: "revoked" },
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).rejects.toMatchObject({ code: "credential_revoked" });
  });

  it("rejects a signature from a different credential than the one claimed", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    const impostor = authenticator({ signCount: 6 });
    const assertion = impostor.get({ challenge: "YXNzZXJ0" });

    await expect(
      verifyAssertionResponse(
        { credentialId: credential.credentialId, ...assertion },
        { ...credential, status: "active" },
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).rejects.toMatchObject({ code: "signature_invalid" });
  });

  it("rejects a DER-encoded signature instead of the raw r||s form", async () => {
    const auth = authenticator({ signCount: 5 });
    const credential = await register(auth);
    const assertion = auth.get({ challenge: "YXNzZXJ0" });

    await expect(
      verifyAssertionResponse(
        {
          credentialId: credential.credentialId,
          ...assertion,
          signature: bytesToBase64Url(new Uint8Array(70).fill(1)),
        },
        { ...credential, status: "active" },
        { expectedChallenge: "YXNzZXJ0", expectedOrigin: ORIGIN, rpId: RP_ID },
        nodeVerifier,
      ),
    ).rejects.toMatchObject({ code: "malformed" });
  });
});

describe("authenticatorData parsing", () => {
  it("decodes flags and the embedded COSE key", async () => {
    const auth = authenticator({ signCount: 3, backupEligible: true, backupState: true });
    const response = auth.create({ challenge: "Y2hhbGxlbmdl" });
    const object = decodeCborMap(base64UrlToBytes(response.attestationObject));
    const authData = object.get("authData") as Uint8Array;
    const parsed = parseAuthenticatorData(authData);

    expect(parsed.signCount).toBe(3);
    expect(parsed.userPresent).toBe(true);
    expect(parsed.userVerified).toBe(true);
    expect(parsed.backupEligible).toBe(true);
    expect(parsed.backupState).toBe(true);
    expect(parsed.attestedCredentialData).toBe(true);
    expect(parsed.aaguid).toMatch(/^07/);
    expect(parsed.credentialPublicKeyLength).toBeGreaterThan(0);
  });

  it("rejects truncated authenticator data", () => {
    expect(() => parseAuthenticatorData(new Uint8Array(10))).toThrow(WebAuthnError);
  });
});

describe("credential commitment", () => {
  it("is deterministic and field-separated", () => {
    const base = {
      wallet: "0x1111111111111111111111111111111111111111",
      credentialId: "abc",
      publicKeyFingerprint: `0x${"22".repeat(32)}`,
    };
    expect(credentialCommitment(base)).toBe(credentialCommitment({ ...base }));
    expect(credentialCommitment(base)).not.toBe(credentialCommitment({ ...base, credentialId: "abd" }));
  });
});

describe("verifier plumbing", () => {
  it("propagates a malformed public key as an error rather than a silent pass", () => {
    expect(() =>
      nodeVerifier(new Uint8Array(3), bytesToBase64Url(new Uint8Array([1])), new Uint8Array(64)),
    ).toThrow();
  });
});


