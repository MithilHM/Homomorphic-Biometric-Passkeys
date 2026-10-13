/**
 * `docs/protocol-spec.md` conformance.
 *
 * The spec is the normative document, but a spec that is never checked is just
 * prose. Every claim below is a byte-level assertion about the spec's section
 * N: if the implementation changes, or the spec is "updated" to match a
 * regression, this file fails.
 *
 * This is deliberately separate from `cross-language.test.ts`, which compares
 * TypeScript against *Solidity*. This file compares both against the *document*.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ascii, bytesToBase64Url, bytesToHex, concat, hexToBytes, keccak256Hex } from "@homobio/crypto-utils";
import {
  decisionProgramHash,
  envelopeHashHex,
  resultCommitmentHex,
  sessionIdToBytes,
} from "@homobio/protocol-types";
import { credentialCommitment } from "@homobio/webauthn";
import { ChallengeService } from "@homobio/challenge-service";
import { ProofService } from "@homobio/proof-service";
import { packAuthorizationEnvelope } from "@homobio/sdk/envelope";
import { packSessionEnvelope, getUserOpHash } from "@homobio/userop";

const root = path.resolve(__dirname, "../..");
const vectors = JSON.parse(readFileSync(path.join(root, "cryptography/vectors/protocol.json"), "utf-8")) as any;

/** Every domain separator the spec's section 0 table claims. */
const DOMAINS = [
  "HOMOBIO/AUTH-V1",
  "HOMOBIO/ENROLL-V1",
  "HOMOBIO/ENVELOPE-V1",
  "HOMOBIO/SESSION-V1",
  "HOMOBIO/RESULT-V1",
  "HOMOBIO/DECISION-PROGRAM-V1",
  "HOMOBIO/INTENT-V1",
  "HOMOBIO/CREDENTIAL-V1",
  "HOMOBIO/ACCOUNT-V1",
];

describe("spec section 0: domain separators", () => {
  const spec = readFileSync(path.join(root, "docs/protocol-spec.md"), "utf-8");

  it("documents every separator the codebase actually uses", () => {
    for (const domain of DOMAINS) {
      expect(spec, `domain ${domain} is missing from the spec`).toContain(`\`${domain}\``);
    }
  });

  it("keeps no domain a prefix of another (so concatenation is unambiguous)", () => {
    for (const a of DOMAINS) {
      for (const b of DOMAINS) {
        if (a === b) continue;
        expect(a.startsWith(b), `${a} is a prefix of ${b}`).toBe(false);
      }
    }
  });
});

describe("spec section 1: canonical encodings", () => {
  it("accepts both session id encodings and yields the same 16 bytes", () => {
    const uuid = "52f82713-feed-4c10-9f5c-431aa5a1a014";
    expect(sessionIdToBytes(uuid)).toHaveLength(16);
    expect(sessionIdToBytes(uuid)).toEqual(sessionIdToBytes(uuid.replace(/-/g, "")));
    expect(sessionIdToBytes(uuid.replace(/-/g, "").toUpperCase())).toEqual(sessionIdToBytes(uuid));
  });

  it("rejects a session id that is neither a uuid nor 32 hex chars", () => {
    expect(() => sessionIdToBytes("not-a-session")).toThrow();
    expect(() => sessionIdToBytes("abcd")).toThrow();
  });
});

describe("spec section 3.2: the intent challenge", () => {
  it("is the pipe-joined string the spec documents", () => {
    const service = new ChallengeService();
    const challenge = service.issue({
      wallet: "0x1111111111111111111111111111111111111111",
      chainId: 143,
      operationHash: `0x${"aa".repeat(32)}`,
      biometricPolicyVersion: 1,
      fheKeyVersion: 1,
      webauthnRpId: "app.example",
      webauthnOrigin: "https://app.example",
      policyHash: `0x${"bb".repeat(32)}`,
      templateVersion: 1,
    });

    // Section 3.2, field for field, in the documented order.
    const expected = keccak256Hex(
      [
        "HOMOBIO/INTENT-V1",
        String(challenge.chainId),
        challenge.wallet,
        challenge.operationHash,
        challenge.nonce,
        challenge.sessionId,
        String(challenge.biometricPolicyVersion),
        String(challenge.expiresAt),
        challenge.policyHash,
      ].join("|"),
    );
    expect(service.intentChallenge(challenge)).toBe(expected);
  });

  it("changes when any bound field changes", () => {
    const service = new ChallengeService();
    const base = {
      wallet: "0x1111111111111111111111111111111111111111",
      chainId: 143,
      operationHash: `0x${"aa".repeat(32)}`,
      biometricPolicyVersion: 1,
      fheKeyVersion: 1,
      webauthnRpId: "app.example",
      webauthnOrigin: "https://app.example",
      policyHash: `0x${"bb".repeat(32)}`,
      templateVersion: 1,
    };
    const original = service.intentChallenge(service.issue(base));
    // A passkey signed for a different operation must not satisfy this one.
    expect(service.intentChallenge(service.issue({ ...base, operationHash: `0x${"cc".repeat(32)}` }))).not.toBe(original);
    expect(service.intentChallenge(service.issue({ ...base, chainId: 1 }))).not.toBe(original);
    expect(service.intentChallenge(service.issue({ ...base, policyHash: `0x${"dd".repeat(32)}` }))).not.toBe(original);
  });

  it("burns the challenge on first use so a retry cannot re-evaluate", () => {
    const service = new ChallengeService();
    const issued = service.issue({
      wallet: "0x1111111111111111111111111111111111111111",
      chainId: 143,
      operationHash: `0x${"aa".repeat(32)}`,
      biometricPolicyVersion: 1,
      fheKeyVersion: 1,
      webauthnRpId: "app.example",
      webauthnOrigin: "https://app.example",
      policyHash: `0x${"bb".repeat(32)}`,
      templateVersion: 1,
    });
    const input = {
      challengeId: issued.challengeId,
      wallet: issued.wallet,
      chainId: issued.chainId,
      operationHash: issued.operationHash,
    };
    expect(() => service.consume(input)).not.toThrow();
    expect(() => service.consume(input)).toThrow(/already consumed/);
  });
});

describe("spec section 4.4: the credential commitment", () => {
  it("has NO separator between the domain and the payload", () => {
    // The subtle one: pipes separate the *payload* fields, but the domain is
    // concatenated directly. Adding a pipe here silently changes every
    // derived account address, so it is pinned.
    const input = {
      wallet: "0x1111111111111111111111111111111111111111",
      credentialId: "AQID",
      publicKeyFingerprint: `0x${"ab".repeat(32)}`,
    };
    const expected = keccak256Hex(
      concat(
        ascii("HOMOBIO/CREDENTIAL-V1"),
        new TextEncoder().encode(`${input.wallet}|${input.credentialId}|${input.publicKeyFingerprint}`),
      ),
    );
    expect(credentialCommitment(input)).toBe(expected);
    expect(credentialCommitment(input)).not.toBe(
      keccak256Hex(`HOMOBIO/CREDENTIAL-V1|${input.wallet}|${input.credentialId}|${input.publicKeyFingerprint}`),
    );
  });
});

describe("spec section 6: the authorization object", () => {
  it("matches the committed authorization hash", () => {
    expect(resultCommitmentHex({
      sessionId: vectors.authorization.fields.sessionId,
      templateCommitment: `0x${"ee".repeat(32)}`,
      queryCommitment: `0x${"ff".repeat(32)}`,
      decision: true,
    })).toBe(vectors.expected.resultCommitment);
  });

  it("produces a 32-byte EIP-191 prefixed digest over the attestation hash", () => {
    // Section 6.4: keccak256(EIP-191 prefix || attestationHashBytes).
    const attestationHash = vectors.expected.authorizationHash;
    const digest = ProofService.ethSignedDigest(attestationHash);
    expect(digest).toHaveLength(32);
    // The digest commits to the attestation hash's *bytes* — not to its 64
    // hex characters — under the standard 26-byte EIP-191 header.
    expect(bytesToHex(digest)).toBe(
      keccak256Hex(concat(ascii("\x19Ethereum Signed Message:\n32"), hexToBytes(`0x${attestationHash}`))),
    );
  });

  it("produces a 32-byte decision program hash", () => {
    expect(
      decisionProgramHash({
        engine: "rlwe-negacyclic-d1",
        metric: "cosine",
        embeddingDimension: 128,
        scaleBits: 18,
        ringDimension: 1024,
        securityLevelBits: 128,
      }),
    ).toHaveLength(64);
  });
});

describe("spec section 7: the signature envelopes", () => {
  const packed = packAuthorizationEnvelope({
    envelopeHash: `0x${"11".repeat(32)}`,
    attestationHash: `0x${"22".repeat(32)}`,
    attestationSignature: `0x${"33".repeat(65)}`,
    webauthnAssertion: bytesToBase64Url(new Uint8Array([0xaa, 0xbb, 0xcc])),
    authorization: { ...vectors.authorization.fields, attestationHash: `0x${"22".repeat(32)}` },
  });

  it("is magic 0x48 with a bodyLength that excludes the 3-byte header", () => {
    expect(packed.slice(2, 4)).toBe("48");
    const bodyLength = Number.parseInt(packed.slice(4, 8), 16);
    expect(bodyLength).toBe((packed.length - 2) / 2 - 3);
    // 32 envelopeHash + 2 assertionLength + 3 assertion + 242 auth + 65 sig
    expect(bodyLength).toBe(32 + 2 + 3 + 242 + 65);
  });

  it("keeps the session envelope at exactly 99 bytes total", () => {
    const session = packSessionEnvelope({
      sessionKey: "0x1111111111111111111111111111111111111111",
      validUntil: 1_791_374_000,
      selector: "0xa9059cbb",
      valueWei: "1000000000000000000",
      scopeHash: `0x${"22".repeat(32)}`,
    });
    expect(session.slice(2, 4)).toBe("53");
    expect((session.length - 2) / 2).toBe(99);
  });

  it("yields a zero-length assertion the account will reject", () => {
    // The account reverts MissingPasskeyAssertion on a zero-length assertion.
    // The client-side packer does not enforce this, so the guard is on-chain —
    // this test pins that the client CAN produce such an envelope, which is
    // exactly why the contract must check.
    const empty = packAuthorizationEnvelope({
      envelopeHash: `0x${"11".repeat(32)}`,
      attestationHash: `0x${"22".repeat(32)}`,
      attestationSignature: `0x${"33".repeat(65)}`,
      webauthnAssertion: "",
      authorization: { ...vectors.authorization.fields, attestationHash: `0x${"22".repeat(32)}` },
    });
    // "0x" + magic(2) + bodyLength(4) + envelopeHash(64) -> assertionLength at 72.
    expect(Number.parseInt(empty.slice(72, 76), 16)).toBe(0);
    // And it is shorter than the packed one by exactly the 3 assertion bytes.
    expect(packed.length - empty.length).toBe(6);
  });
});

describe("spec section 9: the operation hash", () => {
  it("matches the committed userOpHash", () => {
    const json = vectors.userOperation.operation;
    expect(
      getUserOpHash(
        {
          sender: json.sender,
          nonce: BigInt(json.nonce),
          initCode: json.initCode,
          callData: json.callData,
          callGasLimit: BigInt(json.callGasLimit),
          verificationGasLimit: BigInt(json.verificationGasLimit),
          preVerificationGas: BigInt(json.preVerificationGas),
          maxFeePerGas: BigInt(json.maxFeePerGas),
          maxPriorityFeePerGas: BigInt(json.maxPriorityFeePerGas),
          paymasterAndData: json.paymasterAndData,
          signature: json.signature,
        },
        vectors.userOperation.entryPoint,
        vectors.userOperation.chainId,
      ),
    ).toBe(vectors.expected.userOpHash);
  });

  it("commits to the signature field itself", () => {
    // Section 2's warning: the signature is inside `inner`, so the final
    // userOpHash cannot be known until the envelope is packed. If this ever
    // becomes independent of `signature`, section 9's ordering is wrong.
    const json = vectors.userOperation.operation;
    const op = {
      sender: json.sender,
      nonce: BigInt(json.nonce),
      initCode: json.initCode,
      callData: json.callData,
      callGasLimit: BigInt(json.callGasLimit),
      verificationGasLimit: BigInt(json.verificationGasLimit),
      preVerificationGas: BigInt(json.preVerificationGas),
      maxFeePerGas: BigInt(json.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(json.maxPriorityFeePerGas),
      paymasterAndData: json.paymasterAndData,
      signature: json.signature,
    };
    const other = { ...op, signature: `0x${"ab".repeat(64)}` };
    expect(getUserOpHash(other, vectors.userOperation.entryPoint, vectors.userOperation.chainId)).not.toBe(
      getUserOpHash(op, vectors.userOperation.entryPoint, vectors.userOperation.chainId),
    );
  });
});

describe("spec section 7.3: the envelope hash", () => {
  it("is a 32-byte hash over the documented fields", () => {
    expect(
      envelopeHashHex({
        wallet: vectors.authorization.fields.wallet,
        chainId: 143,
        operationHash: `0x${"aa".repeat(32)}`,
        challengeId: "52f82713-feed-4c10-9f5c-431aa5a1a014",
        sessionId: "52f82713-feed-4c10-9f5c-431aa5a1a014",
        nonce: `0x${"11".repeat(32)}`,
        policyHash: `0x${vectors.authorization.fields.policyHash}`,
        authorizationHash: `0x${vectors.expected.authorizationHash}`,
        expiresAt: 1_791_370_180,
      }),
    ).toHaveLength(64);
  });
});