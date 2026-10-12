/**
 * Generate the cross-language cryptographic test vectors (PRD section 41.3).
 *
 * The vectors pin the exact bytes every language boundary must agree on:
 * the canonical authorization hash, the session-key hash, the ERC-4337
 * userOpHash and the FHE ciphertext commitment. `contracts/test/cross-language.test.ts`
 * re-derives them from the Solidity sources and fails on any drift.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import {
  authorizationHashHex,
  decisionProgramHash,
  envelopeHashHex,
  resultCommitmentHex,
  sessionKeyHashHex,
  ProofSystem,
  type AuthorizationFields,
} from "@homobio/protocol-types";
import { getUserOpHash, type PackedUserOperation } from "@homobio/userop";
import { DEFAULT_FHE_PARAMS } from "@homobio/fhe";

const vectors = {
  generatedBy: "scripts/gen-vectors.ts",
  note: "Regenerate with `npm run vectors`; every field here is checked by the test suite.",
  authorization: {
    description: "keccak256(abi.encodePacked('HOMOBIO/AUTH-V1', ...)) as implemented in contracts/protocol/AuthDomain.sol",
    fields: {
      version: 1,
      wallet: "0x1111111111111111111111111111111111111111",
      chainId: 143,
      userOpHash: "aa".repeat(32),
      sessionId: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
      policyHash: "bb".repeat(32),
      templateVersion: 3,
      fheKeyVersion: 2,
      decision: true,
      thresholdBps: 700_000,
      resultCommitment: "cc".repeat(32),
      issuedAt: 1_791_370_000,
      expiresAt: 1_791_370_180,
      proofSystem: ProofSystem.ThresholdAttestation,
      verifierVersion: 1,
      decisionProgramHash: "dd".repeat(32),
    } satisfies AuthorizationFields,
  },
  sessionKey: {
    description: "keccak256 of the scoped session key, mirrored by AuthDomain.sessionKeyHash",
    fields: {
      sessionKey: "0x2222222222222222222222222222222222222222",
      wallet: "0x1111111111111111111111111111111111111111",
      chainId: 143,
      validUntil: 1_791_374_000,
      maxValuePerTxWei: "1000000000000000000",
      nonceDomain: 1,
      allowedTargets: ["0x3333333333333333333333333333333333333333"],
      allowedSelectors: ["0x12345678"],
    },
  },
  userOperation: {
    description: "ERC-4337 v0.7 keccak256(abi.encode(keccak256(abi.encode(op)), entryPoint, chainId))",
    entryPoint: "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
    chainId: 143,
    operation: {
      sender: "0x1111111111111111111111111111111111111111",
      nonce: "0x00",
      initCode: "0x",
      callData: "0xb9059cbb000000000000000000000000000000000000000000000000000000000000dead",
      callGasLimit: "0x61a80",
      verificationGasLimit: "0xdbba0",
      preVerificationGas: "0x1d4c0",
      maxPriorityFeePerGas: "0x59682f00",
      maxFeePerGas: "0x6fc23ac0",
      paymasterAndData: "0x",
      signature: `0x48${"00".repeat(300)}`,
    } as unknown as Record<string, string>,
  },
  fhe: {
    description: "parameter set the off-chain services and the browser must agree on",
    params: DEFAULT_FHE_PARAMS,
    metric: "cosine-similarity",
    templateLayout: "high",
    queryLayout: "low",
    decisionProgramHash: decisionProgramHash({
      engine: DEFAULT_FHE_PARAMS.engine,
      metric: "cosine-similarity",
      embeddingDimension: DEFAULT_FHE_PARAMS.embeddingDimension,
      scaleBits: DEFAULT_FHE_PARAMS.scaleBits,
      ringDimension: DEFAULT_FHE_PARAMS.ringDimension,
      securityLevelBits: DEFAULT_FHE_PARAMS.securityLevelBits,
    }),
  },
} as const;

const expected: Record<string, unknown> = {};

const authorizationFields = vectors.authorization.fields as AuthorizationFields;
expected.authorizationHash = authorizationHashHex(authorizationFields);

const sessionFields = vectors.sessionKey.fields;
expected.sessionKeyHash = sessionKeyHashHex(sessionFields);

const opJson = vectors.userOperation.operation as unknown as Record<string, string>;
const op: PackedUserOperation = {
  sender: opJson.sender,
  nonce: BigInt(opJson.nonce),
  initCode: opJson.initCode,
  callData: opJson.callData,
  callGasLimit: BigInt(opJson.callGasLimit),
  verificationGasLimit: BigInt(opJson.verificationGasLimit),
  preVerificationGas: BigInt(opJson.preVerificationGas),
  maxFeePerGas: BigInt(opJson.maxFeePerGas),
  maxPriorityFeePerGas: BigInt(opJson.maxPriorityFeePerGas),
  paymasterAndData: opJson.paymasterAndData,
  signature: opJson.signature,
};
expected.userOpHash = getUserOpHash(op, vectors.userOperation.entryPoint, vectors.userOperation.chainId);

expected.resultCommitment = resultCommitmentHex({
  sessionId: authorizationFields.sessionId,
  templateCommitment: "ee".repeat(32),
  queryCommitment: "ff".repeat(32),
  decision: true,
});

expected.envelopeHash = envelopeHashHex({
  wallet: authorizationFields.wallet,
  chainId: authorizationFields.chainId,
  operationHash: authorizationFields.userOpHash,
  challengeId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
  sessionId: authorizationFields.sessionId,
  nonce: "12".repeat(32),
  policyHash: authorizationFields.policyHash,
  authorizationHash: expected.authorizationHash as string,
  expiresAt: authorizationFields.expiresAt,
});

const outputDir = path.resolve(process.cwd(), "cryptography/vectors");
mkdirSync(outputDir, { recursive: true });
writeFileSync(
  path.join(outputDir, "protocol.json"),
  `${JSON.stringify({ ...vectors, expected }, null, 2)}\n`,
  "utf-8",
);

console.log("cryptographic test vectors written to cryptography/vectors/protocol.json");
console.log(`  authorizationHash ${expected.authorizationHash}`);
console.log(`  sessionKeyHash    ${expected.sessionKeyHash}`);
console.log(`  userOpHash        ${expected.userOpHash}`);
console.log(`  resultCommitment  ${expected.resultCommitment}`);
console.log(`  envelopeHash      ${expected.envelopeHash}`);
console.log(`  decisionProgram   ${expected.decisionProgramHash ?? vectors.fhe.decisionProgramHash}`);
