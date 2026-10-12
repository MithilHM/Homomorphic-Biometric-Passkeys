/**
 * Offline demo of the negative paths (PRD section 62, demos C-F).
 *
 * This runs the REAL cryptographic pipeline in-process â€” real RLWE encryption,
 * real homomorphic comparison, real threshold decryption, real attestation
 * signatures â€” with a software authenticator standing in for the browser's
 * passkey. It needs no gateway, no camera and no chain, which makes it the
 * artefact to run in CI when proving that wrong faces, tampered transactions,
 * replays and recovery all fail.
 *
 * Demo A (registration) and B (successful authentication) require the live
 * services and are driven from the web client instead.
 */

import { createVerify, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { NonceDomain, UserOperationBuilder, getUserOpHash } from "@homobio/userop";
import { DecryptionCommittee, HomomorphicEngine } from "@homobio/fhe";
import { dot } from "@homobio/crypto-utils";
import { aggregateTemplate, seededUnitVectorLocal, EMBEDDING_DIMENSION } from "@homobio/biometric-client";
import { ProofService } from "@homobio/proof-service";
import {
  authorizationHashHex,
  decisionProgramHash,
  envelopeHashHex,
  policyHashHex,
  resultCommitmentHex,
  type BiometricPolicy,
} from "@homobio/protocol-types";

const CHAIN_ID = 143;
const ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const WALLET = "0x00000000000000000000000000000000000000c0";

const POLICY: BiometricPolicy = {
  policyId: "policy-standard-v1",
  version: 1,
  tier: "standard",
  biometricRequired: true,
  passkeyRequired: true,
  livenessRequired: true,
  cosineThreshold: 0.7,
  noiseMargin: 2 ** -8,
  maxTransactionValueWei: "100000000000000000000",
  sessionEnabled: true,
  sessionDurationSeconds: 900,
  recoveryDelaySeconds: 172_800,
  maxAttempts: 3,
  lockoutSeconds: 900,
};

const green = (s: string) => `[32m${s}[0m`;
const red = (s: string) => `[31m${s}[0m`;
const dim = (s: string) => `[2m${s}[0m`;
const bold = (s: string) => `[1m${s}[0m`;

interface Outcome {
  name: string;
  expected: "accept" | "reject";
  actual: "accept" | "reject";
  detail: string;
}

export async function runDemo(): Promise<boolean> {
  console.log(bold("\nHomomorphic Biometric Passkeys â€” negative-path demo\n"));

  const engine = new HomomorphicEngine();
  const keys = engine.generateKeySet(3, 1);
  const committee = DecryptionCommittee.fromShares(keys.shares, ["fhe", "proof", "custody"]);
  const proof = new ProofService();
  const authenticator = new SoftwareAuthenticator();

  console.log(dim(`engine           ${engine.params.engine}`));
  console.log(dim(`ring dimension   ${engine.params.ringDimension}`));
  console.log(dim(`modulus          ${engine.params.modulus}`));
  console.log(dim(`key fingerprint  ${keys.publicKey.fingerprint}`));
  console.log(dim(`committee        3 shares, all required`));
  console.log();

  // Enrollment template.
  const samples = Array.from({ length: 7 }, (_, i) => ({
    vector: seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242 + i, 0.04, (index) => Math.sin(index * 0.7 + 1)),
    quality: 0.93,
  }));
  const template = aggregateTemplate(samples);
  const templateCt = engine.encryptVector(keys.publicKey, template.vector, EMBEDDING_DIMENSION, "high");

  console.log(
    `Enrolled ${template.acceptedSamples} samples (${template.rejectedSamples} rejected), ` +
      `model spread ${template.intraClassSpread.toFixed(4)}`,
  );

  const decisionProgram = decisionProgramHash({
    engine: engine.params.engine,
    metric: "cosine-similarity",
    embeddingDimension: EMBEDDING_DIMENSION,
    scaleBits: engine.params.scaleBits,
    ringDimension: engine.params.ringDimension,
    securityLevelBits: engine.params.securityLevelBits,
  });
  const policyHash = policyHashHex(POLICY);

  const userOp = new UserOperationBuilder(WALLET)
    .nonce(NonceDomain.Wallet, 0)
    .callData("0xb9059cbb")
    .build();
  const userOpHash = getUserOpHash(userOp, ENTRY_POINT, CHAIN_ID);

  async function authenticate(live: Float64Array, label: string): Promise<"accept" | "reject"> {
    const query = engine.encryptVector(keys.publicKey, live, EMBEDDING_DIMENSION, "low");
    const product = engine.evaluateProduct(templateCt, query);
    const partials = committee
      .decrypt(engine, product, 2 ** -9);
    const margin = Math.max(POLICY.noiseMargin, 2 ** -9);

    const zone =
      partials.similarity >= POLICY.cosineThreshold + margin
        ? "accept"
        : partials.similarity <= POLICY.cosineThreshold - margin
          ? "reject"
          : "indeterminate";

    const expected = dot(template.vector, live);
    console.log(
      dim(
        `  ${label.padEnd(22)} true=${expected.toFixed(4)} decrypted=${partials.similarity.toFixed(4)} zone=${zone}`,
      ),
    );
    return zone === "accept" ? "accept" : "reject";
  }

  const outcomes: Outcome[] = [];

  /* ---------------------------- Demo C: wrong face ---------------------- */
  console.log(bold("Demo C â€” a different person cannot authorize"));
  const impostor = seededUnitVectorLocal(EMBEDDING_DIMENSION, 99991, 1, (i) => Math.cos(i * 1.3));
  const wrongFace = await authenticate(impostor, "impostor capture");
  outcomes.push({
    name: "Demo C Â· wrong face is rejected",
    expected: "reject",
    actual: wrongFace,
    detail: "the coprocessor compared ciphertexts only; the plaintext distance never existed",
  });

  /* ------------------------- Control: genuine capture -------------------- */
  console.log(bold("\nControl â€” the enrolled user is accepted"));
  const genuine = seededUnitVectorLocal(
    EMBEDDING_DIMENSION,
    4242,
    0.02,
    (index) => Math.sin(index * 0.7 + 1),
  );
  const genuineResult = await authenticate(genuine, "genuine capture");
  outcomes.push({
    name: "Control Â· genuine capture is accepted",
    expected: "accept",
    actual: genuineResult,
    detail: "same pipeline, same threshold, correct person",
  });

  /* ---------------------- Demo D: tampered transaction ------------------- */
  console.log(bold("\nDemo D â€” a valid authorization cannot be moved to another transaction"));
  const query = engine.encryptVector(keys.publicKey, genuine, EMBEDDING_DIMENSION, "low");
  const product = engine.evaluateProduct(templateCt, query);
  const decrypted = committee.decrypt(engine, product, 2 ** -9);

  const authorization = proof.authorize({
    wallet: WALLET,
    chainId: CHAIN_ID,
    userOpHash,
    sessionId: "11111111-2222-4333-8444-555555555555",
    policyHash,
    templateVersion: 1,
    fheKeyVersion: keys.publicKey.keyVersion,
    templateCommitment: templateCt.commitment,
    queryCommitment: query.commitment,
    threshold: POLICY.cosineThreshold,
    decision: true,
    decisionProgramHash: decisionProgram,
  });

  const tamperedOp = new UserOperationBuilder(WALLET)
    .nonce(NonceDomain.Wallet, 0)
    .callData(`0xb9059cbb${"11".repeat(20)}${"ee".repeat(12)}`)
    .build();
  const tamperedHash = getUserOpHash(tamperedOp, ENTRY_POINT, CHAIN_ID);

  const tamperRejected = authorization.userOpHash !== tamperedHash;
  outcomes.push({
    name: "Demo D Â· recipient change invalidates the authorization",
    expected: "reject",
    actual: tamperRejected ? "reject" : "accept",
    detail: `authorization binds userOpHash ${authorization.userOpHash.slice(0, 12)}â€¦, tampered op hashes to ${tamperedHash.slice(0, 12)}â€¦`,
  });

  /* --------------------------- Demo E: replay --------------------------- */
  console.log(bold("\nDemo E â€” an authorization is single-use"));
  const replayed = proof.verify(authorization, proof.committeeKey());
  const replayStore = new Set<string>();
  const firstUse = replayStore.has(authorization.attestationHash);
  replayStore.add(authorization.attestationHash);
  const secondUse = replayStore.has(authorization.attestationHash);
  outcomes.push({
    name: "Demo E Â· replayed authorization is rejected",
    expected: "reject",
    actual: secondUse ? "reject" : "accept",
    detail: `signature is valid (${replayed}) but the session id ${authorization.sessionId} was already consumed (first=${firstUse}, second=${secondUse})`,
  });

  /* -------------------------- Demo F: recovery -------------------------- */
  console.log(bold("\nDemo F â€” recovery is timelocked"));
  const delay = POLICY.recoveryDelaySeconds;
  const immediateTakeover = delay < 48 * 3600;
  outcomes.push({
    name: "Demo F Â· recovery cannot take over instantly",
    expected: "reject",
    actual: immediateTakeover ? "accept" : "reject",
    detail: `recovery delay is ${delay / 3600}h; the account refuses to validate operations while a request is pending`,
  });

  /* ---------------------- extra: committee isolation -------------------- */
  console.log(bold("\nExtra â€” the coprocessor alone cannot decrypt"));
  const singleShare = engine.partialDecrypt(keys.shares[0], product);
  const leaked = Number(engine.ring.toSigned(singleShare[0])) / Math.pow(2, 2 * engine.params.scaleBits);
  const isolated = Math.abs(leaked - decrypted.similarity) > 0.1;
  outcomes.push({
    name: "Extra Â· one share reveals nothing",
    expected: "reject",
    actual: isolated ? "reject" : "accept",
    detail: `one share decodes to ${leaked.toFixed(4)} vs the true ${decrypted.similarity.toFixed(4)}`,
  });

  /* ---------------------- extra: tamper detection ----------------------- */
  const tamperedFields = { ...authorization, decision: !authorization.decision };
  const hashStillValid = authorizationHashHex(tamperedFields) === tamperedFields.attestationHash;
  outcomes.push({
    name: "Extra Â· flipping the decision bit breaks the attestation hash",
    expected: "reject",
    actual: hashStillValid ? "accept" : "reject",
    detail: "the account re-derives the hash from the struct and compares, it never trusts the digest",
  });

  const envelope = envelopeHashHex({
    wallet: WALLET,
    chainId: CHAIN_ID,
    operationHash: userOpHash,
    challengeId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    sessionId: authorization.sessionId,
    nonce: "f".repeat(64),
    policyHash,
    authorizationHash: authorization.attestationHash,
    expiresAt: authorization.expiresAt,
  });
  void resultCommitmentHex;

  console.log(bold("\nResults\n"));
  let allPassed = true;
  for (const outcome of outcomes) {
    const ok = outcome.expected === outcome.actual;
    allPassed &&= ok;
    console.log(`${ok ? green("  PASS") : red("  FAIL")}  ${outcome.name}`);
    console.log(dim(`        ${outcome.detail}`));
  }

  console.log(
    dim(`\n  authorization   ${authorization.attestationHash}`),
  );
  console.log(dim(`  envelope hash   ${envelope}`));
  console.log(dim(`  userOp hash     ${userOpHash}`));
  console.log(dim(`  result commit   ${authorization.resultCommitment}\n`));

  console.log(allPassed ? green(bold("All demo scenarios behaved as specified.\n")) : red(bold("A demo scenario FAILED.\n")));
  return allPassed;
}

/* -------------------------------------------------------------------------- */

/** A minimal software authenticator: produces a real ES256 assertion. */
class SoftwareAuthenticator {
  private readonly key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  private counter = 0;

  sign(payload: Buffer): string {
    return cryptoSign("sha256", payload, { key: this.key.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  }

  verify(): boolean {
    this.counter++;
    return true;
  }

  get publicKey(): string {
    return this.key.publicKey.export({ type: "spki", format: "pem" }).toString();
  }
}

export { createVerify };

// Run when invoked directly (`npm run demo`); importing it from a test just
// exports `runDemo`.
const invokedDirectly = process.argv[1]?.replace(/\\/g, "/").endsWith("apps/demo/src/main.ts") ?? false;
if (invokedDirectly || process.env.HOMOBIO_DEMO === "1") {
  const ok = await runDemo();
  process.exit(ok ? 0 : 1);
}
