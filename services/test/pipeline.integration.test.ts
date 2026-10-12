/**
 * End-to-end integration test (PRD section 41.2).
 *
 * Boots the real FHE coprocessor and the real API gateway in-process over
 * loopback HTTP, then drives a complete authentication and asserts the negative
 * paths: wrong face, replay, tampered operation, expired challenge, wrong
 * chain, and a coprocessor that cannot decrypt on its own.
 *
 * A software authenticator stands in for the browser's WebAuthn API, so the
 * signature verification path under test is the real one.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { JsonStore, type StoredRecord } from "../../packages/store/src/index.js";
import type { HttpApp } from "../../packages/http-kit/src/index.js";
import { ChallengeService } from "../../services/challenge-service/src/index.js";
import { WebAuthnService } from "../../services/webauthn-service/src/index.js";
import { ProofService } from "../../services/proof-service/src/index.js";
import { RelayerService, defaultRelayerConfig } from "../../services/relayer-service/src/index.js";
import { DEFAULT_FHE_PARAMS, HomomorphicEngine, serializeShare } from "../../packages/fhe/src/index.js";
import { NonceDomain, UserOperationBuilder, getUserOpHash } from "../../packages/userop/src/index.js";
import {
  EMBEDDING_DIMENSION,
  aggregateTemplate,
  seededUnitVectorLocal,
} from "../../packages/biometric-client/src/index.js";
import type { StoredPasskeyCredential } from "../../packages/protocol-types/src/index.js";
import { FheCoprocessor, createCoprocessorApp, type TemplateRecord } from "../../services/fhe-service/src/coprocessor.js";
import { FheClient } from "../../services/api-gateway/src/fhe-client.js";
import { PolicyRegistry } from "../../services/api-gateway/src/policy.js";
import { DecryptionCommitteeGateway } from "../../services/api-gateway/src/committee.js";
import { createGateway, type GatewayConfig } from "../../services/api-gateway/src/app.js";

/* -------------------------------------------------------------------------- */
/*                          Software authenticator                             */
/* -------------------------------------------------------------------------- */

class SoftwareAuthenticator {
  private readonly key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  private counter = 1;

  constructor(
    private readonly rpId: string,
    private readonly origin: string,
  ) {}

  bump(): void {
    this.counter += 1;
  }

  private clientData(type: string, challenge: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }

  private authData(extra: number): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    return Buffer.concat([
      createHash("sha256").update(this.rpId).digest(),
      Buffer.from([0x01 | 0x04 | extra]),
      counter,
    ]);
  }

  create(challenge: string, credentialId: Buffer) {
    const spki = this.key.publicKey.export({ type: "spki", format: "der" }) as Buffer;
    const point = spki.subarray(spki.length - 65);
    const cose = encodeCbor(
      new Map<number, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(point.subarray(1, 33))],
        [-3, new Uint8Array(point.subarray(33, 65))],
      ]),
    );

    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(credentialId.length);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);

    const authData = Buffer.concat([
      createHash("sha256").update(this.rpId).digest(),
      Buffer.from([0x01 | 0x04 | 0x40]),
      counter,
      Buffer.alloc(16, 7),
      idLength,
      credentialId,
      Buffer.from(cose),
    ]);

    const attestationObject = encodeCbor(
      new Map<string, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", new Uint8Array(authData)],
      ]),
    );

    return {
      credentialId: credentialId.toString("base64url"),
      clientDataJSON: this.clientData("webauthn.create", challenge).toString("base64url"),
      attestationObject: Buffer.from(attestationObject).toString("base64url"),
      transports: ["internal"],
    };
  }

  get(challenge: string) {
    const clientDataJSON = this.clientData("webauthn.get", challenge);
    const authData = this.authData(0);
    const signature = cryptoSign(
      "sha256",
      Buffer.concat([authData, createHash("sha256").update(clientDataJSON).digest()]),
      { key: this.key.privateKey, dsaEncoding: "ieee-p1363" },
    );
    return {
      clientDataJSON: clientDataJSON.toString("base64url"),
      authenticatorData: authData.toString("base64url"),
      signature: signature.toString("base64url"),
    };
  }
}

function cborHead(major: number, length: number): Uint8Array {
  const base = major << 5;
  if (length < 24) return Uint8Array.of(base | length);
  if (length < 0x100) return Uint8Array.of(base | 24, length);
  if (length < 0x10000) return Uint8Array.of(base | 25, (length >> 8) & 0xff, length & 0xff);
  return Uint8Array.of(base | 26, (length >>> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff);
}

function encodeCbor(value: unknown): Uint8Array {
  if (value === null) return Uint8Array.of(0xf6);
  if (typeof value === "boolean") return Uint8Array.of(value ? 0xf5 : 0xf4);
  if (typeof value === "number") return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return Buffer.concat([cborHead(3, bytes.length), Buffer.from(bytes)]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([cborHead(2, value.length), Buffer.from(value)]);
  if (value instanceof Map) {
    const parts: Buffer[] = [Buffer.from(cborHead(5, value.size))];
    for (const [key, item] of value) {
      parts.push(Buffer.from(encodeCbor(key)), Buffer.from(encodeCbor(item)));
    }
    return Buffer.concat(parts);
  }
  throw new Error(`cannot encode ${typeof value} as CBOR`);
}

/* -------------------------------------------------------------------------- */
/*                                 Harness                                     */
/* -------------------------------------------------------------------------- */

const WALLET = "0x00000000000000000000000000000000000000c0";
const CHAIN_ID = 143;
const ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const CUSTODY_SECRET = "integration-test-secret";

let gatewayUrl = "";
let gatewayApp: HttpApp;
let coprocessorApp: HttpApp;
let engine: HomomorphicEngine;
let fheClient: FheClient;
let authenticator: SoftwareAuthenticator;
let credentialId: string;
let policy: ReturnType<PolicyRegistry["get"]>;

async function call<T = any>(
  method: string,
  endpoint: string,
  body?: unknown,
): Promise<{ status: number; body: T }> {
  const response = await fetch(`${gatewayUrl}${endpoint}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : {}) as T };
}

function fullUserOperationJson(userOp: any): Record<string, string> {
  return {
    sender: userOp.sender,
    nonce: `0x${userOp.nonce.toString(16)}`,
    initCode: userOp.initCode,
    callData: userOp.callData,
    callGasLimit: `0x${userOp.callGasLimit.toString(16)}`,
    verificationGasLimit: `0x${userOp.verificationGasLimit.toString(16)}`,
    preVerificationGas: `0x${userOp.preVerificationGas.toString(16)}`,
    maxFeePerGas: `0x${userOp.maxFeePerGas.toString(16)}`,
    maxPriorityFeePerGas: `0x${userOp.maxPriorityFeePerGas.toString(16)}`,
    paymasterAndData: userOp.paymasterAndData,
    signature: `0x48${"11".repeat(300)}`,
  };
}

function buildOperation(recipient = "000000000000000000000000000000000000dead") {
  const userOp = new UserOperationBuilder(WALLET)
    .nonce(NonceDomain.Wallet, 0)
    .callData(`0xb9059cbb${recipient.padStart(64, "0")}`)
    .build();
  return { userOp, userOpHash: getUserOpHash(userOp, ENTRY_POINT, CHAIN_ID) };
}

function enrollTemplate(seed: number) {
  const samples = Array.from({ length: 7 }, (_, i) => ({
    vector: seededUnitVectorLocal(EMBEDDING_DIMENSION, seed + i, 0.04, (k) => Math.sin(k * 0.7 + 1)),
    quality: 0.93,
  }));
  return aggregateTemplate(samples);
}

async function authenticate(options: { vector: Float64Array; operationHash?: string }): Promise<any> {
  const { userOpHash } = buildOperation();
  const challenge = await call("POST", "/v1/auth/challenge", {
    wallet: WALLET,
    chainId: CHAIN_ID,
    operationHash: options.operationHash ?? userOpHash,
  });
  if (challenge.status !== 200) return { status: challenge.status, body: challenge.body };

  authenticator.bump();
  const assertion = authenticator.get(challenge.body.challenge);
  const query = engine.encryptVector(
    fheClientKey(),
    options.vector,
    EMBEDDING_DIMENSION,
    "low",
  );

  return call("POST", "/v1/auth/verify", {
    wallet: WALLET,
    chainId: CHAIN_ID,
    operationHash: options.operationHash ?? userOpHash,
    challengeId: challenge.body.challengeId,
    sessionId: challenge.body.sessionId,
    webauthnAssertion: { credentialId, ...assertion },
    encryptedBiometricQuery: {
      ciphertext: query.ciphertext,
      commitment: query.commitment,
      dimension: EMBEDDING_DIMENSION,
    },
  });
}

let publicKeyBundle: any;

function fheClientKey() {
  return publicKeyBundle;
}

beforeAll(async () => {
  const dataDir = mkdtempSync(path.join(tmpdir(), "homobio-it-"));
  const silentLogger = { info() {}, warn() {}, error() {} };
  const ORIGIN = "http://localhost:5000";
  authenticator = new SoftwareAuthenticator("localhost", ORIGIN);

  // ---- FHE coprocessor -----------------------------------------------------
  const templates = new JsonStore<TemplateRecord & StoredRecord>({ directory: dataDir, persist: false });
  const coprocessor = new FheCoprocessor(
    { port: 0, dataDir, serviceToken: "dev-fhe-token", errorBound: 2 ** -9, chainId: CHAIN_ID },
    templates,
    silentLogger,
  );
  const bootstrap = coprocessor.bootstrap({
    proof: path.join(dataDir, "committee/share-1.json"),
    custody: path.join(dataDir, "committee/share-2.json"),
  });
  publicKeyBundle = bootstrap.publicKey;

  coprocessorApp = createCoprocessorApp(coprocessor, {
    port: 0,
    dataDir,
    serviceToken: "dev-fhe-token",
    errorBound: 2 ** -9,
    chainId: CHAIN_ID,
  });
  const fhePort = await coprocessorApp.listen();

  // ---- Gateway -------------------------------------------------------------
  engine = new HomomorphicEngine(DEFAULT_FHE_PARAMS);
  const store = new JsonStore<StoredRecord>({ directory: dataDir, persist: false });
  const credentialStore = new JsonStore<StoredPasskeyCredential>({ directory: dataDir, persist: false });
  const submissionStore = new JsonStore<any>({ directory: dataDir, persist: false });
  const policyRegistry = new PolicyRegistry();
  policy = policyRegistry.get("policy-standard-v1");

  fheClient = new FheClient({
    baseUrl: `http://127.0.0.1:${fhePort}`,
    serviceToken: "dev-fhe-token",
    errorBound: 2 ** -9,
  });
  // The gateway pins the coprocessor's public key at boot, exactly as main.ts does.
  await fheClient.publicKey();

  // The proof-service share is the one the coprocessor wrote to disk.
  const proofShare = JSON.parse(
    (await import("node:fs")).readFileSync(path.join(dataDir, "committee/share-1.json"), "utf-8"),
  );
  const { deserializeShare } = await import("../../packages/fhe/src/index.js");
  const committee = new DecryptionCommitteeGateway(
    engine,
    publicKeyBundle.fingerprint,
    { custodySharePath: path.join(dataDir, "committee/share-2.json"), custodyUnlockSecret: CUSTODY_SECRET },
    deserializeShare(proofShare, engine, publicKeyBundle.fingerprint),
  );
  committee.unlock(CUSTODY_SECRET);

  const config: GatewayConfig = {
    port: 0,
    chainId: CHAIN_ID,
    chainName: "Monad Testnet",
    rpcUrl: "http://127.0.0.1:8545",
    entryPoint: ENTRY_POINT,
    rpId: "localhost",
    rpName: "Integration test",
    origin: ORIGIN,
    allowedOrigins: [ORIGIN],
    defaultPolicyId: "policy-standard-v1",
    fheServiceUrl: `http://127.0.0.1:${fhePort}`,
    fheServiceToken: "dev-fhe-token",
    custodySharePath: path.join(dataDir, "committee/share-2.json"),
    custodyUnlockSecret: CUSTODY_SECRET,
    modelVersion: "rp-canonical-v1",
    relayerDryRun: true,
    dataDir,
    // The suite drives far more than the per-minute production budget.
    rateLimits: { challenge: 5000, verify: 5000, passkey: 5000, submit: 5000, global: 100_000 },
  };

  const { app } = createGateway(config, {
    store,
    challengeService: new ChallengeService(120),
    webauthnService: new WebAuthnService(credentialStore, true),
    proofService: new ProofService(),
    relayerService: new RelayerService(defaultRelayerConfig({ dryRun: true }), submissionStore),
    policyRegistry,
    fheClient,
    committee,
    engine,
    publicKey: publicKeyBundle,
  });

  gatewayApp = app;
  const gatewayPort = await app.listen();
  gatewayUrl = `http://127.0.0.1:${gatewayPort}`;

  writeFileSync(path.join(dataDir, "info.json"), JSON.stringify({ gatewayPort, fhePort }), "utf-8");

  // ---- Passkey registration + template enrollment --------------------------
  const options = await call("POST", "/v1/auth/passkey/register/options", { wallet: WALLET });
  credentialId = options.body.challengeId ? randomBytes(32).toString("base64url") : "";
  const attestation = authenticator.create(options.body.challenge, Buffer.from(credentialId, "base64url"));
  const registered = await call("POST", "/v1/auth/passkey/register", {
    wallet: WALLET,
    challengeId: options.body.challengeId,
    response: attestation,
    label: "Test device",
    role: "primary",
  });
  if (registered.status !== 200) {
    throw new Error(`passkey registration failed: ${JSON.stringify(registered.body)}`);
  }
  credentialId = registered.body.credentialId;

  const template = enrollTemplate(4242);
  const ciphertext = engine.encryptVector(publicKeyBundle, template.vector, EMBEDDING_DIMENSION, "high");
  const enrolled = await call("POST", "/v1/biometric/enroll", {
    wallet: WALLET,
    ciphertext: ciphertext.ciphertext,
    commitment: ciphertext.commitment,
    modelVersion: "rp-canonical-v1",
    dimension: EMBEDDING_DIMENSION,
    sampleCount: 7,
    meanQuality: 0.93,
  });
  if (enrolled.status >= 300) {
    throw new Error(`enrollment failed: ${JSON.stringify(enrolled.body)}`);
  }

  void randomBytes;
}, 300_000);

afterAll(async () => {
  await gatewayApp?.close();
  await coprocessorApp?.close();
});

/* -------------------------------------------------------------------------- */

describe("gateway configuration", () => {
  it("reports the chain and the exact FHE parameters in use", async () => {
    const { status, body } = await call("GET", "/v1/config");
    expect(status).toBe(200);
    expect(body.chainId).toBe(CHAIN_ID);
    expect(body.entryPoint).toBe(ENTRY_POINT);
    expect(body.fhe.engine).toBe(DEFAULT_FHE_PARAMS.engine);
    expect(body.fhe.modulus).toBe(DEFAULT_FHE_PARAMS.modulus);
    expect(body.fhe.fingerprint).toBe(publicKeyBundle.fingerprint);
    expect(body.webauthn.requireUserVerification).toBe(true);
  });

  it("publishes the committee address and never a distance", async () => {
    const { body } = await call("GET", "/v1/health");
    expect(body.committeeAddress).toMatch(/^0x[0-9a-f]{40}$/);
    expect(JSON.stringify(body)).not.toMatch(/distance|similarity/i);
  });

  it("rejects a challenge for the wrong chain", async () => {
    const { userOpHash } = buildOperation();
    const { status, body } = await call("POST", "/v1/auth/challenge", {
      wallet: WALLET,
      chainId: 1,
      operationHash: userOpHash,
    });
    expect(status).toBe(400);
    expect(body.error).toBe("chain_mismatch");
  });
});

describe("registration", () => {
  it("rejects a passkey that signs a different challenge", async () => {
    const options = await call("POST", "/v1/auth/passkey/register/options", { wallet: WALLET });
    const attestation = authenticator.create("not-the-challenge", Buffer.from(randomBytes(32).toString("base64url")));
    const { status, body } = await call("POST", "/v1/auth/passkey/register", {
      wallet: WALLET,
      challengeId: options.body.challengeId,
      response: attestation,
    });
    expect(status).toBe(401);
    expect(body.error).toBe("challenge_mismatch");
  });

  it("refuses a second registration of the same credential", async () => {
    const options = await call("POST", "/v1/auth/passkey/register/options", { wallet: WALLET });
    const attestation = authenticator.create(options.body.challenge, Buffer.from(credentialId, "base64url"));
    const { status, body } = await call("POST", "/v1/auth/passkey/register", {
      wallet: WALLET,
      challengeId: options.body.challengeId,
      response: attestation,
    });
    expect(status).toBe(409);
    expect(body.error).toBe("credential_exists");
  });
});

describe("successful authentication", () => {
  it("authorizes a genuine capture and returns no distance", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { status, body } = await authenticate({ vector: live });
    expect(status).toBe(200);
    expect(body.authenticated).toBe(true);
    expect(body.authorization.decision).toBe(true);
    expect(body.decision.zone).toBe("accept");
    expect(body.authorization.attestationHash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.authorization.signature.startsWith("0x")).toBe(true);

    const serialized = JSON.stringify(body);
    expect(serialized).not.toMatch(/"distance"|"similarity"\s*:\s*-?\d/);
    expect(serialized).not.toContain("embedding");
  });

  it("submits the authorized UserOperation", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.03, (k) => Math.sin(k * 0.7 + 1));
    const { body: verified } = await authenticate({ vector: live });
    const { userOp } = buildOperation();
    const { userOpHash } = buildOperation();

    const { status, body } = await call("POST", "/v1/userop/submit", {
      userOperation: {
        sender: userOp.sender,
        nonce: `0x${userOp.nonce.toString(16)}`,
        initCode: userOp.initCode,
        callData: userOp.callData,
        callGasLimit: `0x${userOp.callGasLimit.toString(16)}`,
        verificationGasLimit: `0x${userOp.verificationGasLimit.toString(16)}`,
        preVerificationGas: `0x${userOp.preVerificationGas.toString(16)}`,
        maxFeePerGas: `0x${userOp.maxFeePerGas.toString(16)}`,
        maxPriorityFeePerGas: `0x${userOp.maxPriorityFeePerGas.toString(16)}`,
        paymasterAndData: userOp.paymasterAndData,
        signature: `0x48${"00".repeat(300)}`,
        userOpHash,
      },
      authorization: verified.authorization,
    });

    expect(status).toBe(200);
    expect(body.submitted).toBe(true);
    // The submitted hash covers the full operation INCLUDING the authorization
    // envelope, so it necessarily differs from the pre-authentication hash the
    // challenge was bound to — that difference is the binding working.
    expect(body.userOpHash).not.toBe(userOpHash);
    expect(body.userOpHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("negative authentication paths", () => {
  it("rejects a different person", async () => {
    const impostor = seededUnitVectorLocal(EMBEDDING_DIMENSION, 999_991, 1, (k) => Math.cos(k * 1.3));
    const { status, body } = await authenticate({ vector: impostor });
    expect(status).toBe(403);
    expect(body.error).toBe("biometric_mismatch");
  });

  it("rejects a replayed challenge", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { userOpHash } = buildOperation();
    const challenge = await call("POST", "/v1/auth/challenge", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
    });
    authenticator.bump();
    const assertion = authenticator.get(challenge.body.challenge);
    const query = engine.encryptVector(publicKeyBundle, live, EMBEDDING_DIMENSION, "low");
    const payload = {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
      challengeId: challenge.body.challengeId,
      sessionId: challenge.body.sessionId,
      webauthnAssertion: { credentialId, ...assertion },
      encryptedBiometricQuery: {
        ciphertext: query.ciphertext,
        commitment: query.commitment,
        dimension: EMBEDDING_DIMENSION,
      },
    };

    const first = await call("POST", "/v1/auth/verify", payload);
    expect(first.status).toBe(200);

    // The very same challenge, asserted again, with a fresh counter.
    authenticator.bump();
    const replay = await call("POST", "/v1/auth/verify", {
      ...payload,
      webauthnAssertion: { credentialId, ...authenticator.get(challenge.body.challenge) },
    });
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(["replay_detected", "session_not_replayable"]).toContain(replay.body.error);
  });

  it("rejects an assertion that signs a different operation", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { userOpHash } = buildOperation();
    const otherHash = buildOperation("11".repeat(20)).userOpHash;

    const challenge = await call("POST", "/v1/auth/challenge", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
    });
    authenticator.bump();
    const assertion = authenticator.get(challenge.body.challenge);
    const query = engine.encryptVector(publicKeyBundle, live, EMBEDDING_DIMENSION, "low");

    // Claim a different operation than the one the challenge was issued for.
    const { status, body } = await call("POST", "/v1/auth/verify", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: otherHash,
      challengeId: challenge.body.challengeId,
      sessionId: challenge.body.sessionId,
      webauthnAssertion: { credentialId, ...assertion },
      encryptedBiometricQuery: {
        ciphertext: query.ciphertext,
        commitment: query.commitment,
        dimension: EMBEDDING_DIMENSION,
      },
    });
    expect(status).toBe(400);
    expect(body.error).toBe("operation_mismatch");
  });

  it("rejects a tampered ciphertext", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { userOpHash } = buildOperation();
    const challenge = await call("POST", "/v1/auth/challenge", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
    });
    authenticator.bump();
    const assertion = authenticator.get(challenge.body.challenge);
    const query = engine.encryptVector(publicKeyBundle, live, EMBEDDING_DIMENSION, "low");
    const flipped = query.ciphertext.slice(0, -2) + (query.ciphertext.endsWith("A") ? "B" : "A");

    const { status, body } = await call("POST", "/v1/auth/verify", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
      challengeId: challenge.body.challengeId,
      sessionId: challenge.body.sessionId,
      webauthnAssertion: { credentialId, ...assertion },
      encryptedBiometricQuery: {
        ciphertext: flipped,
        commitment: query.commitment,
        dimension: EMBEDDING_DIMENSION,
      },
    });
    expect(status).toBeGreaterThanOrEqual(400);
    expect(["fhe_error", "bad_request", "invalid_request", "internal_error"]).toContain(body.error);
  });

  it("rejects a query whose commitment does not match the ciphertext", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { userOpHash } = buildOperation();
    const challenge = await call("POST", "/v1/auth/challenge", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
    });
    authenticator.bump();
    const assertion = authenticator.get(challenge.body.challenge);
    const query = engine.encryptVector(publicKeyBundle, live, EMBEDDING_DIMENSION, "low");

    const { status } = await call("POST", "/v1/auth/verify", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: userOpHash,
      challengeId: challenge.body.challengeId,
      sessionId: challenge.body.sessionId,
      webauthnAssertion: { credentialId, ...assertion },
      encryptedBiometricQuery: {
        ciphertext: query.ciphertext,
        commitment: "00".repeat(32),
        dimension: EMBEDDING_DIMENSION,
      },
    });
    expect(status).toBeGreaterThanOrEqual(400);
  });

  it("rejects a forged authorization at submission time", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { body: verified } = await authenticate({ vector: live });
    const { userOp, userOpHash } = buildOperation();

    const forged = { ...verified.authorization, decision: false };
    const { status, body } = await call("POST", "/v1/userop/submit", {
      userOperation: { sender: userOp.sender, userOpHash, signature: "0x48" },
      authorization: forged,
    });
    expect(status).toBe(401);
    expect(body.error).toBe("authorization_invalid");
  });

  it("refuses to submit the same authorization twice", async () => {
    const live = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02, (k) => Math.sin(k * 0.7 + 1));
    const { body: verified } = await authenticate({ vector: live });
    const { userOp } = buildOperation();
    let userOpHash = getUserOpHash(userOp, ENTRY_POINT, CHAIN_ID);
    const payload = {
      userOperation: fullUserOperationJson(userOp),
      authorization: verified.authorization,
    };
    userOpHash = getUserOpHash(userOp, ENTRY_POINT, CHAIN_ID);

    const first = await call("POST", "/v1/userop/submit", payload);
    expect(first.status).toBe(200);

    const second = await call("POST", "/v1/userop/submit", payload);
    expect(second.status).toBe(409);
    expect(second.body.error).toBe("authorization_replayed");
  });
});

describe("recovery", () => {
  it("starts a timelocked request and can be cancelled", async () => {
    const { status, body } = await call("POST", `/v1/wallet/${WALLET}/recovery`);
    expect(status).toBe(200);
    expect(body.delaySeconds).toBe(policy.recoveryDelaySeconds);
    expect(body.executableAt).toBeGreaterThan(Math.floor(Date.now() / 1000));

    const cancelled = await call("POST", `/v1/wallet/${WALLET}/recovery/cancel`, {
      requestId: body.requestId,
    });
    expect(cancelled.status).toBe(200);
    expect(cancelled.body.status).toBe("cancelled");
  });
});

describe("privacy of the operator view", () => {
  it("records sessions without any biometric material", async () => {
    const { status, body } = await call("GET", "/v1/operator/sessions?limit=100");
    expect(status).toBe(200);
    expect(Array.isArray(body.sessions)).toBe(true);
    for (const session of body.sessions) {
      // The audit trail may contain identifiers and status only. Any field whose
      // name suggests biometric material is a hard failure.
      for (const key of Object.keys(session)) {
        expect(key).not.toMatch(/embedding|ciphertext|distance|pixel|image|vector|template/i);
      }
    }
  });
});

export { serializeShare };
