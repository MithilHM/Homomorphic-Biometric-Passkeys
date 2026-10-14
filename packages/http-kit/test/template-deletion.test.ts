/**
 * Template deletion proof, end to end (M3.5, gate 9).
 *
 * There was no delete path before this test: enrollment only retired
 * predecessors. `DELETE /v1/wallet/:address/template` must erase every
 * coprocessor record for the wallet such that:
 *   1. the store holds no record for the wallet (record gone);
 *   2. the template commitment no longer resolves (404 template_not_found);
 *   3. a subsequent evaluation fails with template_not_found;
 *   4. the gateway reports the wallet as not enrolled and refuses challenges.
 *
 * Boots the real coprocessor and the real gateway in-process and drives them
 * over loopback HTTP. Enrollment goes through the real coprocessor endpoint;
 * the wallet account is created through the real gateway passkey-options
 * endpoint so the gateway wallet view is meaningful end to end.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { JsonStore, memoryStore, type StoredRecord } from "../../store/src/index.js";
import type { HttpApp } from "../src/index.js";
import { ChallengeService } from "../../../services/challenge-service/src/index.js";
import { WebAuthnService } from "../../../services/webauthn-service/src/index.js";
import { ProofService } from "../../../services/proof-service/src/index.js";
import { RelayerService, defaultRelayerConfig } from "../../../services/relayer-service/src/index.js";
import {
  DEFAULT_FHE_PARAMS,
  HomomorphicEngine,
  deserializeShare,
} from "../../../packages/fhe/src/index.js";
import {
  EMBEDDING_DIMENSION,
  seededUnitVectorLocal,
} from "../../../packages/biometric-client/src/index.js";
import type { StoredPasskeyCredential } from "../../../packages/protocol-types/src/index.js";
import {
  FheCoprocessor,
  createCoprocessorApp,
  type TemplateRecord,
} from "../../../services/fhe-service/src/coprocessor.js";
import { FheClient } from "../../../services/api-gateway/src/fhe-client.js";
import { PolicyRegistry } from "../../../services/api-gateway/src/policy.js";
import { DecryptionCommitteeGateway } from "../../../services/api-gateway/src/committee.js";
import { createGateway, type GatewayConfig } from "../../../services/api-gateway/src/app.js";

const WALLET = "0x00000000000000000000000000000000000000d1";
const CHAIN_ID = 143;
const ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const SERVICE_TOKEN = "deletion-test-token";
const CUSTODY_SECRET = "deletion-test-secret";
const ORIGIN = "http://localhost:5000";

let gatewayUrl = "";
let coprocessorUrl = "";
let gatewayApp: HttpApp;
let coprocessorApp: HttpApp;
let engine: HomomorphicEngine;
let publicKeyBundle: any;
let templates: JsonStore<TemplateRecord & StoredRecord>;

async function gcall<T = any>(
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

async function fcall<T = any>(
  method: string,
  endpoint: string,
  body?: unknown,
): Promise<{ status: number; body: T }> {
  const response = await fetch(`${coprocessorUrl}${endpoint}`, {
    method,
    headers: { "content-type": "application/json", authorization: `Bearer ${SERVICE_TOKEN}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : {}) as T };
}

function templateCiphertext(seed: number) {
  const vector = seededUnitVectorLocal(EMBEDDING_DIMENSION, seed, 0.04, (k) => Math.sin(k * 0.7 + 1));
  return engine.encryptVector(publicKeyBundle, vector, EMBEDDING_DIMENSION, "high");
}

function queryCiphertext(seed: number) {
  const vector = seededUnitVectorLocal(EMBEDDING_DIMENSION, seed, 0.02, (k) => Math.sin(k * 0.7 + 1));
  return engine.encryptVector(publicKeyBundle, vector, EMBEDDING_DIMENSION, "low");
}

async function enrollViaCoprocessor(seed: number): Promise<{ status: number; body: any }> {
  const ciphertext = templateCiphertext(seed);
  return fcall("POST", "/v1/fhe/enroll", {
    wallet: WALLET,
    ciphertext: ciphertext.ciphertext,
    commitment: ciphertext.commitment,
    modelVersion: "rp-canonical-v1",
    dimension: EMBEDDING_DIMENSION,
    templateVersion: 1,
    sampleCount: 7,
    meanQuality: 0.93,
  });
}

beforeAll(async () => {
  const dataDir = mkdtempSync(path.join(tmpdir(), "homobio-del-"));
  const silentLogger = { info() {}, warn() {}, error() {} };

  templates = memoryStore<TemplateRecord & StoredRecord>();
  const coprocessor = new FheCoprocessor(
    { port: 0, dataDir, serviceToken: SERVICE_TOKEN, errorBound: 2 ** -9, chainId: CHAIN_ID },
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
    serviceToken: SERVICE_TOKEN,
    errorBound: 2 ** -9,
    chainId: CHAIN_ID,
  });
  coprocessorUrl = `http://127.0.0.1:${await coprocessorApp.listen()}`;

  engine = new HomomorphicEngine(DEFAULT_FHE_PARAMS);
  const fheClient = new FheClient({
    baseUrl: coprocessorUrl,
    serviceToken: SERVICE_TOKEN,
    errorBound: 2 ** -9,
  });
  await fheClient.publicKey();

  const proofShare = JSON.parse(
    (await import("node:fs")).readFileSync(path.join(dataDir, "committee/share-1.json"), "utf-8"),
  );
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
    rpName: "Deletion test",
    origin: ORIGIN,
    allowedOrigins: [ORIGIN],
    defaultPolicyId: "policy-standard-v1",
    fheServiceUrl: coprocessorUrl,
    fheServiceToken: SERVICE_TOKEN,
    custodySharePath: path.join(dataDir, "committee/share-2.json"),
    custodyUnlockSecret: CUSTODY_SECRET,
    modelVersion: "rp-canonical-v1",
    relayerDryRun: true,
    dataDir,
    rateLimits: { challenge: 5000, verify: 5000, passkey: 5000, submit: 5000, global: 100_000 },
  };

  const { app } = createGateway(config, {
    store: memoryStore<StoredRecord>(),
    challengeService: new ChallengeService(120),
    webauthnService: new WebAuthnService(memoryStore<StoredPasskeyCredential>(), true),
    proofService: new ProofService(),
    relayerService: new RelayerService(defaultRelayerConfig({ dryRun: true }), memoryStore<any>()),
    policyRegistry: new PolicyRegistry(),
    fheClient,
    committee,
    engine,
    publicKey: publicKeyBundle,
  });
  gatewayApp = app;
  gatewayUrl = `http://127.0.0.1:${await app.listen()}`;

  // Create the gateway account so the wallet view is meaningful end to end.
  const options = await gcall("POST", "/v1/auth/passkey/register/options", { wallet: WALLET });
  expect(options.status).toBe(200);
}, 120_000);

afterAll(async () => {
  await gatewayApp?.close();
  await coprocessorApp?.close();
});

describe("template deletion end to end", () => {
  it("enrolls, deletes, and proves erasure at every layer", async () => {
    const enrolled = await enrollViaCoprocessor(4242);
    expect(enrolled.status).toBe(200);
    const commitment = enrolled.body.commitment as string;
    expect(commitment).toMatch(/^0x[0-9a-fA-F]{64}$/);

    // Sanity: the wallet resolves as enrolled before deletion, which also
    // primes the gateway's 5s template cache - deletion must invalidate it.
    const before = await gcall("GET", `/v1/wallet/${WALLET}`);
    expect(before.status).toBe(200);
    expect(before.body.biometric?.enrolled).toBe(true);
    expect(before.body.biometric?.commitment).toBe(commitment);

    const deleted = await gcall("DELETE", `/v1/wallet/${WALLET}/template`);
    expect(deleted.status).toBe(200);
    expect(deleted.body).toMatchObject({ deleted: true, templatesRemoved: 1 });
    expect(JSON.stringify(deleted.body)).not.toContain("ciphertext");

    // 1. Record gone from the coprocessor store (every status, not just active).
    expect(templates.list("templates", (t) => t.wallet === WALLET.toLowerCase())).toHaveLength(0);

    // 2. Commitment unresolvable at the coprocessor API.
    const metadata = await fcall("GET", `/v1/fhe/template/${WALLET}`);
    expect(metadata.status).toBe(404);
    expect(metadata.body.error).toBe("template_not_found");

    // 3. Subsequent evaluation fails with template_not_found.
    const query = queryCiphertext(4242);
    const evaluated = await fcall("POST", "/v1/fhe/evaluate", {
      wallet: WALLET,
      queryCiphertext: query.ciphertext,
      queryCommitment: query.commitment,
      dimension: EMBEDDING_DIMENSION,
    });
    expect(evaluated.status).toBe(404);
    expect(evaluated.body.error).toBe("template_not_found");

    // 4. Gateway agrees: not enrolled, and no challenge without a template.
    const after = await gcall("GET", `/v1/wallet/${WALLET}`);
    expect(after.status).toBe(200);
    expect(after.body.biometric).toMatchObject({ enrolled: false });

    const challenge = await gcall("POST", "/v1/auth/challenge", {
      wallet: WALLET,
      chainId: CHAIN_ID,
      operationHash: "ab".repeat(32),
    });
    expect(challenge.status).toBe(409);
    expect(challenge.body.error).toBe("template_required");
  });

  it("returns template_not_found when nothing is enrolled", async () => {
    const again = await gcall("DELETE", `/v1/wallet/${WALLET}/template`);
    expect(again.status).toBe(404);
    expect(again.body.error).toBe("template_not_found");
  });

  it("erases retired predecessors too, and leaves a clean state for re-enrollment", async () => {
    // Two enrollments: the first is retired, the second active.
    expect((await enrollViaCoprocessor(111)).status).toBe(200);
    expect((await enrollViaCoprocessor(222)).status).toBe(200);
    expect(templates.count("templates", (t) => t.wallet === WALLET.toLowerCase())).toBe(2);

    const deleted = await gcall("DELETE", `/v1/wallet/${WALLET}/template`);
    expect(deleted.status).toBe(200);
    expect(deleted.body).toMatchObject({ deleted: true, templatesRemoved: 2 });
    expect(templates.count("templates", (t) => t.wallet === WALLET.toLowerCase())).toBe(0);

    const reenrolled = await enrollViaCoprocessor(333);
    expect(reenrolled.status).toBe(200);
    const wallet = await gcall("GET", `/v1/wallet/${WALLET}`);
    expect(wallet.body.biometric?.enrolled).toBe(true);

    // Leave the wallet clean for no other test to trip over.
    expect((await gcall("DELETE", `/v1/wallet/${WALLET}/template`)).status).toBe(200);
  });

  it("rejects a malformed address without reaching the coprocessor", async () => {
    const res = await gcall("DELETE", "/v1/wallet/not-an-address/template");
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
  });
});
