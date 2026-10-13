/**
 * API Gateway process entry point.
 *
 * Wires the challenge, WebAuthn, FHE, proof and relayer services together and
 * serves the built web application, so `npm run dev` brings up the whole system
 * with a single command.
 */

import path from "node:path";
import { existsSync } from "node:fs";
import { JsonStore, type StoredRecord } from "@homobio/store";
import type { StoredPasskeyCredential } from "@homobio/protocol-types";
import type { SubmissionRecord } from "@homobio/relayer-service";
import { createLogger } from "@homobio/http-kit";
import { ChallengeService } from "@homobio/challenge-service";
import { WebAuthnService } from "@homobio/webauthn-service";
import { ProofService } from "@homobio/proof-service";
import { RelayerService, defaultRelayerConfig } from "@homobio/relayer-service";
import { HomomorphicEngine, DEFAULT_FHE_PARAMS, deserializeShare, type ShareFile } from "@homobio/fhe";
import { PolicyRegistry } from "./policy.js";
import { FheClient } from "./fhe-client.js";
import { DecryptionCommitteeGateway } from "./committee.js";
import { createGateway, type GatewayConfig } from "./app.js";
import { serveStatic, ensureWebBundle } from "./static.js";

const logger = createLogger("api-gateway");

try {
  process.loadEnvFile?.();
} catch {
  // .env is optional
}

const DATA_DIR = process.env.HOMOBIO_DATA_DIR ?? path.resolve(process.cwd(), ".data");
const PORT = Number(process.env.PORT ?? 5000);
const CHAIN_ID = Number(process.env.CHAIN_ID ?? 143);
const RP_ID = process.env.WEBAUTHN_RP_ID ?? "localhost";
const ORIGIN = process.env.WEBAUTHN_ORIGIN ?? `http://localhost:${PORT}`;
const FHE_URL = process.env.FHE_SERVICE_URL ?? "http://127.0.0.1:5001";
const FHE_TOKEN = process.env.FHE_SERVICE_TOKEN ?? "dev-fhe-token";
const CUSTODY_PATH = path.join(DATA_DIR, "committee", "share-2-custody.json");
const PROOF_SHARE_PATH = path.join(DATA_DIR, "committee", "share-1-proof.json");

const config: GatewayConfig = {
  port: PORT,
  chainId: CHAIN_ID,
  chainName: process.env.CHAIN_NAME ?? "Monad Testnet",
  rpcUrl: process.env.MONAD_RPC ?? "https://testnet-rpc.monad.xyz",
  entryPoint: process.env.MONAD_ENTRY_POINT ?? "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
  factoryAddress: process.env.ACCOUNT_FACTORY_ADDRESS,
  verifierAddress: process.env.AUTHORIZATION_VERIFIER_ADDRESS,
  registryAddress: process.env.PROOF_VERIFIER_REGISTRY_ADDRESS,
  rpId: RP_ID,
  rpName: process.env.WEBAUTHN_RP_NAME ?? "Homomorphic Biometric Passkeys",
  origin: ORIGIN,
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? ORIGIN).split(",").map((s) => s.trim()).filter(Boolean),
  defaultPolicyId: process.env.DEFAULT_POLICY_ID ?? "policy-standard-v1",
  fheServiceUrl: FHE_URL,
  fheServiceToken: FHE_TOKEN,
  custodySharePath: CUSTODY_PATH,
  custodyUnlockSecret: process.env.CUSTODY_UNLOCK_SECRET ?? "dev-custody",
  modelVersion: process.env.MODEL_VERSION ?? "rp-canonical-v1",
  relayerDryRun: process.env.RELAYER_DRY_RUN !== "false",
  bundlerUrl: process.env.BUNDLER_URL,
  dataDir: DATA_DIR,
};

const store = new JsonStore<StoredRecord>({ directory: path.join(DATA_DIR, "gateway"), fileName: "state.json" });
const credentialStore = new JsonStore<StoredPasskeyCredential>({
  directory: path.join(DATA_DIR, "gateway"),
  fileName: "credentials.json",
});
const relayerStore = new JsonStore<SubmissionRecord>({
  directory: path.join(DATA_DIR, "gateway"),
  fileName: "submissions.json",
});
const challengeService = new ChallengeService(120);
const webauthnService = new WebAuthnService(credentialStore, true);
const proofService = new ProofService(process.env.PROOF_SERVICE_SECRET_PEM);
const relayerService = new RelayerService(defaultRelayerConfig({ dryRun: config.relayerDryRun }), relayerStore);
const policyRegistry = new PolicyRegistry();
const fheClient = new FheClient({ baseUrl: FHE_URL, serviceToken: FHE_TOKEN, errorBound: Number(process.env.FHE_ERROR_BOUND ?? 2 ** -9) });
const engine = new HomomorphicEngine(DEFAULT_FHE_PARAMS);

// The gateway cannot start without the coprocessor: a degraded FHE path must
// fail loudly rather than silently downgrade the security posture.
let publicKey;
try {
  publicKey = await fheClient.publicKey();
  logger.info("loaded FHE public key", { fingerprint: publicKey.fingerprint, keyVersion: publicKey.keyVersion });
} catch (error) {
  logger.error("FHE coprocessor is unreachable; start services/fhe-service first", {
    error: String(error),
    url: FHE_URL,
  });
  process.exit(1);
}

if (!existsSync(PROOF_SHARE_PATH)) {
  logger.error("committee share for the proof service is missing; start the FHE coprocessor first", {
    path: PROOF_SHARE_PATH,
  });
  process.exit(1);
}
let proofShare;
try {
  proofShare = deserializeShare(
    JSON.parse((await import("node:fs")).readFileSync(PROOF_SHARE_PATH, "utf-8")) as ShareFile,
    engine,
    publicKey.fingerprint,
  );
} catch (error) {
  // The overwhelmingly common cause is a half-restarted stack: an old coprocessor
  // still holding port 5001 while a new one wrote a new key set to disk.
  logger.error("committee shares on disk do not match the running FHE coprocessor", {
    error: String(error),
    expectedFingerprint: publicKey.fingerprint,
    sharePath: PROOF_SHARE_PATH,
    hint: "stop every homobio process, delete $HOMOBIO_DATA_DIR, and start the coprocessor before the gateway",
  });
  process.exit(1);
}

const committee = new DecryptionCommitteeGateway(engine, publicKey.fingerprint, {
  custodySharePath: CUSTODY_PATH,
  custodyUnlockSecret: config.custodyUnlockSecret,
}, proofShare);

// Unlock the committee when the custody secret is supplied in the environment;
// otherwise an operator must POST /v1/operator/committee/unlock explicitly.
if (process.env.CUSTODY_UNLOCK_ON_BOOT === "true") {
  committee.unlock(process.env.CUSTODY_UNLOCK_SECRET ?? "dev-custody");
  logger.warn("decryption committee unlocked at boot", { threshold: 3 });
}

const { app, metrics } = createGateway(config, {
  store,
  challengeService,
  webauthnService,
  proofService,
  relayerService,
  policyRegistry,
  fheClient,
  committee,
  engine,
  publicKey,
});

await ensureWebBundle(logger);
serveStatic(app, path.resolve(process.cwd(), "apps/web/dist"), logger);

const port = await app.listen();
logger.info("api gateway ready", { port, chainId: CHAIN_ID, rpId: RP_ID, origin: ORIGIN });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void (async () => {
      await store.settled();
      await app.close();
      logger.info("shutdown complete", { metrics });
      process.exit(0);
    })();
  });
}
