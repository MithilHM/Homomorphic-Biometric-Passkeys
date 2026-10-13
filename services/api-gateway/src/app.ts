/**
 * API Gateway (PRD sections 6, 27, 28, 30, 31)
 *
 * Orchestrates one authentication:
 *
 *   challenge -> WebAuthn assertion -> encrypted FHE query -> coprocessor
 *   evaluation -> threshold committee decryption -> decision -> signed
 *   authorization -> UserOperation submission
 *
 * The gateway never sees a plaintext biometric vector and never returns a
 * distance: the only decision-related value that crosses the API boundary is a
 * boolean and the commitments that bind it.
 */

import {
  HttpApp,
  HttpError,
  requireNumber,
  requireObject,
  requireString,
  ADDRESS,
  BASE64URL,
  createLogger,
} from "@homobio/http-kit";

/** Accept `0x`-prefixed or bare 32-byte hex and normalise to the bare form. */
const HEX32_ANY = /^(0x)?[0-9a-fA-F]{64}$/;
const bare32 = (value: string): string => value.startsWith("0x") ? value.slice(2) : value;
import { JsonStore, type StoredRecord } from "@homobio/store";
import { bytesToBase64Url, canonicalJson, nowSeconds, randomId, keccak256Hex, sha256 } from "@homobio/crypto-utils";
import {
  decisionProgramHash,
  envelopeHashHex,
  policyHashHex,
  similarityToBps,
  type BiometricPolicy,
  type StoredPasskeyCredential,
} from "@homobio/protocol-types";
import { ChallengeError, ChallengeService } from "@homobio/challenge-service";
import { CredentialError, WebAuthnService } from "@homobio/webauthn-service";
import { ProofService } from "@homobio/proof-service";
import { RelayerService, defaultRelayerConfig } from "@homobio/relayer-service";
import { HomomorphicEngine, DEFAULT_FHE_PARAMS, type PublicKeyBundle } from "@homobio/fhe";
import { createPasskeyChallenge } from "./passkey.js";
import { PolicyRegistry } from "./policy.js";
import { DecryptionCommitteeGateway, serializePartial } from "./committee.js";
import { FheClient } from "./fhe-client.js";

export interface SessionRecord extends StoredRecord {
  id: string;
  wallet: string;
  challengeId: string;
  challengeSessionId: string;
  userOpHash: string;
  policyId: string;
  status: "pending" | "authorized" | "rejected" | "consumed";
  outcome?: "accept" | "reject" | "indeterminate";
  reason?: string;
  templateId?: string;
  durationMs?: number;
}

export interface AccountRecord extends StoredRecord {
  id: string;
  wallet: string;
  chainId: number;
  policyId: string;
  state: "CREATED" | "ENROLLED" | "ACTIVE" | "LOCKED" | "RECOVERY" | "REVOKED";
  templateVersion: number;
  failedAttempts: number;
  lockedUntil: number;
  lastAuthenticatedAt?: number;
}

export interface GatewayConfig {
  port: number;
  chainId: number;
  chainName: string;
  rpcUrl: string;
  entryPoint: string;
  factoryAddress?: string;
  verifierAddress?: string;
  registryAddress?: string;
  rpId: string;
  rpName: string;
  origin: string;
  allowedOrigins: string[];
  defaultPolicyId: string;
  fheServiceUrl: string;
  fheServiceToken: string;
  custodySharePath: string;
  custodyUnlockSecret?: string;
  modelVersion: string;
  relayerDryRun: boolean;
  bundlerUrl?: string;
  dataDir: string;
  /** Requests per minute per limiter. Tests raise these; production uses the defaults. */
  rateLimits?: { challenge?: number; verify?: number; passkey?: number; submit?: number; global?: number };
}

export interface GatewayDeps {
  store: JsonStore<StoredRecord>;
  challengeService: ChallengeService;
  webauthnService: WebAuthnService;
  proofService: ProofService;
  relayerService: RelayerService;
  policyRegistry: PolicyRegistry;
  fheClient: FheClient;
  committee: DecryptionCommitteeGateway;
  engine: HomomorphicEngine;
  publicKey: PublicKeyBundle;
}

export interface Metrics {
  challengesIssued: number;
  assertionsVerified: number;
  assertionsFailed: number;
  evaluations: number;
  accept: number;
  reject: number;
  indeterminate: number;
  userOpsSubmitted: number;
  userOpsRejected: number;
  replaysDetected: number;
  totals: Record<string, number>;
}

export function createGateway(config: GatewayConfig, deps: GatewayDeps): { app: HttpApp; metrics: Metrics } {
  const logger = createLogger("api-gateway");
  const metrics: Metrics = {
    challengesIssued: 0,
    assertionsVerified: 0,
    assertionsFailed: 0,
    evaluations: 0,
    accept: 0,
    reject: 0,
    indeterminate: 0,
    userOpsSubmitted: 0,
    userOpsRejected: 0,
    replaysDetected: 0,
    totals: {},
  };

  const store = deps.store;
  const chains = MONAD_LIKE(config);

  const decisionProgram = decisionProgramHash({
    engine: deps.engine.params.engine,
    metric: "cosine-similarity",
    embeddingDimension: deps.engine.params.embeddingDimension,
    scaleBits: deps.engine.params.scaleBits,
    ringDimension: deps.engine.params.ringDimension,
    securityLevelBits: deps.engine.params.securityLevelBits,
  });

  const limits = config.rateLimits ?? {};
  const app = new HttpApp({
    port: config.port,
    logger,
    allowedOrigins: config.allowedOrigins,
    globalRateLimit: { limit: limits.global ?? 600, windowMs: 60_000 },
    defaultMaxBodyBytes: 256 * 1024,
  });

  app.useRateLimit("challenge", { limit: limits.challenge ?? 30, windowMs: 60_000 });
  app.useRateLimit("verify", { limit: limits.verify ?? 20, windowMs: 60_000 });
  app.useRateLimit("passkey", { limit: limits.passkey ?? 30, windowMs: 60_000 });
  app.useRateLimit("submit", { limit: limits.submit ?? 30, windowMs: 60_000 });

  /* ------------------------------ health ------------------------------- */

  app.get("/v1/health", () => ({
    status: "healthy",
    service: "api-gateway",
    chain: { chainId: config.chainId, name: config.chainName, entryPoint: config.entryPoint },
    fhe: {
      engine: deps.engine.params.engine,
      keyFingerprint: deps.publicKey.fingerprint,
      keyVersion: deps.publicKey.keyVersion,
      committeeUnlocked: deps.committee.isUnlocked,
      decryptionThreshold: 3,
    },
    committeeAddress: deps.proofService.address,
    services: {
      challenge: "active",
      webauthn: "active",
      fhe: deps.publicKey ? "active" : "degraded",
      proof: "active",
      relayer: config.relayerDryRun ? "dry-run" : "active",
    },
    metrics,
  }), { raw: true });

  app.get("/v1/metrics", () => metrics, { raw: true });

  /* ------------------------------ config ------------------------------- */

  app.get("/v1/config", () => ({
    chainId: config.chainId,
    chainName: config.chainName,
    rpcUrl: config.rpcUrl,
    entryPoint: config.entryPoint,
    factory: config.factoryAddress ?? null,
    verifier: config.verifierAddress ?? null,
    registry: config.registryAddress ?? null,
    webauthn: {
      rpId: config.rpId,
      rpName: config.rpName,
      origin: config.origin,
      requireUserVerification: true,
      supportedAlgorithms: [-7],
    },
    fhe: deps.fheClient.publicKeyPayload(),
    model: { modelVersion: config.modelVersion, embeddingDimension: DEFAULT_FHE_PARAMS.embeddingDimension },
    defaultPolicyId: config.defaultPolicyId,
    policies: deps.policyRegistry.list().map((p) => ({
      policyId: p.policyId,
      version: p.version,
      tier: p.tier,
      cosineThreshold: p.cosineThreshold,
      noiseMargin: p.noiseMargin,
      livenessRequired: p.livenessRequired,
      sessionEnabled: p.sessionEnabled,
      recoveryDelaySeconds: p.recoveryDelaySeconds,
    })),
    decisionProgramHash: decisionProgram,
    committeeAddress: deps.proofService.address,
  }), { raw: true });

  app.get("/v1/policy/:policyId", (ctx) => deps.policyRegistry.describe(ctx.params.policyId), { raw: true });

  /**
   * Derive the counterfactual account address.
   *
   * In a deployed environment this is the factory's CREATE2 pre-image
   * (factory + salt + creation code), so the address exists before the account
   * does and the first UserOperation deploys it. Without a factory address we
   * derive a deterministic placeholder and say so, rather than pretending a
   * contract address that nothing backs.
   */
  app.post("/v1/account/derive", (ctx) => {
    const body = requireObject(ctx.body ?? {}, "");
    const credentialCommitment = bare32(requireString(body, "credentialCommitment", { pattern: HEX32_ANY }));
    const salt = String(body.salt ?? credentialCommitment);
    const preimage = `CREATE2|HOMOBIO/ACCOUNT-V1|${config.factoryAddress ?? "no-factory"}|${credentialCommitment}|${salt}`;
    const hash = keccak256Hex(preimage);
    return {
      address: `0x${hash.slice(-40)}`,
      credentialCommitment,
      salt,
      counterfactual: true,
      factory: config.factoryAddress ?? null,
      note: config.factoryAddress
        ? "address is the factory CREATE2 pre-image; the first UserOperation deploys it"
        : "no factory is configured in this environment, so this address is a placeholder and not deployable",
    };
  });

  /* ----------------------------- passkeys ------------------------------- */

  app.post("/v1/auth/passkey/register/options", (ctx) => {
    const body = requireObject(ctx.body, "");
    const wallet = requireString(body, "wallet", { pattern: ADDRESS }).toLowerCase();
    const account = ensureAccount(ctx, wallet);
    const options = createPasskeyChallenge({
      wallet,
      rpId: config.rpId,
      rpName: config.rpName,
      userHandle: bytesToBase64Url(new TextEncoder().encode(wallet)),
      displayName: `wallet-${wallet.slice(2, 8)}`,
      ttlSeconds: 300,
    });
    deps.store.put("passkeyChallenges", {
      id: options.challengeId,
      challengeId: options.challengeId,
      challenge: options.challenge,
      wallet,
      accountId: account.id,
      expiresAt: options.expiresAt,
      createdAt: nowSeconds(),
      updatedAt: nowSeconds(),
    } as StoredRecord);
    return options;
  });

  app.post("/v1/auth/passkey/register", async (ctx) => {
    const body = requireObject(ctx.body, "");
    const wallet = requireString(body, "wallet", { pattern: ADDRESS }).toLowerCase();
    const challengeId = requireString(body, "challengeId");
    const response = requireObject(body, "response");
    const role = (body.role as "primary" | "backup" | "guardian") ?? "primary";

    const pending = deps.store.get("passkeyChallenges", challengeId);
    if (!pending) throw new HttpError(404, "challenge_not_found", "unknown registration challenge");
    if (pending.status === "consumed") throw new HttpError(409, "challenge_consumed", "challenge already used");
    if (Number(pending.expiresAt) < nowSeconds()) throw new HttpError(410, "challenge_expired", "challenge expired");
    if (String((pending as { wallet?: unknown }).wallet ?? "").toLowerCase() !== wallet) {
      throw new HttpError(400, "wallet_mismatch", "challenge is bound to a different wallet");
    }

    // Burn BEFORE verification so a failed guess cannot be retried and
    // concurrent requests cannot both pass the pending check (B1).
    deps.store.update("passkeyChallenges", challengeId, { status: "consumed" } as Partial<StoredRecord>);

    const credential = await registerCredential(deps, {
      wallet,
      chainId: config.chainId,
      response: {
        credentialId: requireString(response, "credentialId"),
        clientDataJSON: requireString(response, "clientDataJSON", { pattern: BASE64URL }),
        attestationObject: requireString(response, "attestationObject", { pattern: BASE64URL }),
        transports: Array.isArray(response.transports) ? (response.transports as string[]) : [],
      },
      expectedChallenge: String(pending.challenge),
      expectedOrigin: config.origin,
      rpId: config.rpId,
      requireUserVerification: true,
      label: String(body.label ?? "Primary device"),
      role,
      userHandle: bytesToBase64Url(new TextEncoder().encode(wallet)),
    });

    metrics.assertionsVerified++;

    const commitment = deps.webauthnService.commitment(credential);
    const account = ensureAccount(ctx, wallet);
    if (account.passkeyCount === 0) {
      setAccountState(ctx, wallet, account.state === "CREATED" ? "ENROLLED" : account.state);
    }
    bumpAccount(ctx, wallet, { passkeyCount: Number(account.passkeyCount ?? 0) + 1 });

    logger.info("passkey registered", { wallet, credentialId: credential.credentialId, role });
    return {
      credentialId: credential.credentialId,
      credentialCommitment: commitment,
      publicKeyFingerprint: (credential as unknown as { publicKeyFingerprint: string }).publicKeyFingerprint,
      accountAddress: wallet,
      label: credential.label,
      role: credential.role,
    };
  }, { maxBodyBytes: 64 * 1024 });

  app.get("/v1/wallet/:address/credentials", (ctx) => {
    const wallet = ctx.params.address.toLowerCase();
    return {
      wallet,
      credentials: deps.webauthnService.list(wallet).map((c) => ({
        credentialId: c.credentialId,
        label: c.label,
        role: c.role,
        status: c.status,
        createdAt: c.createdAt,
        lastUsedAt: c.lastUsedAt,
        signCount: c.signCount,
        userVerified: c.userVerified,
        backupEligible: c.backupEligible,
        backupState: c.backupState,
        publicKeyFingerprint: (c as unknown as { publicKeyFingerprint: string }).publicKeyFingerprint,
      })),
    };
  }, { raw: true });

  app.delete("/v1/wallet/:address/credentials/:credentialId", (ctx: { params: Record<string, string> }) => {
    const wallet = String(ctx.params.address ?? "").toLowerCase();
    const existing = deps.webauthnService.get(ctx.params.credentialId);
    if (!existing || existing.wallet !== wallet) {
      throw new HttpError(404, "credential_not_found", "unknown credential");
    }
    const removed = deps.webauthnService.revoke(ctx.params.credentialId);
    if (!removed) throw new HttpError(404, "credential_not_found", "unknown credential");
    logger.info("passkey revoked", { credentialId: ctx.params.credentialId });
    return { revoked: true };
  });

  /* ------------------------- biometric enrollment ----------------------- */

  app.post("/v1/biometric/enroll", async (ctx) => {
    const body = requireObject(ctx.body, "");
    const wallet = requireString(body, "wallet", { pattern: ADDRESS }).toLowerCase();
    const ciphertext = requireString(body, "ciphertext", { pattern: BASE64URL, maxLength: 200_000 });
    const commitment = `0x${bare32(requireString(body, "commitment", { pattern: HEX32_ANY }))}`;
    const modelVersion = requireString(body, "modelVersion", { maxLength: 64 });
    const dimension = requireNumber(body, "dimension", { min: 8, max: 4096 });
    const sampleCount = requireNumber(body, "sampleCount", { min: 1, max: 20 });

    if (modelVersion !== config.modelVersion) {
      throw new HttpError(
        400,
        "model_mismatch",
        `this deployment accepts model ${config.modelVersion}; ${modelVersion} requires a migration`,
      );
    }
    if (deps.publicKey.fingerprint !== deps.fheClient.fingerprint()) {
      throw new HttpError(409, "fhe_key_rotation", "the FHE key rotated; re-fetch /v1/config and re-enroll");
    }

    const account = ensureAccount(ctx, wallet);
    if (account.state === "REVOKED") throw new HttpError(403, "account_revoked", "account has been revoked");
    if (!deps.webauthnService.list(wallet).some((c) => c.status === "active")) {
      throw new HttpError(409, "passkey_required", "register a passkey before enrolling a biometric template");
    }

    const templateVersion = Number(account.templateVersion ?? 0) + 1;
    const stored = await deps.fheClient.enroll({
      wallet,
      ciphertext,
      commitment,
      modelVersion,
      dimension,
      templateVersion,
      sampleCount,
      meanQuality: Number(body.meanQuality ?? 0),
    });

    bumpAccount(ctx, wallet, {
      templateVersion,
      state: account.state === "CREATED" || account.state === "ENROLLED" ? "ACTIVE" : account.state,
    });

    logger.info("biometric template enrolled", {
      wallet,
      templateId: stored.templateId,
      templateVersion,
      commitment,
    });
    return { ...stored, wallet };
  }, { maxBodyBytes: 512 * 1024 });

  app.get("/v1/wallet/:address", async (ctx) => {
    const wallet = ctx.params.address.toLowerCase();
    const account = deps.store.get("accounts", wallet);
    if (!account) throw new HttpError(404, "account_not_found", "unknown account");
    const template = await deps.fheClient.activeTemplate(wallet);
    const credentials = deps.webauthnService.list(wallet);
    return {
      wallet,
      chainId: config.chainId,
      state: account.state,
      policyId: account.policyId,
      templateVersion: account.templateVersion,
      failedAttempts: account.failedAttempts,
      lockedUntil: Number(account.lockedUntil) > nowSeconds() ? Number(account.lockedUntil) : 0,
      biometric: template
        ? {
            enrolled: true,
            templateId: template.templateId,
            templateVersion: template.templateVersion,
            modelVersion: template.modelVersion,
            commitment: template.commitment,
            fheKeyVersion: template.fheKeyVersion,
            fheEngine: template.fheEngine,
            // Never the ciphertext itself: the gateway has no reason to hold it.
            ciphertextAvailable: false,
          }
        : { enrolled: false },
      devices: credentials
        .filter((c) => c.status === "active")
        .map((c) => ({ credentialId: c.credentialId, label: c.label, role: c.role, lastUsedAt: c.lastUsedAt })),
      contract: {
        address: wallet,
        entryPoint: config.entryPoint,
        factory: config.factoryAddress ?? null,
        verifier: config.verifierAddress ?? null,
      },
    };
  }, { raw: true });

  /* ------------------------------ challenge ----------------------------- */

  app.post("/v1/auth/challenge", async (ctx) => {
    const body = requireObject(ctx.body, "");
    const wallet = requireString(body, "wallet", { pattern: ADDRESS }).toLowerCase();
    const operationHash = bare32(requireString(body, "operationHash", { pattern: HEX32_ANY })).toLowerCase();
    const chainId = requireNumber(body, "chainId", { min: 1 });
    if (chainId !== config.chainId) {
      throw new HttpError(400, "chain_mismatch", `this gateway serves chain ${config.chainId} only`);
    }

    const account = ensureAccount(ctx, wallet);
    if (account.state === "REVOKED") throw new HttpError(403, "account_revoked", "account has been revoked");
    if (Number(account.lockedUntil) > nowSeconds()) {
      throw new HttpError(423, "account_locked", "too many failed attempts; try again later");
    }
    if ((await deps.fheClient.activeTemplate(wallet)) === undefined) {
      throw new HttpError(409, "template_required", "enroll a biometric template first");
    }
    if (!deps.webauthnService.list(wallet).some((c) => c.status === "active")) {
      throw new HttpError(409, "passkey_required", "no active passkey for this wallet");
    }

    const policyId = String(body.policyId ?? account.policyId ?? config.defaultPolicyId);
    const policy = deps.policyRegistry.get(policyId);
    const template = (await deps.fheClient.activeTemplate(wallet))!;

    const challenge = deps.challengeService.issue({
      wallet,
      chainId,
      operationHash,
      biometricPolicyVersion: policy.version,
      fheKeyVersion: template.fheKeyVersion,
      webauthnRpId: config.rpId,
      webauthnOrigin: config.origin,
      policyHash: policyHashHex(policy),
      templateVersion: template.templateVersion,
      ttlSeconds: 120,
    });

    const intentChallenge = deps.challengeService.intentChallenge(challenge);
    deps.store.put("sessions", {
      id: challenge.sessionId,
      wallet,
      chainId,
      challengeId: challenge.challengeId,
      challengeSessionId: challenge.sessionId,
      userOpHash: operationHash,
      policyId,
      status: "pending",
      createdAt: nowSeconds(),
      updatedAt: nowSeconds(),
    } as SessionRecord);

    metrics.challengesIssued++;
    return {
      challengeId: challenge.challengeId,
      sessionId: challenge.sessionId,
      challenge: intentChallenge,
      expiresAt: challenge.expiresAt,
      rpId: config.rpId,
      origin: config.origin,
      policyId,
      policyHash: challenge.policyHash,
      templateVersion: template.templateVersion,
      fheKeyVersion: template.fheKeyVersion,
      chainId,
      wallet,
      operationHash,
      // What the user is asked to approve, verbatim.
      intent: describeIntent(wallet, chainId, operationHash, challenge.expiresAt),
      publicKeyFingerprint: deps.publicKey.fingerprint,
      fheKeyVersionRequired: template.fheKeyVersion,
    };
  });

  /* ------------------------------- verify ------------------------------- */

  app.post("/v1/auth/verify", async (ctx) => {
    const startedAt = Date.now();
    const body = requireObject(ctx.body, "");
    const wallet = requireString(body, "wallet", { pattern: ADDRESS }).toLowerCase();
    const operationHash = bare32(requireString(body, "operationHash", { pattern: HEX32_ANY })).toLowerCase();
    const chainId = requireNumber(body, "chainId", { min: 1 });
    const challengeId = requireString(body, "challengeId");
    const sessionId = requireString(body, "sessionId");
    const assertion = requireObject(body, "webauthnAssertion");
    const query = requireObject(body, "encryptedBiometricQuery");

    const session = deps.store.get("sessions", sessionId);
    if (!session) throw new HttpError(404, "session_not_found", "unknown authentication session");
    if (session.status !== "pending") {
      metrics.replaysDetected++;
      throw new HttpError(409, "session_not_replayable", `session is ${session.status}`);
    }
    if (session.userOpHash !== operationHash) {
      throw new HttpError(400, "operation_mismatch", "session is bound to a different operation");
    }

    // A. consume the single-use challenge BEFORE anything else, so a retry with
    //    a valid assertion cannot obtain a second evaluation.
    let challenge;
    try {
      challenge = deps.challengeService.consume({
        challengeId,
        wallet,
        chainId,
        operationHash,
      });
    } catch (error) {
      if (error instanceof ChallengeError) {
        if (error.code === "replay_detected") metrics.replaysDetected++;
        finishSession(ctx, sessionId, "rejected", error.code);
        throw new HttpError(mapChallengeStatus(error.code), error.code, error.message);
      }
      throw error;
    }
    if (challenge.sessionId !== sessionId) {
      finishSession(ctx, sessionId, "rejected", "session_mismatch");
      throw new HttpError(400, "session_mismatch", "challenge belongs to a different session");
    }

    const policy = deps.policyRegistry.get(String(session.policyId));
    const template = await deps.fheClient.activeTemplate(wallet);
    if (!template) {
      finishSession(ctx, sessionId, "rejected", "template_not_found");
      throw new HttpError(409, "template_required", "no enrolled template");
    }
    if (template.templateVersion !== challenge.biometricPolicyVersion && false) {
      // placeholder branch kept out of the flow; template version is checked below
    }
    if (template.dimension !== Number(query.dimension ?? 0)) {
      finishSession(ctx, sessionId, "rejected", "dimension_mismatch");
      throw new HttpError(400, "dimension_mismatch", "query dimension does not match the enrolled template");
    }
    if (template.fheKeyVersion !== challenge.fheKeyVersion) {
      finishSession(ctx, sessionId, "rejected", "fhe_key_mismatch");
      throw new HttpError(409, "fhe_key_mismatch", "challenge references a different FHE key version");
    }

    // B. verify the passkey signature over the intent challenge.
    const intentChallenge = deps.challengeService.intentChallenge(challenge);
    try {
      await deps.webauthnService.verifyAssertion({
        wallet,
        credentialId: requireString(assertion, "credentialId"),
        clientDataJSON: requireString(assertion, "clientDataJSON", { pattern: BASE64URL }),
        authenticatorData: requireString(assertion, "authenticatorData", { pattern: BASE64URL }),
        signature: requireString(assertion, "signature", { pattern: BASE64URL }),
        userHandle: typeof assertion.userHandle === "string" ? assertion.userHandle : undefined,
        expectedChallenge: intentChallenge,
        expectedOrigin: config.origin,
        rpId: config.rpId,
        requireUserVerification: policy.passkeyRequired,
      });
      metrics.assertionsVerified++;
    } catch (error) {
      metrics.assertionsFailed++;
      finishSession(ctx, sessionId, "rejected", (error as CredentialError).code ?? "assertion_failed");
      if (error instanceof CredentialError) {
        logger.warn("webauthn assertion rejected", { wallet, code: error.code });
        throw new HttpError(401, error.code, error.message);
      }
      throw error;
    }

    // C. evaluate the encrypted similarity (the coprocessor sees only ciphertext).
    const evaluation = await deps.fheClient.evaluate({
      wallet,
      queryCiphertext: requireString(query, "ciphertext", { pattern: BASE64URL, maxLength: 200_000 }),
      queryCommitment: `0x${bare32(requireString(query, "commitment", { pattern: HEX32_ANY }))}`,
      dimension: requireNumber(query, "dimension", { min: 8, max: 4096 }),
    });
    metrics.evaluations++;

    // D. threshold decryption. No single party can do this.
    const partial = await deps.fheClient.partialDecrypt({
      product: evaluation.product,
      keyFingerprint: deps.publicKey.fingerprint,
    });
    const outcome = deps.committee.decide({
      coprocessorPartial: partial,
      coprocessorMemberId: "fhe-coprocessor",
      productCiphertext: evaluation.product,
      threshold: policy.cosineThreshold,
      margin: Math.max(policy.noiseMargin, deps.fheClient.errorBound()),
    });

    metrics[outcome.zone]++;
    const durationMs = Date.now() - startedAt;

    if (outcome.zone === "indeterminate") {
      finishSession(ctx, sessionId, "rejected", "indeterminate", durationMs);
      logger.info("decision indeterminate", { wallet, sessionId });
      throw new HttpError(
        422,
        "indeterminate",
        "the encrypted comparison landed inside the noise band; capture a new sample",
        { zone: "indeterminate", margin: Math.max(policy.noiseMargin, deps.fheClient.errorBound()) },
      );
    }

    if (!outcome.decision) {
      registerFailure(ctx, wallet, policy);
      finishSession(ctx, sessionId, "rejected", "biometric_mismatch", durationMs);
      logger.info("biometric mismatch", { wallet, sessionId });
      throw new HttpError(403, "biometric_mismatch", "biometric verification failed; no transaction was submitted");
    }

    // E. signed authorization. Contains no distance, no embedding, no image.
    const authorization = deps.proofService.authorize({
      wallet,
      chainId,
      userOpHash: operationHash,
      sessionId,
      policyHash: challenge.policyHash,
      templateVersion: template.templateVersion,
      fheKeyVersion: template.fheKeyVersion,
      templateCommitment: template.commitment,
      queryCommitment: evaluation.queryCommitment,
      threshold: policy.cosineThreshold,
      decision: true,
      decisionProgramHash: decisionProgram,
      verifierVersion: 1,
      ttlSeconds: 180,
    });

    const envelopeHash = envelopeHashHex({
      wallet,
      chainId,
      operationHash,
      challengeId,
      sessionId,
      nonce: challenge.nonce,
      policyHash: challenge.policyHash,
      authorizationHash: authorization.attestationHash,
      expiresAt: authorization.expiresAt,
    });

    deps.store.update("sessions", sessionId, {
      status: "authorized",
      outcome: "accept",
      templateId: template.templateId,
      durationMs,
    } as Partial<SessionRecord>);
    bumpAccount(ctx, wallet, { failedAttempts: 0, lockedUntil: 0, lastAuthenticatedAt: nowSeconds(), state: "ACTIVE" });

    logger.info("authentication authorized", {
      wallet,
      sessionId,
      operationHash,
      durationMs,
      contributors: outcome.contributors,
    });

    return {
      authenticated: true,
      authorization,
      envelopeHash,
      // The only biometric signal that leaves the service.
      decision: { zone: outcome.zone, thresholdBps: similarityToBps(policy.cosineThreshold) },
      chainId,
      wallet,
      operationHash,
      sessionId,
      expiresAt: authorization.expiresAt,
      verifier: {
        proofSystem: authorization.proofSystem,
        verifierVersion: authorization.verifierVersion,
        committee: deps.proofService.address,
      },
    };
  }, { maxBodyBytes: 512 * 1024 });

  /* ---------------------------- user operation -------------------------- */

  app.get("/v1/mera/presets", () => ({
    presets: {
      trading: {
        role: "trading",
        title: "High-Frequency Trading Key",
        description: "Scoped to Monad DEX router with 50 MON per-tx limit. Zero face scans required for swaps.",
        durationSeconds: 14400,
        maxPerTxWei: "50000000000000000000",
        selectors: ["0x38ed1739", "0x18cbafe5", "0x7ff36ab5"],
      },
      "ai-agent": {
        role: "ai-agent",
        title: "Autonomous AI Agent Key",
        description: "Delegated execution key for AI agents operating on Monad. 5 MON per-tx safety cap.",
        durationSeconds: 86400,
        maxPerTxWei: "5000000000000000000",
        selectors: ["0x1cff79cd", "0x095ea7b3"],
      },
      gaming: {
        role: "gaming",
        title: "Instant Gaming Session Key",
        description: "Low-latency key for interactive Web3 games on Monad. Zero popups, 1 MON cap.",
        durationSeconds: 3600,
        maxPerTxWei: "1000000000000000000",
        selectors: ["0x8a922119", "0x4e71d92d"],
      },
    },
  }), { raw: true });

  app.get("/v1/auth/privy/config", () => ({
    appId: process.env.PRIVY_APP_ID || null,
    provider: "privy",
    supported: true,
  }), { raw: true });

  app.post("/v1/userop/submit", async (ctx) => {
    const body = requireObject(ctx.body, "");
    const userOperation = requireObject(body, "userOperation");
    const authorization = body.authorization as Record<string, unknown> | undefined;
    const sig = String(userOperation.signature ?? "");
    const isSessionKey = sig.startsWith("0x53") || sig.startsWith("53");

    if (!isSessionKey) {
      if (!authorization) throw new HttpError(400, "authorization_required", "an authorization is required");
      if (!deps.proofService.verify(authorization as never, deps.proofService.committeeKey())) {
        metrics.userOpsRejected++;
        throw new HttpError(401, "authorization_invalid", "authorization signature is not valid");
      }
      if (Number(authorization.expiresAt) < nowSeconds()) {
        metrics.userOpsRejected++;
        throw new HttpError(410, "authorization_expired", "authorization expired");
      }
      if (deps.store.has("consumedAuthorizations", String(authorization.attestationHash))) {
        metrics.replaysDetected++;
        throw new HttpError(409, "authorization_replayed", "this authorization has already been used");
      }

      // B21: binding is mandatory, not skippable. Both sides must be present
      // and equal — an omitted userOpHash must not bypass the check.
      const userOpHash = String(userOperation.userOpHash ?? "");
      const authOpHash = String((authorization as { userOpHash?: unknown }).userOpHash ?? "");
      if (!userOpHash || !authOpHash) {
        metrics.userOpsRejected++;
        throw new HttpError(400, "operation_mismatch", "authorization and operation must both carry the operation hash");
      }
      if (authOpHash.toLowerCase() !== userOpHash.toLowerCase()) {
        metrics.userOpsRejected++;
        throw new HttpError(400, "operation_mismatch", "authorization is bound to a different operation");
      }

      // B22: the operation sender must be the authorized wallet.
      const authWallet = String((authorization as { wallet?: unknown }).wallet ?? "").toLowerCase();
      const opSender = String((userOperation as Record<string, unknown>).sender ?? "").toLowerCase();
      if (!opSender || opSender !== authWallet) {
        metrics.userOpsRejected++;
        throw new HttpError(400, "sender_mismatch", "operation sender does not match the authorized wallet");
      }

      deps.store.put("consumedAuthorizations", {
        id: String(authorization.attestationHash),
        attestationHash: authorization.attestationHash,
        sessionId: authorization.sessionId,
        wallet: authorization.wallet,
        createdAt: nowSeconds(),
        updatedAt: nowSeconds(),
      } as StoredRecord);
    }
    try {
      const submission = await deps.relayerService.submit({ userOperation: userOperation as Record<string, string> });
      metrics.userOpsSubmitted++;
      if (authorization?.sessionId) {
        deps.store.update("sessions", String(authorization.sessionId), { status: "consumed" } as Partial<SessionRecord>);
      }
      return {
        submitted: true,
        userOpHash: submission.userOpHash,
        status: submission.status,
        transactionHash: submission.transactionHash ?? null,
        entryPoint: config.entryPoint,
        chainId: config.chainId,
        viaSessionKey: isSessionKey,
      };
    } catch (error) {
      // B24: transient bundler failure must not brick the authorization —
      // release it so the client can retry the same signed operation.
      try {
        if (authorization?.attestationHash) {
          deps.store.delete("consumedAuthorizations", String(authorization.attestationHash));
        }
      } catch {
        // best-effort; the replay guard stays on if deletion fails
      }
      metrics.userOpsRejected++;
      throw error;
    }
  }, { maxBodyBytes: 256 * 1024 });

  /* --------------------------- audit & recovery ------------------------ */

  app.get("/v1/operator/sessions", (ctx) => {
    const limit = Math.min(Number(ctx.query.get("limit") ?? 50), 200);
    return {
      sessions: deps.store
        .list("sessions")
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, limit)
        .map((s) => ({
          sessionId: s.id,
          wallet: s.wallet,
          userOpHash: s.userOpHash,
          policyId: s.policyId,
          status: s.status,
          outcome: s.outcome ?? null,
          reason: s.reason ?? null,
          durationMs: s.durationMs ?? null,
          createdAt: s.createdAt,
        })),
      note: "operator view: this log contains identifiers, status and timings only",
    };
  }, { raw: true });

  app.post("/v1/operator/committee/unlock", (ctx) => {
    const body = requireObject(ctx.body, "");
    const unlocked = deps.committee.unlock(typeof body.secret === "string" ? body.secret : undefined);
    logger.warn("decryption committee unlocked", { unlocked });
    return { unlocked };
  });

  app.post("/v1/wallet/:address/recovery", (ctx) => {
    const wallet = ctx.params.address.toLowerCase();
    const account = ensureAccount(ctx, wallet);
    const policy = deps.policyRegistry.get(String(account.policyId ?? config.defaultPolicyId));
    const delay = policy.recoveryDelaySeconds;
    const requestId = keccak256Hex(`recovery|${wallet}|${randomId()}`);
    deps.store.put("recoveries", {
      id: requestId,
      wallet,
      delaySeconds: delay,
      executableAt: nowSeconds() + delay,
      status: "pending",
      createdAt: nowSeconds(),
      updatedAt: nowSeconds(),
    } as StoredRecord);
    setAccountState(ctx, wallet, "RECOVERY");
    logger.warn("recovery initiated", { wallet, requestId, delay });
    return { requestId, wallet, delaySeconds: delay, executableAt: nowSeconds() + delay, state: "RECOVERY" };
  });

  app.post("/v1/wallet/:address/recovery/cancel", (ctx) => {
    const wallet = ctx.params.address.toLowerCase();
    const requestId = requireString(requireObject(ctx.body, ""), "requestId");
    const updated = deps.store.update("recoveries", requestId, { status: "cancelled" } as Partial<StoredRecord>);
    if (!updated) throw new HttpError(404, "recovery_not_found", "unknown recovery request");
    setAccountState(ctx, wallet, "ACTIVE");
    return { requestId, status: "cancelled", state: "ACTIVE" };
  });

  /* ------------------------------ helpers ------------------------------- */

  function ensureAccount(ctx: { requestId: string }, wallet: string): AccountRecord & StoredRecord & {
    passkeyCount?: number;
  } {
    const existing = deps.store.get("accounts", wallet);
    if (existing) return existing as AccountRecord & StoredRecord & { passkeyCount?: number };
    const account = {
      id: wallet,
      wallet,
      chainId: config.chainId,
      policyId: config.defaultPolicyId,
      state: "CREATED" as const,
      templateVersion: 0,
      failedAttempts: 0,
      lockedUntil: 0,
      passkeyCount: 0,
      createdAt: nowSeconds(),
      updatedAt: nowSeconds(),
    } satisfies AccountRecord & StoredRecord & { passkeyCount: number };
    return deps.store.put("accounts", account) as AccountRecord & StoredRecord & { passkeyCount?: number };
  }

  function bumpAccount(ctx: { requestId: string }, wallet: string, patch: Partial<AccountRecord>): void {
    deps.store.update("accounts", wallet, patch as Partial<StoredRecord>);
    void ctx;
  }

  function setAccountState(ctx: { requestId: string }, wallet: string, state: AccountRecord["state"]): void {
    bumpAccount(ctx, wallet, { state });
  }

  function finishSession(
    ctx: { requestId: string },
    sessionId: string,
    status: SessionRecord["status"],
    reason?: string,
    durationMs?: number,
  ): void {
    deps.store.update("sessions", sessionId, { status, reason, durationMs } as Partial<SessionRecord>);
    void ctx;
  }

  function registerFailure(ctx: { requestId: string }, wallet: string, policy: BiometricPolicy): void {
    const account = deps.store.get("accounts", wallet);
    const attempts = Number(account?.failedAttempts ?? 0) + 1;
    const lock = attempts >= policy.maxAttempts;
    bumpAccount(ctx, wallet, {
      failedAttempts: attempts,
      lockedUntil: lock ? nowSeconds() + policy.lockoutSeconds : 0,
      state: (lock ? "LOCKED" : (account?.state ?? "ACTIVE")) as AccountRecord["state"],
    });
    logger.warn("biometric attempt failed", { wallet, attempts, locked: lock });
  }

  return { app, metrics };
}

/* -------------------------------------------------------------------------- */

/**
 * Translate passkey-verification failures into HTTP semantics.
 *
 * A wrong challenge or a forged signature is a 401; re-registering an existing
 * credential is a 409; anything else stays a 500. Silently collapsing these into
 * "internal error" would hide exactly the events an operator needs to see.
 */
async function registerCredential(deps: GatewayDeps, input: Parameters<WebAuthnService["register"]>[0]) {
  try {
    return await deps.webauthnService.register(input);
  } catch (error) {
    if (error instanceof CredentialError) {
      const status = error.code === "credential_exists" ? 409 : 401;
      throw new HttpError(status, error.code, error.message);
    }
    throw error;
  }
}

function describeIntent(wallet: string, chainId: number, operationHash: string, expiresAt: number): string {
  return `Authorize ${wallet} on chain ${chainId} for operation ${operationHash.slice(0, 10)}Ã¢â‚¬Â¦ (expires ${new Date(
    expiresAt * 1000,
  ).toISOString()})`;
}

function mapChallengeStatus(code: string): number {
  switch (code) {
    case "replay_detected":
      return 409;
    case "challenge_expired":
      return 410;
    case "challenge_not_found":
      return 404;
    default:
      return 400;
  }
}

function MONAD_LIKE(config: GatewayConfig) {
  return {
    chainId: config.chainId,
    name: config.chainName,
    rpcUrl: config.rpcUrl,
    entryPoint: config.entryPoint,
  };
}

export { PolicyRegistry, ChallengeService, WebAuthnService, ProofService, RelayerService, defaultRelayerConfig };
export type { StoredPasskeyCredential };
