/**
 * Homomorphic Biometric Passkeys SDK (PRD section 60)
 *
 * A thin, honest wrapper over the protocol. It hides endpoint plumbing but
 * never hides security state: every method returns the commitments and proofs
 * involved, so an integrator can audit what the wallet actually authorised.
 */

import { keccak256Hex, nowSeconds } from "@homobio/crypto-utils";
import { HomomorphicEngine, type FheCiphertext, type PublicKeyBundle } from "@homobio/fhe";
import { createCredential, getAssertion, isWebAuthnSupported } from "@homobio/webauthn";
import {
  NonceDomain,
  UserOperationBuilder,
  getUserOpHash,
  type PackedUserOperation,
} from "@homobio/userop";
import { packAuthorizationEnvelope } from "./envelope.js";

export interface SdkOptions {
  gatewayUrl: string;
  /** Supplied by a dApp; the account address is derived from the passkey. */
  wallet?: string;
  policyId?: string;
}

export interface GatewayConfigResponse {
  chainId: number;
  chainName: string;
  entryPoint: string;
  webauthn: { rpId: string; rpName: string; origin: string };
  fhe: {
    engine: string;
    keyVersion: number;
    fingerprint: string;
    ringDimension: number;
    modulus: string;
    scaleBits: number;
    embeddingDimension: number;
    securityLevelBits: number;
    publicKeyA: string;
    publicKeyB: string;
    errorBound: number;
    templateLayout: "high";
    queryLayout: "low";
  };
  model: { modelVersion: string; embeddingDimension: number };
  defaultPolicyId: string;
  decisionProgramHash: string;
  committeeAddress: string;
}

export interface RegisterPasskeyResult {
  credentialId: string;
  credentialCommitment: string;
  accountAddress: string;
  publicKeyFingerprint: string;
}

export interface AuthenticationResult {
  authenticated: boolean;
  authorization: {
    version: number;
    wallet: string;
    chainId: number;
    userOpHash: string;
    sessionId: string;
    policyHash: string;
    templateVersion: number;
    fheKeyVersion: number;
    attestationHash: string;
    sessionExpiry: number;
    expiresAt: number;
    decision: boolean;
    thresholdBps: number;
    resultCommitment: string;
    issuedAt: number;
    proofSystem: number;
    verifierVersion: number;
    decisionProgramHash: string;
    signature: string;
  };
  envelopeHash: string;
  operationHash: string;
  /** The exact envelope that must go into `userOp.signature`. */
  signatureEnvelope: string;
  userOpHash: string;
  decision: { zone: string; thresholdBps: number };
}

export class HomomorphicPasskeyWallet {
  private engine?: HomomorphicEngine;
  private publicKey?: PublicKeyBundle;
  private config?: GatewayConfigResponse;

  constructor(private readonly options: SdkOptions) {}

  /* ------------------------------- transport ---------------------------- */

  private async api<T>(method: "GET" | "POST" | "DELETE", endpoint: string, body?: unknown): Promise<T> {
    const response = await fetch(`${this.options.gatewayUrl.replace(/\/$/, "")}${endpoint}`, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    const parsed = text ? (JSON.parse(text) as unknown) : {};
    if (!response.ok) {
      const record = parsed as { error?: string; message?: string; details?: unknown };
      throw new SdkError(record.error ?? "request_failed", record.message ?? "request failed", response.status, record.details);
    }
    return parsed as T;
  }

  async loadConfig(): Promise<GatewayConfigResponse> {
    this.config = await this.api<GatewayConfigResponse>("GET", "/v1/config");
    this.publicKey = {
      engine: this.config.fhe.engine,
      keyVersion: this.config.fhe.keyVersion,
      encodingVersion: 1,
      ringDimension: this.config.fhe.ringDimension,
      modulus: this.config.fhe.modulus,
      scaleBits: this.config.fhe.scaleBits,
      embeddingDimension: this.config.fhe.embeddingDimension,
      securityLevelBits: this.config.fhe.securityLevelBits,
      publicKeyA: this.config.fhe.publicKeyA,
      publicKeyB: this.config.fhe.publicKeyB,
      fingerprint: this.config.fhe.fingerprint,
    };
    this.engine = new HomomorphicEngine({
      engine: this.config.fhe.engine,
      ringDimension: this.config.fhe.ringDimension,
      modulus: this.config.fhe.modulus,
      scaleBits: this.config.fhe.scaleBits,
      embeddingDimension: this.config.fhe.embeddingDimension,
      securityLevelBits: this.config.fhe.securityLevelBits,
      encodingVersion: 1,
    });
    return this.config;
  }

  get wallet(): string | undefined {
    return this.options.wallet;
  }

  get fheEngine(): HomomorphicEngine {
    if (!this.engine) throw new SdkError("config_not_loaded", "call loadConfig() first");
    return this.engine;
  }

  /** Encrypt an embedding locally. The plaintext never leaves this function. */
  encryptEmbedding(vector: ArrayLike<number>, layout: "low" | "high" = "low"): FheCiphertext {
    if (!this.publicKey) throw new SdkError("config_not_loaded", "call loadConfig() first");
    return this.fheEngine.encryptVector(
      this.publicKey,
      vector,
      this.publicKey.embeddingDimension,
      layout,
    );
  }

  /* -------------------------------- passkeys ---------------------------- */

  async registerPasskey(params: { wallet: string; label?: string; role?: "primary" | "backup" | "guardian" }): Promise<RegisterPasskeyResult> {
    if (!isWebAuthnSupported()) {
      throw new SdkError("passkey_not_supported", "this browser cannot create passkeys");
    }
    const options = await this.api<{
      challengeId: string;
      challenge: string;
      rpId: string;
      rpName: string;
      userHandle: string;
      userName: string;
      userDisplayName: string;
    }>("POST", "/v1/auth/passkey/register/options", { wallet: params.wallet });

    const response = await createCredential({
      rpId: options.rpId,
      rpName: options.rpName,
      userId: options.userHandle,
      userName: options.userName,
      userDisplayName: options.userDisplayName,
      challenge: options.challenge,
      userVerification: "required",
      residentKey: "required",
    });

    return this.api<RegisterPasskeyResult>("POST", "/v1/auth/passkey/register", {
      wallet: params.wallet,
      challengeId: options.challengeId,
      response,
      label: params.label ?? "This device",
      role: params.role ?? "primary",
    });
  }

  async listCredentials(wallet: string): Promise<Array<Record<string, unknown>>> {
    const response = await this.api<{ credentials: Array<Record<string, unknown>> }>(
      "GET",
      `/v1/wallet/${wallet}/credentials`,
    );
    return response.credentials;
  }

  async revokeCredential(wallet: string, credentialId: string): Promise<void> {
    await this.api("DELETE", `/v1/wallet/${wallet}/credentials/${credentialId}`);
  }

  /* ------------------------------ enrollment ---------------------------- */

  /**
   * Encrypt and upload an aggregated template.
   *
   * `template` must already be an aggregated, L2-normalised vector produced by
   * the biometric client for the model version the gateway reports.
   */
  async enrollBiometric(params: {
    wallet: string;
    template: ArrayLike<number>;
    modelVersion: string;
    sampleCount: number;
    meanQuality: number;
  }): Promise<{ templateId: string; commitment: string; templateVersion: number }> {
    if (!this.config) await this.loadConfig();
    const ciphertext = this.encryptEmbedding(params.template, this.config?.fhe.templateLayout ?? "high");
    return this.api("POST", "/v1/biometric/enroll", {
      wallet: params.wallet,
      ciphertext: ciphertext.ciphertext,
      commitment: ciphertext.commitment,
      modelVersion: params.modelVersion,
      dimension: params.template.length,
      sampleCount: params.sampleCount,
      meanQuality: params.meanQuality,
    });
  }

  /* ---------------------------- authentication -------------------------- */

  /**
   * Run the full authentication: challenge -> passkey -> encrypted query -> decision.
   *
   * `vector` is the live embedding; it is encrypted here and the plaintext is
   * dropped immediately afterwards.
   */
  async authenticate(params: {
    wallet: string;
    userOp: PackedUserOperation;
    vector: ArrayLike<number>;
    credentialId: string;
    policyId?: string;
  }): Promise<AuthenticationResult> {
    if (!this.config) await this.loadConfig();
    const config = this.config!;

    const userOpHash = getUserOpHash(params.userOp, config.entryPoint, config.chainId);
    const challenge = await this.api<{
      challengeId: string;
      sessionId: string;
      challenge: string;
      rpId: string;
      origin: string;
      expiresAt: number;
      policyId: string;
      intent: string;
    }>("POST", "/v1/auth/challenge", {
      wallet: params.wallet,
      chainId: config.chainId,
      operationHash: userOpHash,
      policyId: params.policyId,
    });

    const assertion = await getAssertion({
      rpId: challenge.rpId,
      challenge: challenge.challenge,
      credentialId: params.credentialId,
      userVerification: "required",
    });

    const query = this.encryptEmbedding(params.vector, config.fhe.queryLayout);

    const verified = await this.api<{
      authenticated: boolean;
      authorization: AuthenticationResult["authorization"];
      envelopeHash: string;
      decision: { zone: string; thresholdBps: number };
    }>("POST", "/v1/auth/verify", {      wallet: params.wallet,
      chainId: config.chainId,
      operationHash: userOpHash,
      challengeId: challenge.challengeId,
      sessionId: challenge.sessionId,
      webauthnAssertion: {
        credentialId: assertion.credentialId,
        clientDataJSON: assertion.clientDataJSON,
        authenticatorData: assertion.authenticatorData,
        signature: assertion.signature,
        userHandle: assertion.userHandle,
      },
      encryptedBiometricQuery: {
        ciphertext: query.ciphertext,
        commitment: query.commitment,
        dimension: params.vector.length,
      },
    });

    const signatureEnvelope = packAuthorizationEnvelope({
      envelopeHash: verified.envelopeHash,
      attestationHash: verified.authorization.attestationHash,
      attestationSignature: verified.authorization.signature,
      webauthnAssertion: assertion.clientDataJSON,
      authorization: {
        version: verified.authorization.version,
        wallet: verified.authorization.wallet,
        chainId: verified.authorization.chainId,
        userOpHash: verified.authorization.userOpHash,
        sessionId: verified.authorization.sessionId,
        policyHash: verified.authorization.policyHash,
        templateVersion: verified.authorization.templateVersion,
        fheKeyVersion: verified.authorization.fheKeyVersion,
        decision: verified.authorization.decision,
        thresholdBps: verified.authorization.thresholdBps,
        resultCommitment: verified.authorization.resultCommitment,
        issuedAt: verified.authorization.issuedAt,
        expiresAt: verified.authorization.expiresAt,
        proofSystem: verified.authorization.proofSystem,
        verifierVersion: verified.authorization.verifierVersion,
        decisionProgramHash: verified.authorization.decisionProgramHash,
        attestationHash: verified.authorization.attestationHash,
      },
    });

    return {
      authenticated: verified.authenticated,
      authorization: verified.authorization,
      envelopeHash: verified.envelopeHash,
      operationHash: userOpHash,
      signatureEnvelope,
      userOpHash,
      decision: verified.decision,
    };
  }

  /* ----------------------------- submission ----------------------------- */

  async submitUserOperation(params: {
    userOperation: Record<string, string>;
    authorization: unknown;
  }): Promise<Record<string, unknown>> {
    return this.api("POST", "/v1/userop/submit", params);
  }

  /** Convenience: build a UserOperation for a contract call. */
  buildUserOperation(params: {
    wallet: string;
    callData: string;
    value?: bigint;
    nonce?: number;
    initCode?: string;
    sponsored?: boolean;
  }): PackedUserOperation {
    const op = new UserOperationBuilder(params.wallet)
      .nonce(params.nonce ? NonceDomain.Wallet : NonceDomain.Wallet, params.nonce ?? 0)
      .callData(params.callData);
    if (params.initCode) op.initCode(params.initCode);
    void params.value;
    return op.build();
  }

  /* ------------------------------ recovery ------------------------------ */

  async startRecovery(wallet: string): Promise<{ requestId: string; executableAt: number; delaySeconds: number }> {
    return this.api("POST", `/v1/wallet/${wallet}/recovery`);
  }

  async cancelRecovery(wallet: string, requestId: string): Promise<Record<string, unknown>> {
    return this.api("POST", `/v1/wallet/${wallet}/recovery/cancel`, { requestId });
  }

  /* ------------------------------- policy ------------------------------- */

  async getWalletPolicy(policyId: string): Promise<Record<string, unknown>> {
    return this.api("GET", `/v1/policy/${policyId}`);
  }

  async walletState(wallet: string): Promise<Record<string, unknown>> {
    return this.api("GET", `/v1/wallet/${wallet}`);
  }
}

export class SdkError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 0,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "SdkError";
  }
}

/** Factory matching the PRD's example surface. */
export async function createBiometricWallet(options: {
  gatewayUrl: string;
  chain?: string;
  biometric?: { enabled: boolean; liveness: "active" | "passive" };
  gas?: { sponsored: boolean };
}): Promise<HomomorphicPasskeyWallet> {
  if (options.biometric?.liveness === "passive") {
    throw new SdkError(
      "liveness_unsupported",
      "passive liveness is not implemented; the pipeline requires active liveness",
    );
  }
  const wallet = new HomomorphicPasskeyWallet({ gatewayUrl: options.gatewayUrl });
  await wallet.loadConfig();
  return wallet;
}

export { getUserOpHash, UserOperationBuilder, NonceDomain, nowSeconds, keccak256Hex };
export { packAuthorizationEnvelope, AUTHORIZATION_MAGIC } from "./envelope.js";
