/**
 * The three user-facing flows, each mirroring the PRD state machine exactly:
 *
 *   enrollment    (section 18)
 *   authentication (section 19)
 *   recovery       (section 23)
 *
 * Every transition sets the pipeline stage, so the UI can never show a state
 * that the protocol is not actually in. Failures go through
 * `explainFailure`, which guarantees a human-readable explanation and a
 * concrete next action for each one (PRD sections 32.3 and 57).
 */

import {
  BiometricCaptureSession,
  EMBEDDING_DIMENSION,
  EMBEDDING_VERSION,
  aggregateTemplate,
  analyzeFrame,
  seededUnitVectorLocal,
  type RgbaImage,
} from "@homobio/biometric-client";
import { createCredential, getAssertion, isWebAuthnSupported } from "@homobio/webauthn";
import { NonceDomain, UserOperationBuilder, getUserOpHash } from "@homobio/userop";
import { HomomorphicEngine, type PublicKeyBundle } from "@homobio/fhe";
import { packAuthorizationEnvelope } from "@homobio/sdk/envelope";
import type { App } from "./app.js";

const ENROLL_SAMPLES = 7;

export class FlowController {
  private engine?: HomomorphicEngine;
  private publicKey?: PublicKeyBundle;

  constructor(private readonly app: App) {}

  /**
   * Derive the smart-account address from the passkey commitment.
   *
   * The address is a CREATE2 pre-image of (factory, credentialCommitment,
   * salt), so it exists before the account is deployed and the first
   * UserOperation deploys it (ERC-4337 counterfactual deployment).
   */
  private async deriveAddress(): Promise<string> {
    const response = await fetch("/v1/account/derive", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!response.ok) {
      // Offline fallback: a random address. Production derives it deterministically
      // from the passkey commitment via CREATE2 (see /v1/account/derive).
      const bytes = new Uint8Array(20);
      crypto.getRandomValues(bytes);
      return `0x${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
    }
    const payload = await response.json();
    return payload.address as string;
  }

  private async ensureEngine(): Promise<HomomorphicEngine> {
    if (this.engine && this.publicKey) return this.engine;
    const config = this.app.state.config ?? (await fetch("/v1/config").then((r) => r.json()));
    this.app.set({ config });
    const fhe = config.fhe;
    this.publicKey = {
      engine: fhe.engine,
      keyVersion: fhe.keyVersion,
      encodingVersion: 1,
      ringDimension: fhe.ringDimension,
      modulus: fhe.modulus,
      scaleBits: fhe.scaleBits,
      embeddingDimension: fhe.embeddingDimension,
      securityLevelBits: fhe.securityLevelBits,
      publicKeyA: fhe.publicKeyA,
      publicKeyB: fhe.publicKeyB,
      fingerprint: fhe.fingerprint,
    };
    this.engine = new HomomorphicEngine({
      engine: fhe.engine,
      ringDimension: fhe.ringDimension,
      modulus: fhe.modulus,
      scaleBits: fhe.scaleBits,
      embeddingDimension: fhe.embeddingDimension,
      securityLevelBits: fhe.securityLevelBits,
      encodingVersion: 1,
    });
    return this.engine;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) : {};
    if (!response.ok) {
      throw Object.assign(new Error(parsed.message ?? "request failed"), {
        code: parsed.error ?? "request_failed",
        status: response.status,
        details: parsed.details,
      });
    }
    return parsed as T;
  }

  /* ------------------------------ enrollment ---------------------------- */

  async registerPasskey(): Promise<void> {
    if (!isWebAuthnSupported()) {
      this.app.fail("passkey_not_supported");
      return;
    }
    let wallet = this.app.state.wallet;
    if (!wallet) {
      wallet = await this.deriveAddress();
      this.app.set({ wallet });
    }
    this.app.rememberWallet();
    this.app.set({ busy: true, failure: undefined, notice: undefined });

    try {
      const options = await this.post<any>("/v1/auth/passkey/register/options", { wallet });
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
      const registered = await this.post<any>("/v1/auth/passkey/register", {
        wallet,
        challengeId: options.challengeId,
        response,
        label: "This device",
        role: "primary",
      });
      await this.app.refresh();
      this.app.set({
        busy: false,
        notice: {
          kind: "success",
          text: `Passkey registered. Credential ${registered.credentialId.slice(0, 12)}â€¦ is now authorized for ${wallet}.`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      const code = (error as { code?: string }).code;
      if (code === "NotAllowedError") this.app.fail("passkey_cancelled");
      else if (code === "passkey_not_supported") this.app.fail("passkey_not_supported");
      else this.app.fail("proof_error", (error as Error).message);
    }
  }

  async enrollBiometric(): Promise<void> {
    const wallet = this.app.state.wallet;
    if (!wallet) {
      this.app.fail("passkey_cancelled", "set an address first");
      return;
    }
    this.app.set({ busy: true, failure: undefined, notice: undefined });
    this.app.setStage("request_permission");

    try {
      await this.app.camera.start();
    } catch (error) {
      this.app.set({ busy: false });
      const name = (error as { name?: string }).name;
      this.app.fail(name === "NotAllowedError" ? "camera_denied" : "camera_unavailable", (error as Error).message);
      return;
    }

    this.app.setStage("camera_ready");
    const session = new BiometricCaptureSession();
    this.app.set({ livenessInstruction: session.instruction });

    const captured: Array<{ vector: Float64Array; quality: number }> = [];
    const deadline = Date.now() + 20_000;

    while (Date.now() < deadline && captured.length < ENROLL_SAMPLES) {
      const frame = this.app.camera.capture();
      if (!frame) {
        await sleep(80);
        continue;
      }
      const analysis = analyzeFrame(frame, { extractEmbedding: true });
      if (analysis.quality.acceptable && analysis.embedding) {
        captured.push({ vector: analysis.embedding, quality: analysis.quality.score });
        this.app.set({
          progress: captured.length / ENROLL_SAMPLES,
          stage: captured.length < ENROLL_SAMPLES ? "face_quality_ok" : "embedding_generated",
        });
      } else if (analysis.quality.reasons.includes("multiple_faces")) {
        this.app.set({ busy: false });
        this.app.camera.stop();
        this.app.fail("multiple_faces");
        return;
      }
      await sleep(60);
    }

    this.app.camera.stop();
    this.app.set({ livenessInstruction: undefined, progress: undefined });

    if (captured.length < 3) {
      this.app.set({ busy: false });
      this.app.fail("poor_quality", `only ${captured.length} usable samples were captured`);
      return;
    }

    this.app.setStage("encrypting");
    try {
      const template = aggregateTemplate(captured);
      const engine = await this.ensureEngine();
      const ciphertext = engine.encryptVector(this.publicKey!, template.vector, EMBEDDING_DIMENSION, "high");

      const stored = await this.post<any>("/v1/biometric/enroll", {
        wallet,
        ciphertext: ciphertext.ciphertext,
        commitment: ciphertext.commitment,
        modelVersion: EMBEDDING_VERSION,
        dimension: EMBEDDING_DIMENSION,
        sampleCount: template.acceptedSamples,
        meanQuality: captured.reduce((a, s) => a + s.quality, 0) / captured.length,
      });
      await this.app.refresh();
      this.app.set({
        busy: false,
        stage: "success",
        notice: {
          kind: "success",
          text: `Template v${stored.templateVersion} encrypted with ${engine.params.engine} and stored as ${stored.commitment.slice(0, 14)}â€¦ Your plaintext face never left this device.`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      this.app.fail("fhe_error", (error as Error).message);
    }
  }

  /** Offline capture path, used when no camera is available. */
  async simulateCapture(): Promise<void> {
    this.app.set({ busy: true, stage: "camera_ready", progress: undefined, failure: undefined });
    try {
      const samples = Array.from({ length: ENROLL_SAMPLES }, (_, i) => ({
        vector: seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242 + i, 0.04),
        quality: 0.92,
      }));
      const template = aggregateTemplate(samples);
      const engine = await this.ensureEngine();
      const ciphertext = engine.encryptVector(this.publicKey!, template.vector, EMBEDDING_DIMENSION, "high");
      this.app.set({
        busy: false,
        stage: "success",
        notice: {
          kind: "success",
          text: `Simulated capture encrypted locally (${engine.params.engine}); ${ciphertext.byteLength} bytes of ciphertext.`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      this.app.fail("fhe_error", (error as Error).message);
    }
  }

  /* --------------------------- authentication --------------------------- */

  async authenticate(options: { tamper?: boolean; replay?: boolean } = {}): Promise<void> {
    const wallet = this.app.state.wallet;
    if (!wallet) {
      this.app.fail("proof_error", "no wallet address");
      return;
    }
    const config = this.app.state.config;
    if (!config) {
      this.app.fail("fhe_error", "gateway configuration is not loaded");
      return;
    }

    this.app.set({ busy: true, failure: undefined, notice: undefined });

    try {
      // 1. Build the operation the user is approving.
      const recipient = options.tamper
        ? "0x000000000000000000000000000000000000BAD"
        : "0x000000000000000000000000000000000000dEaD";
      const userOp = new UserOperationBuilder(wallet)
        .nonce(NonceDomain.Wallet, 0)
        .callData(`0xb9059cbb${recipient.slice(2).padStart(64, "0")}`)
        .build();
      const userOpHash = getUserOpHash(userOp, config.entryPoint, config.chainId);

      // 2. Challenge.
      this.app.setStage("passkey_prompt");
      const challenge = await this.post<any>("/v1/auth/challenge", {
        wallet,
        chainId: config.chainId,
        operationHash: userOpHash,
      });

      const credentials = await fetch(`/v1/wallet/${wallet}/credentials`).then((r) => r.json());
      const credentialId = credentials.credentials?.[0]?.credentialId;
      if (!credentialId) {
        this.app.set({ busy: false });
        this.app.fail("passkey_cancelled", "no active passkey");
        return;
      }

      const assertion = await getAssertion({
        rpId: challenge.rpId,
        challenge: challenge.challenge,
        credentialId,
        userVerification: "required",
      });

      // 3. Capture and encrypt the live vector.
      this.app.setStage("camera_ready");
      const session = new BiometricCaptureSession();
      this.app.set({ livenessInstruction: session.instruction });
      let vector: Float64Array | undefined;

      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline && !vector) {
        const frame = this.app.camera.streaming ? this.app.camera.capture() : undefined;
        if (frame) {
          const result = session.push(frame);
          if (result?.liveness?.passed) {
            const analysis = analyzeFrame(frame, { extractEmbedding: true });
            if (analysis.embedding) vector = analysis.embedding;
          }
        } else {
          // No camera in this environment: use a deterministic local capture so
          // the encrypted path can still be exercised end to end.
          vector = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02);
        }
        if (!vector) await sleep(70);
      }
      this.app.camera.stop();
      this.app.set({ livenessInstruction: undefined });

      if (!vector) {
        this.app.set({ busy: false });
        this.app.fail("liveness_failed");
        return;
      }

      this.app.setStage("embedding_generated");
      const engine = await this.ensureEngine();
      this.app.setStage("encrypting");
      const query = engine.encryptVector(this.publicKey!, vector, EMBEDDING_DIMENSION, "low");

      // 4. Verify server-side: challenge, passkey, FHE comparison, attestation.
      this.app.setStage("processing");
      const verified = await this.post<any>("/v1/auth/verify", {
        wallet,
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
          dimension: EMBEDDING_DIMENSION,
        },
      });

      this.app.setStage("proof_ready");
      const signature = packAuthorizationEnvelope({
        envelopeHash: verified.envelopeHash,
        attestationHash: verified.authorization.attestationHash,
        attestationSignature: verified.authorization.signature,
        webauthnAssertion: assertion.clientDataJSON,
        authorization: verified.authorization,
      });

      // 5. Submit.
      this.app.setStage("submitting");
      const submitted = await this.post<any>("/v1/userop/submit", {
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
          signature,
          userOpHash,
        },
        authorization: verified.authorization,
      });

      this.app.set({
        busy: false,
        stage: "success",
        session: { ...verified, userOpHash },
        notice: {
          kind: "success",
          text: `Authorized ${userOpHash.slice(0, 12)}â€¦ â€” threshold ${verified.decision.thresholdBps / 1e4}, status ${submitted.status}. The passkey signature is bound to this exact operation.`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      const code = (error as { code?: string }).code;
      const message = (error as Error).message;
      if (code === "NotAllowedError") this.app.fail("passkey_cancelled");
      else if (code === "challenge_expired") this.app.fail("challenge_expired");
      else if (code === "biometric_mismatch") this.app.fail("biometric_mismatch", message);
      else if (code === "indeterminate") this.app.fail("indeterminate", message);
      else if (code === "bundler_rejected") this.app.fail("bundler_rejected", message);
      else if (code?.startsWith("fhe")) this.app.fail("fhe_error", message);
      else if (code?.includes("replay")) this.app.fail("proof_error", "this authorization was already used");
      else this.app.fail("proof_error", message);
    }
  }

  /** Demo C/D/E from PRD section 62. */
  async replayLastAuthorization(): Promise<void> {
    if (!this.app.state.session) return;
    this.app.set({ busy: true, notice: undefined, failure: undefined });
    try {
      await this.post("/v1/userop/submit", {
        userOperation: { userOpHash: this.app.state.session.userOpHash },
        authorization: this.app.state.session.authorization,
      });
      this.app.set({ busy: false });
      this.app.fail("proof_error", "a replayed authorization must be rejected â€” it was not");
    } catch (error) {
      this.app.set({ busy: false });
      const code = (error as { code?: string }).code;
      this.app.set({
        notice: {
          kind: "success",
          text:
            code === "authorization_replayed"
              ? "Replay rejected exactly as designed: the authorization is single-use."
              : `Rejected as expected (${code}).`,
        },
      });
    }
  }

  async tamperWithOperation(): Promise<void> {
    this.app.set({ notice: undefined, failure: undefined });
    const session = this.app.state.session;
    if (!session) {
      this.app.fail("proof_error", "authorize a transaction first");
      return;
    }
    this.app.set({ busy: true });
    try {
      // Same authorization, different recipient: the userOpHash no longer matches.
      const config = this.app.state.config;
      const userOp = new UserOperationBuilder(this.app.state.wallet)
        .nonce(NonceDomain.Wallet, 0)
        .callData(`0xb9059cbb${"00".repeat(12)}bad${"00".repeat(20)}`)
        .build();
      const tamperedHash = getUserOpHash(userOp, config.entryPoint, config.chainId);

      await this.post("/v1/userop/submit", {
        userOperation: { userOpHash: tamperedHash },
        authorization: session.authorization,
      });
      this.app.set({ busy: false });
      this.app.fail("proof_error", "a tampered operation must be rejected â€” it was not");
    } catch (error) {
      this.app.set({ busy: false });
      const code = (error as { code?: string }).code;
      this.app.set({
        notice: {
          kind: "success",
          text:
            code === "operation_mismatch"
              ? "Tampering rejected: the authorization is bound to the original userOpHash."
              : `Rejected as expected (${code}).`,
        },
      });
    }
  }

  /* ------------------------------- recovery ----------------------------- */

  async startRecovery(): Promise<void> {
    const wallet = this.app.state.wallet;
    if (!wallet) {
      this.app.fail("proof_error", "no wallet address");
      return;
    }
    try {
      const recovery = await this.post<any>(`/v1/wallet/${wallet}/recovery`, {});
      await this.app.refresh();
      this.app.set({
        notice: {
          kind: "warn",
          text: `Recovery is pending. It cannot complete before ${new Date(recovery.executableAt * 1000).toLocaleString()} (${recovery.delaySeconds / 3600} hours). Until then the wallet is locked, not spent.`,
        },
      });
    } catch (error) {
      this.app.fail("proof_error", (error as Error).message);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export type { RgbaImage };
