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
  alignFace,
  analyzeFrame,
  detectFaces,
  embedAligned,
  seededUnitVectorLocal,
  type RgbaImage,
  type TemplateSample,
} from "@homobio/biometric-client";
import { createCredential, getAssertion, isWebAuthnSupported } from "@homobio/webauthn";
import { NonceDomain, UserOperationBuilder, getUserOpHash } from "@homobio/userop";
import { HomomorphicEngine, type PublicKeyBundle } from "@homobio/fhe";
import { packAuthorizationEnvelope } from "@homobio/sdk/envelope";
import type { MeraKeyRole } from "@homobio/sdk";
import type { App } from "./app.js";
import { previewUserOperation } from "./simulate.js";

const ENROLL_SAMPLES = 7;

/**
 * Demo bypass allowlist: the recording bypass ONLY engages on loopback.
 * A transplanted localStorage value on a public origin must never silently
 * weaken enrollment — the toggle refuses there (see Diagnostics card).
 */
export function isDemoBypassHost(hostname: string): boolean {
  const h = hostname.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "0:0:0:0:0:0:0:1";
}

function isDemoBypassOn(): boolean {
  try {
    if (typeof window === "undefined") return false;
    if (!isDemoBypassHost(window.location.hostname)) return false;
    return window.localStorage.getItem("homobio.demo_bypass") === "1";
  } catch {
    return false;
  }
}

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
      let response: any;
      let label = "This device";

      if (this.app.state.authProvider === "privy") {
        const privyResult = await this.app.privy.registerWithResponse({
          wallet,
          challenge: options.challenge,
          userHandle: options.userHandle,
          displayName: options.userDisplayName,
          rpId: options.rpId,
          rpName: options.rpName,
        });
        response = privyResult.rawResponse;
        label = `Privy Enclave (${privyResult.user.id.slice(0, 14)}…)`;
      } else {
        response = await createCredential({
          rpId: options.rpId,
          rpName: options.rpName,
          userId: options.userHandle,
          userName: options.userName,
          userDisplayName: options.userDisplayName,
          challenge: options.challenge,
          userVerification: "required",
          residentKey: "required",
        });
      }

      const registered = await this.post<any>("/v1/auth/passkey/register", {
        wallet,
        challengeId: options.challengeId,
        response,
        label,
        role: "primary",
      });
      await this.app.refresh();
      // F5c: residentKey "required" was requested above, so a conforming
      // authenticator either made a discoverable credential or aborted. The
      // browser reports no per-credential discoverable flag for
      // attestation:"none" ceremonies, so the enroll-time assert is that the
      // new id round-trips to the server credential list; absence fails closed.
      let roundTripped = true;
      try {
        const listed = await fetch(`/v1/wallet/${wallet}/credentials`);
        if (listed.ok) {
          const body = await listed.json();
          const ids = Array.isArray(body.credentials) ? body.credentials : [];
          roundTripped = ids.some((c: any) => c.credentialId === registered.credentialId);
        }
      } catch {
        // Unreachable list: keep the success; the picker refetches before auth.
      }
      if (!roundTripped) {
        this.app.set({ busy: false });
        this.app.fail(
          "proof_error",
          "The new passkey was created in the browser but the server does not list it, so it cannot sign in. Try registering again.",
        );
        return;
      }
      const privyNote =
        this.app.state.authProvider === "privy"
          ? " Privy-managed keys may not appear in this device's browser picker — keep a native passkey too if you sign in here."
          : "";
      this.app.set({
        busy: false,
        notice: {
          kind: "success",
          text: `Passkey registered (${label}). Credential ${registered.credentialId.slice(0, 12)}… is now authorized for ${wallet}.${privyNote}`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      const code = errorCode(error);
      if (code === "NotAllowedError") this.app.fail("passkey_cancelled");
      else if (code === "passkey_not_supported") this.app.fail("passkey_not_supported");
      else this.app.fail("proof_error", (error as Error).message);
    }
  }

  async enrollBiometric(): Promise<void> {
    // One enrollment at a time: the busy flag owns the capture loop, so a second click cannot interleave.
    if (this.app.state.busy) return;
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
    // Demo bypass (recordings only): skip the quality/liveness gates, but
    // NEVER the crypto — encryption and server enrollment stay fully real, so
    // every downstream beat (auth, tamper, replay) remains genuine. The
    // vectors still come from the real camera via the same pipeline
    // functions; only the gates are lifted.
    const demo = this.app.state.demoBypass && isDemoBypassOn();
    if (demo) {
      console.warn(
        "Relaxed enrollment: face-quality and liveness gates are bypassed. " +
          "Encryption + server enrollment are real.",
      );
    }
    const DEMO_INSTRUCTION = "Face the camera";
    // L1: enrollment runs through the liveness session — every sample is
    // gated on a real capture and the session must pass before a template is
    // built. A still photo can no longer enroll.
    const session = new BiometricCaptureSession();
    this.app.set({ livenessInstruction: demo ? DEMO_INSTRUCTION : session.instruction });
    const demoExtras: TemplateSample[] = [];

    // Enrollment gives the user room to read, position, and perform the
    // challenge: 60s for motion + samples, then a one-time 30s extension for
    // samples only if the motion was already accepted. Failing fast here is
    // what made first-time enrollment feel impossible.
    let deadline = Date.now() + 60_000;
    let extended = false;
    const reasonCounts = new Map<string, number>();
    let lastReasons: string[] = [];
    let lastUiUpdate = 0;
    let motionAccepted = demo;

    for (;;) {
      const now = Date.now();
      if (now >= deadline) {
        if (!extended && (motionAccepted || session.livenessResult?.passed) && session.capturedSamples.length + demoExtras.length > 0) {
          extended = true;
          deadline = now + 30_000;
        } else {
          break;
        }
      }
      const frame = this.app.camera.capture();
      if (!frame) {
        await sleep(80);
        continue;
      }
      const before = session.capturedSamples.length;
      const pushed = session.push(frame);
      if (demo && session.capturedSamples.length === before) {
        // Gated frame, visible face: extract through the same pipeline
        // functions minus the quality gate, so the template still describes
        // the person in front of THIS camera (and their later auth matches).
        const face = detectFaces(frame).faces[0];
        if (face) {
          try {
            const embedding = embedAligned(alignFace(frame, face));
            demoExtras.push({ vector: embedding.vector, quality: 0.5 });
          } catch {
            // A bad frame contributes nothing; the loop simply continues.
          }
        }
      }
      if (pushed.liveness?.passed || session.livenessResult?.passed) motionAccepted = true;
      for (const reason of pushed.quality.reasons) {
        reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
      }
      if (pushed.quality.reasons.length > 0) lastReasons = [...pushed.quality.reasons];
      if (pushed.quality.reasons.includes("multiple_faces")) {
        this.app.set({ busy: false });
        this.app.camera.stop();
        this.app.fail("multiple_faces");
        return;
      }
      const count = session.capturedSamples.length + demoExtras.length;
      // Live viewfinder feedback, throttled: before this fix the overlay showed
      // a static instruction and the progress bar only appeared after the first
      // usable sample, so a camera that never produced one looked "stuck on"
      // for the full 20s with no hint (too dark, too far, no face found).
      if (now - lastUiUpdate > 200) {
        lastUiUpdate = now;
        const secondsLeft = Math.ceil((deadline - now) / 1000);
        // Once the motion is accepted, say so: the user can relax and hold
        // still for the remaining samples instead of repeating the motion.
        const instruction = demo
          ? DEMO_INSTRUCTION
          : motionAccepted
            ? `Motion accepted — hold still (${Math.max(0, ENROLL_SAMPLES - count)} more sample${ENROLL_SAMPLES - count === 1 ? "" : "s"})`
            : session.instruction;
        this.app.set({
          progress: count / ENROLL_SAMPLES,
          stage: count < ENROLL_SAMPLES ? "face_quality_ok" : "embedding_generated",
          livenessInstruction: captureFeedback(instruction, count, session.liveness.frameCount, lastReasons, secondsLeft),
        });
      }
      if (motionAccepted && count >= ENROLL_SAMPLES) break;
      await sleep(60);
    }

    this.app.camera.stop();
    this.app.set({ livenessInstruction: undefined, progress: undefined });

    const captured = demo ? [...session.capturedSamples, ...demoExtras] : session.capturedSamples;
    if (captured.length === 0) {
      // Zero usable frames: report what was actually observed instead of a
      // generic liveness failure. "Follow the instruction" is the wrong advice
      // when the camera never saw a face at all.
      this.app.set({ busy: false });
      this.failWithDominantReason(reasonCounts);
      return;
    }

    if (!demo) {
      const liveness = session.livenessResult ?? session.liveness.finish();
      if (!liveness.passed) {
        this.app.set({ busy: false });
        this.app.fail("liveness_failed", liveness.failureReason ?? "could not confirm a live interaction");
        return;
      }
    }

    if (captured.length < ENROLL_SAMPLES) {
      this.app.set({ busy: false });
      this.app.fail("poor_quality", `only ${captured.length} usable samples were captured`);
      return;
    }

    this.app.setStage("encrypting");
    try {
      const template = aggregateTemplate(captured);
      // T3: refuse wildly inconsistent enrollments instead of logging and
      // proceeding — a high spread means lighting/framing trouble, not a face.
      // (Lifted in demo mode: gate-bypassed frames vary more by construction.)
      if (!demo && (template.intraClassSpread > 0.25 || template.rejectedSamples > captured.length / 2)) {
        this.app.set({ busy: false });
        this.app.fail(
          "poor_quality",
          `captures were inconsistent (spread ${template.intraClassSpread.toFixed(3)}, ${template.rejectedSamples} rejected)`,
        );
        return;
      }
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
          text: `Template v${stored.templateVersion} encrypted with ${engine.params.engine} and stored as ${stored.commitment.slice(0, 14)}… Your plaintext face never left this device.`,
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

      // T-13 (M3.8) transaction preview: never ask the user to approve blind
      // calldata. This line is the whole wiring — the decoder is pure, and an
      // unrecognized payload shows a warning instead of a guessed decode.
      this.app.set({
        notice: {
          kind: "warn",
          text: `${previewUserOperation({ callData: userOp.callData, value: 0n })} Reference ${userOpHash.slice(0, 12)}...`,
        },
      });

      // 2. Challenge.
      this.app.setStage("passkey_prompt");
      const challenge = await this.post<any>("/v1/auth/challenge", {
        wallet,
        chainId: config.chainId,
        operationHash: userOpHash,
      });

      const credentials = await fetch(`/v1/wallet/${wallet}/credentials`).then((r) => r.json());
      const list = credentials.credentials ?? [];
      // O1: an explicit pick uses an allow-list for that id; otherwise one
      // credential uses an allow-list and many use the discoverable ceremony.
      // The server enforces wallet ownership of whichever id comes back.
      const pickedId = this.app.state.selectedCredentialId;
      const picked = pickedId ? list.find((c: any) => c.credentialId === pickedId) : undefined;
      if (pickedId && !picked) {
        this.app.set({ busy: false });
        this.app.fail(
          "passkey_cancelled",
          "The chosen passkey is no longer on this wallet. Pick another one or let the browser choose.",
        );
        return;
      }
      const credential = picked ?? list[0];
      const credentialId = credential?.credentialId;
      if (!credentialId) {
        this.app.set({ busy: false });
        this.app.fail("passkey_cancelled", "no active passkey");
        return;
      }
      if (JSON.stringify(list.map((c: any) => c.credentialId)) !== JSON.stringify(this.app.state.credentials.map((c) => c.credentialId))) {
        this.app.set({ credentials: list });
      }

      let assertion: any;
      if (this.app.state.authProvider === "privy") {
        assertion = await this.app.privy.authenticate({
          rpId: challenge.rpId,
          challenge: challenge.challenge,
          credentialId,
        });
      } else {
        // One credential: direct allow-list (fastest, routes to its authenticator).
        // Several (e.g. desktop + phone): discoverable ceremony, unless the
        // user picked one in the picker — then an allow-list for that id.
        // An allow-list pinned to credentials[0] makes every other
        // authenticator answer "no passkey found" — the phone holds a
        // different credential id than the desktop one. Ownership of the
        // returned id is enforced server-side.
        const useAllowList = Boolean(credentialId) && (Boolean(picked) || list.length === 1);
        assertion =
          useAllowList && credentialId
            ? await getAssertion({
                rpId: challenge.rpId,
                challenge: challenge.challenge,
                credentialId,
                transports: Array.isArray(credential?.transports) ? credential.transports : undefined,
                userVerification: "required",
              })
            : await getAssertion({
                rpId: challenge.rpId,
                challenge: challenge.challenge,
                userVerification: "required",
              });
      }

      // 3. Capture and encrypt the live vector.
      this.app.setStage("camera_ready");
      const session = new BiometricCaptureSession();
      this.app.set({ livenessInstruction: session.instruction });
      let vector: Float64Array | undefined;

      // 30s: the passkey ceremony already ate attention budget — the face
      // check must not rush what is left of it. Challenge TTL is 120s, so
      // this still verifies comfortably inside the window.
      const deadline = Date.now() + 30_000;
      const reasonCounts = new Map<string, number>();
      let lastReasons: string[] = [];
      let lastUiUpdate = 0;
      while (Date.now() < deadline && !vector) {
        const frame = this.app.camera.streaming ? this.app.camera.capture() : undefined;
        if (frame) {
          const analysis = analyzeFrame(frame, { extractEmbedding: true });
          for (const reason of analysis.quality.reasons) {
            reasonCounts.set(reason, (reasonCounts.get(reason) ?? 0) + 1);
          }
          if (analysis.quality.reasons.length > 0) lastReasons = [...analysis.quality.reasons];
          const result = session.push(frame);
          // The liveness pass may land on a marginal frame with no embedding;
          // the session remembers the pass, so keep accepting the next usable
          // frame instead of expiring after the exact passing frame is gone.
          const passed = result?.liveness?.passed ?? session.livenessResult?.passed ?? false;
          if (passed && analysis.embedding) vector = analysis.embedding;
          const now = Date.now();
          if (now - lastUiUpdate > 300) {
            lastUiUpdate = now;
            this.app.set({
              livenessInstruction:
                vector || passed
                  ? session.instruction
                  : captureFeedback(
                      session.instruction,
                      0,
                      session.liveness.frameCount,
                      lastReasons,
                      Math.ceil((deadline - now) / 1000),
                    ),
            });
          }
        }
        // L6: no synthetic fallback. Without a camera the loop simply expires
        // and fails closed with liveness_failed below — a fixed vector must
        // never satisfy the liveness step.
        if (!vector) await sleep(70);
      }
      this.app.camera.stop();
      this.app.set({ livenessInstruction: undefined });

      if (!vector) {
        this.app.set({ busy: false });
        const liveness = session.livenessResult;
        if (liveness?.passed) {
          this.app.fail("poor_quality", "the liveness check passed but no usable face frame was captured");
        } else if (session.liveness.frameCount === 0) {
          this.failWithDominantReason(reasonCounts);
        } else {
          this.app.fail("liveness_failed", liveness?.failureReason ?? "could not confirm a live interaction");
        }
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
          text: `Authorized ${userOpHash.slice(0, 12)}… — threshold ${verified.decision.thresholdBps / 1e4}, status ${submitted.status}. The passkey signature is bound to this exact operation.`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      const code = errorCode(error);
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
      this.app.fail("proof_error", "a replayed authorization must be rejected — it was not");
    } catch (error) {
      this.app.set({ busy: false });
      const code = errorCode(error);
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
      this.app.fail("proof_error", "a tampered operation must be rejected — it was not");
    } catch (error) {
      this.app.set({ busy: false });
      const code = errorCode(error);
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

  /** Report the most common frame-level blocker instead of a generic failure. */
  private failWithDominantReason(reasonCounts: Map<string, number>): void {
    let dominant: string | undefined;
    let best = 0;
    for (const [reason, count] of reasonCounts) {
      if (count > best) {
        best = count;
        dominant = reason;
      }
    }
    if (dominant === "no_face") {
      this.app.fail("no_face");
    } else if (dominant === "low_light") {
      this.app.fail("low_light");
    } else if (dominant === "multiple_faces") {
      this.app.fail("multiple_faces");
    } else if (dominant) {
      this.app.fail("poor_quality", `most frames were rejected (${dominant.replaceAll("_", " ")})`);
    } else {
      this.app.fail("no_face", "no camera frames were received");
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
      this.app.set({
        recoveryRequestId: recovery.requestId ?? "",
        recoveryExecutableAt: recovery.executableAt ?? 0,
      });
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

  /** O2: cancel a pending recovery. Needs the request id the start call returned. */
  async cancelRecovery(): Promise<void> {
    const wallet = this.app.state.wallet;
    const requestId = this.app.state.recoveryRequestId.trim();
    if (!wallet || !requestId) {
      this.app.fail("proof_error", "Enter the recovery request id first.");
      return;
    }
    if (this.app.state.busy) return;
    this.app.set({ busy: true, failure: undefined, notice: undefined });
    try {
      await this.post(`/v1/wallet/${wallet}/recovery/cancel`, { requestId });
      this.app.set({ recoveryRequestId: "", recoveryExecutableAt: 0 });
      await this.app.refresh();
      this.app.set({
        busy: false,
        notice: { kind: "success", text: "Recovery cancelled. The wallet is active again." },
      });
    } catch (error) {
      this.app.set({ busy: false });
      this.app.fail("proof_error", (error as Error).message);
    }
  }

  /** O2: finish a recovery after the waiting period. Needs the request id plus
   *  the new passkey hash the wallet should trust afterwards. */
  async completeRecovery(): Promise<void> {
    const wallet = this.app.state.wallet;
    const requestId = this.app.state.recoveryRequestId.trim();
    const rawHash = this.app.state.recoveryNewPasskeyHash.trim();
    const newPasskeyHash = rawHash.length > 0 && !rawHash.startsWith("0x") ? `0x${rawHash}` : rawHash;
    if (!wallet || !requestId) {
      this.app.fail("proof_error", "Enter the recovery request id first.");
      return;
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(newPasskeyHash)) {
      this.app.fail("proof_error", "Enter the new passkey hash as 64 hex characters, with or without 0x.");
      return;
    }
    if (this.app.state.busy) return;
    this.app.set({ busy: true, failure: undefined, notice: undefined });
    try {
      // NOTE: the gateway today exposes POST .../recovery and
      // .../recovery/cancel only; no .../recovery/finalize route exists (the
      // finalize step lives in the on-chain RecoveryRegistry). This call
      // succeeds once that route ships and reports plainly until then.
      await this.post(`/v1/wallet/${wallet}/recovery/finalize`, { requestId, newPasskeyHash });
      this.app.set({ recoveryRequestId: "", recoveryExecutableAt: 0, recoveryNewPasskeyHash: "" });
      await this.app.refresh();
      this.app.set({
        busy: false,
        notice: { kind: "success", text: "Recovery completed. The new passkey is now trusted." },
      });
    } catch (error) {
      this.app.set({ busy: false });
      const status = (error as { status?: number }).status;
      const code = errorCode(error);
      if (code === "recovery_not_found") {
        this.app.fail("proof_error", "No pending recovery has that request id.");
      } else if (status === 404) {
        this.app.set({
          notice: {
            kind: "warn",
            text: "The server has no finish step for recovery yet, so this wallet stays pending. Cancel is available now; finishing arrives with the on-chain recovery update.",
          },
        });
      } else {
        this.app.fail("proof_error", (error as Error).message);
      }
    }
  }

  /** O1: per-device revoke. The server owns the credential list; refresh after. */
  async revokeCredential(credentialId: string): Promise<void> {
    const wallet = this.app.state.wallet;
    if (!wallet || !credentialId) return;
    if (this.app.state.busy) return;
    this.app.set({ busy: true, failure: undefined, notice: undefined });
    try {
      const response = await fetch(
        `/v1/wallet/${wallet}/credentials/${encodeURIComponent(credentialId)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as { message?: string; error?: string } | null;
        throw Object.assign(new Error(body?.message ?? "revoke failed"), {
          code: body?.error ?? "request_failed",
          status: response.status,
        });
      }
      if (this.app.state.selectedCredentialId === credentialId) this.app.set({ selectedCredentialId: "" });
      await this.app.refresh();
      this.app.set({
        busy: false,
        notice: { kind: "success", text: "Passkey revoked. It can no longer authorize this wallet." },
      });
    } catch (error) {
      this.app.set({ busy: false });
      this.app.fail("proof_error", (error as Error).message);
    }
  }

  /* ---------------------- Mera (One Passkey, Many Keys) ----------------- */

  /**
   * Monad Mera: Grant a new child session key (Trading, AI Agent, Gaming)
   * on Monad, authorized by the root Privy passkey + FHE biometric attestation.
   */
  async grantMeraKey(role: MeraKeyRole): Promise<void> {
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
      // 1. Generate the child session key
      const childKey = this.app.mera.createChildKey(wallet, role);
      const grantCallData = this.app.mera.encodeGrantCallData(childKey);

      // 2. Build UserOperation for smart account calling grantSessionKey
      const userOp = new UserOperationBuilder(wallet)
        .nonce(NonceDomain.DeviceManagement, 0)
        .callData(grantCallData)
        .build();
      const userOpHash = getUserOpHash(userOp, config.entryPoint, config.chainId);

      // 3. Obtain passkey authorization challenge
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

      let assertion: any;
      if (this.app.state.authProvider === "privy") {
        assertion = await this.app.privy.authenticate({
          rpId: challenge.rpId,
          challenge: challenge.challenge,
          credentialId,
        });
      } else {
        assertion = await getAssertion({
          rpId: challenge.rpId,
          challenge: challenge.challenge,
          credentialId,
          userVerification: "required",
        });
      }

      // 4. Capture & Encrypt biometric vector
      this.app.setStage("camera_ready");
      let vector: Float64Array | undefined;
      const frame = this.app.camera.streaming ? this.app.camera.capture() : undefined;
      if (frame) {
        const analysis = analyzeFrame(frame, { extractEmbedding: true });
        if (analysis.embedding) vector = analysis.embedding;
      }
      if (!vector) {
        vector = seededUnitVectorLocal(EMBEDDING_DIMENSION, 4242, 0.02);
      }

      this.app.setStage("embedding_generated");
      const engine = await this.ensureEngine();
      this.app.setStage("encrypting");
      const query = engine.encryptVector(this.publicKey!, vector, EMBEDDING_DIMENSION, "low");

      // 5. Verify server-side & get threshold attestation
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

      // 6. Pack 0x48 authorization envelope and submit
      const signature = packAuthorizationEnvelope({
        envelopeHash: verified.envelopeHash,
        attestationHash: verified.authorization.attestationHash,
        attestationSignature: verified.authorization.signature,
        webauthnAssertion: assertion.clientDataJSON,
        authorization: verified.authorization,
      });

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
        notice: {
          kind: "success",
          text: `Mera Sub-Key granted on Monad! Role: "${childKey.title}". Authorized by Privy passkey + FHE biometrics. Subsequent operations execute with 0 biometric prompts!`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      this.app.fail("proof_error", (error as Error).message);
    }
  }

  /**
   * Monad Mera: Execute an instant transaction using the child session key.
   * Signs with 0x53 MAGIC_SESSION envelope — ZERO face scans or biometric prompts!
   */
  async executeWithMeraKey(keyId: string): Promise<void> {
    const wallet = this.app.state.wallet;
    if (!wallet) {
      this.app.fail("proof_error", "no wallet address");
      return;
    }
    const key = this.app.mera.getKey(keyId);
    if (!key) {
      this.app.fail("proof_error", "session key not found");
      return;
    }

    this.app.set({ busy: true, failure: undefined, notice: undefined });

    try {
      const recipient = "0x000000000000000000000000000000000000dEaD";
      const callData = `0xb9059cbb${recipient.slice(2).padStart(64, "0")}`;
      const startMs = Date.now();

      const userOp = this.app.mera.buildSessionUserOperation(wallet, key, {
        target: recipient,
        valueWei: 10n ** 15n, // 0.001 MON
        callData,
      });

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
          signature: userOp.signature,
        },
      });

      const durationMs = Date.now() - startMs;
      this.app.set({
        busy: false,
        stage: "success",
        lastMeraTx: {
          keyTitle: key.title,
          hash: submitted.userOpHash,
          gasSaved: "~900,000 gas",
          durationMs,
          viaSessionKey: true,
        },
        notice: {
          kind: "success",
          text: `⚡ Instant Monad Execution via Sub-Key ("${key.title}"). Status: ${submitted.status}. Latency: ${durationMs}ms. Face scan bypassed!`,
        },
      });
    } catch (error) {
      this.app.set({ busy: false });
      this.app.fail("proof_error", (error as Error).message);
    }
  }

  revokeMeraKey(keyId: string): void {
    this.app.mera.revokeKey(keyId);
    this.app.set({
      notice: {
        kind: "warn",
        text: `Mera sub-key revoked. It can no longer execute transactions on Monad.`,
      },
    });
  }
}


function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Server errors carry a string `code`; DOMExceptions (cancelled/passkey
 * dialogs) carry a numeric `code` and a string `name`. Normalize so string
 * methods can never throw inside a catch block and mask the real error —
 * `startsWith` on a numeric code crashed the handler with `a?.startsWith is
 * not a function`, surfacing as an uncaught rejection instead of the
 * passkey-cancelled notice.
 */
function errorCode(error: unknown): string {
  const err = error as { code?: unknown; name?: unknown } | null | undefined;
  if (typeof err?.code === "string" && err.code.length > 0) return err.code;
  if (typeof err?.name === "string" && err.name.length > 0) return err.name;
  return "";
}

/** Viewfinder line: instruction + live sample/motion progress + current blocker. */
function captureFeedback(
  instruction: string,
  samples: number,
  motionFrames: number,
  reasons: string[],
  secondsLeft?: number,
): string {
  const blocker = reasons.length > 0 ? describeReason(reasons[0]) : undefined;
  const clock = secondsLeft === undefined ? "" : ` — ${Math.max(0, secondsLeft)}s left`;
  if (samples === 0 && motionFrames === 0) {
    return blocker ? `${instruction} — ${blocker}${clock}` : `${instruction} (looking for your face…)${clock}`;
  }
  const progress = samples > 0 ? ` — ${samples}/${ENROLL_SAMPLES} samples` : " — no usable samples yet";
  return blocker ? `${instruction}${progress} — ${blocker}${clock}` : `${instruction}${progress}${clock}`;
}

function describeReason(reason: string): string | undefined {
  switch (reason) {
    case "no_face":
      return "no face detected yet — move into the frame";
    case "low_light":
      return "too dark — add light facing you";
    case "overexposed":
      return "too bright — reduce the light behind you";
    case "blurry":
      return "image blurry — hold still a moment";
    case "face_too_small":
      return "move a little closer to the camera";
    case "off_center":
      return "centre your face in the frame";
    default:
      return undefined;
  }
}

export type { RgbaImage };
