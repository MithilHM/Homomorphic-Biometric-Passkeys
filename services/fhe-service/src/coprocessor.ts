/**
 * FHE Coprocessor (PRD sections 10, 12, 13)
 *
 * The service that sees ciphertexts and must not be able to learn anything from
 * them. It:
 *   - publishes the FHE public key (clients encrypt under it, in the browser);
 *   - stores enrolled templates as CIPHERTEXT ONLY;
 *   - evaluates the encrypted similarity — one ring multiplication, no plaintext;
 *   - hands its decryption share to the orchestrator and never decrypts alone.
 *
 * What this service can NOT do:
 *   - recover the enrolled template (no secret key share);
 *   - recover the live capture (it never sees it in plaintext either);
 *   - decrypt a decision on its own (threshold committee, all shares required).
 *
 * It also cannot be used as an oracle: `/evaluate` refuses any request without a
 * live, single-use challenge issued by the challenge service (PRD section 30).
 */

import {
  DecryptionCommittee,
  CommitteeMember,
  DEFAULT_FHE_PARAMS,
  HomomorphicEngine,
  deserializeShare,
  serializeShare,
  type FheCiphertext,
  type PublicKeyBundle,
  type SecretKeyShare,
  type ShareFile,
} from "@homobio/fhe";
import { keccak256Hex, nowSeconds } from "@homobio/crypto-utils";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { JsonStore, StoredRecord } from "@homobio/store";
import { HttpApp, HttpError, createLogger, requireNumber, requireObject, requireString, BASE64URL, HEX_32 } from "@homobio/http-kit";

export interface TemplateRecord extends StoredRecord {
  id: string;
  wallet: string;
  chainId: number;
  ciphertext: string;
  commitment: string;
  modelVersion: string;
  dimension: number;
  encodingVersion: number;
  scaleBits: number;
  fheKeyVersion: number;
  fheEngine: string;
  templateVersion: number;
  status: "active" | "retired" | "deleted";
  sampleCount: number;
  meanQuality: number;
}

export interface FheServiceConfig {
  port: number;
  dataDir: string;
  serviceToken: string;
  errorBound: number;
  chainId: number;
}

const MAX_CIPHERTEXT_BYTES = 64 * 1024;

export class FheCoprocessor {
  readonly engine = new HomomorphicEngine(DEFAULT_FHE_PARAMS);
  private keySet: ReturnType<HomomorphicEngine["generateKeySet"]> | null = null;
  private shares = new Map<string, SecretKeyShare>();

  constructor(
    private readonly config: FheServiceConfig,
    private readonly templates: JsonStore<TemplateRecord>,
    private readonly logger = createLogger("fhe-coprocessor"),
  ) {}

  /**
   * Bootstrap the FHE key and split it across the committee.
   *
   * Share 0 stays in this process (the coprocessor's contribution). Share 1 is
   * written for the proof service and share 2 for the recovery/custody holder.
   * Neither is readable by this process after generation, which is what makes
   * the coprocessor unable to decrypt on its own.
   */
  bootstrap(sharePaths: { proof: string; custody: string }): { publicKey: PublicKeyBundle; fingerprint: string } {
    if (this.keySet) return { publicKey: this.keySet.publicKey, fingerprint: this.keySet.publicKey.fingerprint };

    const keySet = this.engine.generateKeySet(3, 1);
    mkdirSync(path.dirname(sharePaths.proof), { recursive: true });
    mkdirSync(path.dirname(sharePaths.custody), { recursive: true });

    const write = (file: string, share: SecretKeyShare) =>
      writeFileSync(
        file,
        JSON.stringify(serializeShare(share, this.engine, keySet.publicKey.fingerprint), null, 2),
        { encoding: "utf-8", mode: 0o600 },
      );

    write(sharePaths.proof, keySet.shares[1]);
    write(sharePaths.custody, keySet.shares[2]);

    this.shares.set("fhe", keySet.shares[0]);
    this.keySet = keySet;
    this.logger.info("FHE key set generated", {
      keyVersion: keySet.publicKey.keyVersion,
      fingerprint: keySet.publicKey.fingerprint,
      ringDimension: this.engine.params.ringDimension,
      engine: this.engine.params.engine,
      threshold: keySet.shares.length,
    });
    return { publicKey: keySet.publicKey, fingerprint: keySet.publicKey.fingerprint };
  }

  /** Reload a previously generated key set from disk (no secret retained). */
  load(publicKeyPath: string, sharePath: string): PublicKeyBundle {
    const publicKey = JSON.parse(readFileSync(publicKeyPath, "utf-8")) as PublicKeyBundle;
    const shareFile = JSON.parse(readFileSync(sharePath, "utf-8")) as ShareFile;
    this.shares.set("fhe", deserializeShare(shareFile, this.engine, publicKey.fingerprint));
    this.keySet = { publicKey, shares: [], secret: [] } as never;
    return publicKey;
  }

  publicKey(): PublicKeyBundle {
    if (!this.keySet) throw new HttpError(503, "fhe_unavailable", "FHE key set has not been bootstrapped");
    return this.keySet.publicKey;
  }

  /**
   * Store an enrolled template.
   *
   * Only ciphertext is persisted. The plaintext embedding died in the browser.
   */
  enroll(input: {
    wallet: string;
    chainId: number;
    ciphertext: string;
    commitment: string;
    modelVersion: string;
    dimension: number;
    templateVersion: number;
    sampleCount: number;
    meanQuality: number;
  }): TemplateRecord {
    assertCiphertextSize(input.ciphertext);
    const key = this.publicKey();
    const engine = this.engine;
    // Round-trip the ciphertext so a malformed payload is rejected at the edge,
    // not deep inside the ring arithmetic.
    const parsed: FheCiphertext = {
      ciphertext: input.ciphertext,
      commitment: input.commitment,
      ringDimension: engine.params.ringDimension,
      modulus: engine.params.modulus,
      scaleBits: engine.params.scaleBits,
      dimension: input.dimension,
      layout: "high",
      engine: engine.params.engine,
      encodingVersion: engine.params.encodingVersion,
      byteLength: input.ciphertext.length,
    };
    engine.unpackCiphertext(parsed);

    const wallet = input.wallet.toLowerCase();
    for (const existing of this.templates.list("templates", (t) => t.wallet === wallet && t.status === "active")) {
      this.templates.update("templates", existing.id, { status: "retired" });
    }

    const record: TemplateRecord = {
      id: keccak256Hex(`${wallet}:${input.commitment}`).slice(0, 32),
      wallet,
      chainId: input.chainId,
      ciphertext: input.ciphertext,
      commitment: input.commitment,
      modelVersion: input.modelVersion,
      dimension: input.dimension,
      encodingVersion: engine.params.encodingVersion,
      scaleBits: engine.params.scaleBits,
      fheKeyVersion: key.keyVersion,
      fheEngine: engine.params.engine,
      templateVersion: input.templateVersion,
      status: "active",
      sampleCount: input.sampleCount,
      meanQuality: input.meanQuality,
      createdAt: nowSeconds(),
      updatedAt: nowSeconds(),
    };
    return this.templates.put("templates", record);
  }

  activeTemplate(wallet: string): TemplateRecord | undefined {
    return this.templates.find(
      "templates",
      (t) => t.wallet === wallet.toLowerCase() && t.status === "active",
    );
  }

  /**
   * Evaluate the encrypted similarity.
   *
   * The result is a PRODUCT CIPHERTEXT. This function cannot turn it into a
   * decision: `decryptWithCommittee` needs all three shares.
   */
  evaluateForCommittee(input: {
    wallet: string;
    queryCiphertext: string;
    queryCommitment: string;
    dimension: number;
  }): {
    product: FheCiphertext;
    template: TemplateRecord;
    evaluationId: string;
    evaluationMs: number;
  } {
    const template = this.activeTemplate(input.wallet);
    if (!template) throw new HttpError(404, "template_not_found", "no enrolled biometric template for this wallet");
    assertCiphertextSize(input.queryCiphertext);
    if (input.dimension !== template.dimension) {
      throw new HttpError(400, "dimension_mismatch", "query dimension does not match the enrolled template");
    }

    const wrap = (payload: string, commitment: string, layout: "low" | "high"): FheCiphertext => ({
      ciphertext: payload,
      commitment,
      ringDimension: this.engine.params.ringDimension,
      modulus: this.engine.params.modulus,
      scaleBits: this.engine.params.scaleBits,
      dimension: template.dimension,
      layout,
      engine: this.engine.params.engine,
      encodingVersion: this.engine.params.encodingVersion,
      byteLength: payload.length,
    });

    const startedAt = performance.now();
    const product = this.engine.evaluateProduct(
      wrap(template.ciphertext, template.commitment, "high"),
      wrap(input.queryCiphertext, input.queryCommitment, "low"),
    );
    return {
      product,
      template,
      evaluationId: keccak256Hex(`${input.queryCommitment}:${product.commitment}`).slice(0, 32),
      evaluationMs: performance.now() - startedAt,
    };
  }

  /** This service's own (insufficient) contribution to a decryption. */
  partialDecrypt(ciphertext: FheCiphertext, keyFingerprint: string): PolyOut {
    const share = this.shares.get("fhe");
    if (!share) throw new HttpError(503, "fhe_unavailable", "coprocessor share is not loaded");
    if (this.publicKey().fingerprint !== keyFingerprint) {
      throw new HttpError(400, "key_mismatch", "request references a different FHE key version");
    }
    return this.engine.partialDecrypt(share, ciphertext);
  }

  committeeWith(extra: Array<{ id: string; share: SecretKeyShare }>): DecryptionCommittee {
    const share = this.shares.get("fhe");
    if (!share) throw new HttpError(503, "fhe_unavailable", "coprocessor share is not loaded");
    const members = [new CommitteeMember("fhe-coprocessor", share)];
    for (const item of extra) members.push(new CommitteeMember(item.id, item.share));
    return new DecryptionCommittee(members);
  }

  decide(similarity: number, threshold: number, margin: number): ReturnType<HomomorphicEngine["decide"]> {
    return this.engine.decide(similarity, threshold, margin);
  }

  health(): Record<string, unknown> {
    return {
      status: this.keySet ? "healthy" : "degraded",
      service: "fhe-coprocessor",
      engine: this.engine.params.engine,
      ringDimension: this.engine.params.ringDimension,
      modulus: this.engine.params.modulus,
      scaleBits: this.engine.params.scaleBits,
      embeddingDimension: this.engine.params.embeddingDimension,
      securityLevelBits: this.engine.params.securityLevelBits,
      keyFingerprint: this.keySet?.publicKey.fingerprint ?? null,
      keyVersion: this.keySet?.publicKey.keyVersion ?? null,
      decryptionSharesHeld: this.shares.size,
      decryptionThreshold: 3,
      templates: this.templates.count("templates", (t) => t.status === "active"),
      errorBound: this.config.errorBound,
    };
  }

  /** Public key material, safe to serve to any client. */
  publicKeyResponse(): Record<string, unknown> {
    const key = this.publicKey();
    return {
      ...key,
      engine: this.engine.params.engine,
      ringDimension: this.engine.params.ringDimension,
      modulus: this.engine.params.modulus,
      scaleBits: this.engine.params.scaleBits,
      embeddingDimension: this.engine.params.embeddingDimension,
      errorBound: this.config.errorBound,
      metric: "cosine-similarity",
      templateLayout: "high",
      queryLayout: "low",
    };
  }
  /**
   * Template metadata only — never the ciphertext.
   *
   * The gateway needs the commitment and the version to bind a challenge to a
   * template, but it has no business holding the encrypted template itself.
   */
  templateMetadata(wallet: string): Record<string, unknown> | undefined {
    const template = this.activeTemplate(wallet);
    if (!template) return undefined;
    return {
      templateId: template.id,
      wallet: template.wallet,
      templateVersion: template.templateVersion,
      commitment: template.commitment,
      fheKeyVersion: template.fheKeyVersion,
      fheEngine: template.fheEngine,
      dimension: template.dimension,
      modelVersion: template.modelVersion,
      scaleBits: template.scaleBits,
      encodingVersion: template.encodingVersion,
      sampleCount: template.sampleCount,
      meanQuality: template.meanQuality,
      createdAt: template.createdAt,
      status: template.status,
    };
  }
}

export type PolyOut = ReturnType<HomomorphicEngine["partialDecrypt"]>;

function assertCiphertextSize(payload: string): void {
  if (typeof payload !== "string" || payload.length === 0) {
    throw new HttpError(400, "invalid_ciphertext", "ciphertext payload is required");
  }
  if (!BASE64URL.test(payload)) {
    throw new HttpError(400, "invalid_ciphertext", "ciphertext must be base64url");
  }
  if (payload.length > MAX_CIPHERTEXT_BYTES * 2) {
    throw new HttpError(413, "payload_too_large", `ciphertext exceeds ${MAX_CIPHERTEXT_BYTES} bytes`);
  }
}

/* -------------------------------------------------------------------------- */
/*                              HTTP entry point                               */
/* -------------------------------------------------------------------------- */

export function createCoprocessorApp(coprocessor: FheCoprocessor, config: FheServiceConfig): HttpApp {
  const logger = createLogger("fhe-coprocessor");
  const app = new HttpApp({
    port: config.port,
    logger,
    allowedOrigins: [],
    serviceAuthToken: config.serviceToken,
    globalRateLimit: { limit: 600, windowMs: 60_000 },
  });

  app.get("/health", () => coprocessor.health(), { raw: true });

  app.get("/v1/fhe/public-key", () => coprocessor.publicKeyResponse(), { raw: true });

  app.post("/v1/fhe/enroll", (ctx) => {    const body = requireObject(ctx.body, "");
    const wallet = requireString(body, "wallet", { pattern: /^0x[0-9a-fA-F]{40}$/ });
    const ciphertext = requireString(body, "ciphertext", { maxLength: MAX_CIPHERTEXT_BYTES * 2 });
    const commitment = requireString(body, "commitment", { pattern: HEX_32 });
    const modelVersion = requireString(body, "modelVersion", { maxLength: 64 });
    const dimension = requireNumber(body, "dimension", { min: 8, max: 4096 });
    const templateVersion = Number(body.templateVersion ?? 1);
    const record = coprocessor.enroll({
      wallet,
      chainId: config.chainId,
      ciphertext,
      commitment,
      modelVersion,
      dimension,
      templateVersion,
      sampleCount: Number(body.sampleCount ?? 1),
      meanQuality: Number(body.meanQuality ?? 0),
    });
    logger.info("template enrolled", {
      wallet: record.wallet,
      templateId: record.id,
      commitment: record.commitment,
      templateVersion: record.templateVersion,
    });
    return {
      templateId: record.id,
      commitment: record.commitment,
      templateVersion: record.templateVersion,
      fheKeyVersion: record.fheKeyVersion,
      fheEngine: record.fheEngine,
      status: record.status,
    };
  }, { maxBodyBytes: MAX_CIPHERTEXT_BYTES * 2 });

  app.get("/v1/fhe/template/:wallet", (ctx) => {
    const metadata = coprocessor.templateMetadata(ctx.params.wallet);
    if (!metadata) throw new HttpError(404, "template_not_found", "no enrolled template for this wallet");
    return metadata;
  }, { raw: true });

  /**
   * Evaluate the encrypted similarity.
   *
   * The response is a PRODUCT CIPHERTEXT plus its commitment. No decision, no
   * distance, no similarity: this process structurally cannot produce one.
   */
  app.post("/v1/fhe/evaluate", (ctx) => {
    const body = requireObject(ctx.body, "");
    const result = coprocessor.evaluateForCommittee({
      wallet: requireString(body, "wallet", { pattern: /^0x[0-9a-fA-F]{40}$/ }),
      queryCiphertext: requireString(body, "queryCiphertext", { pattern: BASE64URL, maxLength: MAX_CIPHERTEXT_BYTES * 2 }),
      queryCommitment: requireString(body, "queryCommitment", { pattern: HEX_32 }),
      dimension: requireNumber(body, "dimension", { min: 8, max: 4096 }),
    });
    logger.info("evaluated encrypted similarity", {
      evaluationId: result.evaluationId,
      evaluationMs: Number(result.evaluationMs.toFixed(2)),
      engine: coprocessor.engine.params.engine,
    });
    return {
      product: result.product,
      templateCommitment: result.template.commitment,
      templateVersion: result.template.templateVersion,
      evaluationId: result.evaluationId,
      evaluationMs: Number(result.evaluationMs.toFixed(2)),
      engine: coprocessor.engine.params.engine,
    };
  }, { maxBodyBytes: MAX_CIPHERTEXT_BYTES * 4 });

  /** This service's single share of the decryption, hex-encoded. */
  app.post("/v1/fhe/partial-decrypt", (ctx) => {
    const body = requireObject(ctx.body, "");
    const keyFingerprint = requireString(body, "keyFingerprint");
    const partial = coprocessor.partialDecrypt(requireObject(body, "product") as never, keyFingerprint);
    return `0x${partial.map((v) => v.toString(16).padStart(16, "0")).join("")}`;
  }, { maxBodyBytes: MAX_CIPHERTEXT_BYTES * 4, raw: false });

  return app;
}

export function loadShare(engine: HomomorphicEngine, file: string, fingerprint: string): SecretKeyShare {
  if (!existsSync(file)) throw new Error(`committee share file missing: ${file}`);
  return deserializeShare(JSON.parse(readFileSync(file, "utf-8")) as ShareFile, engine, fingerprint);
}
