/**
 * Client for the FHE coprocessor.
 *
 * The gateway holds ONE committee share (the proof-service one) and asks the
 * coprocessor for its share over an authenticated local channel. Neither party
 * can decrypt alone, and the gateway never receives a plaintext distance: the
 * recombined value lives only inside `DecryptionCommitteeGateway.decide`.
 */

import { HttpError } from "@homobio/http-kit";
import type { FheCiphertext, PublicKeyBundle } from "@homobio/fhe";

export interface FheClientOptions {
  baseUrl: string;
  serviceToken: string;
  errorBound: number;
}

export interface TemplateMetadata {
  templateId: string;
  wallet: string;
  templateVersion: number;
  commitment: string;
  fheKeyVersion: number;
  fheEngine: string;
  dimension: number;
  modelVersion: string;
  scaleBits: number;
  encodingVersion: number;
  sampleCount: number;
  meanQuality: number;
  createdAt: number;
  status: string;
}

export class FheClient {
  private publicKeyCache?: PublicKeyBundle;

  constructor(private readonly options: FheClientOptions) {}

  async publicKey(): Promise<PublicKeyBundle> {
    if (this.publicKeyCache) return this.publicKeyCache;
    const response = await this.request<PublicKeyBundle>("GET", "/v1/fhe/public-key");
    this.publicKeyCache = response;
    return response;
  }

  fingerprint(): string | undefined {
    return this.publicKeyCache?.fingerprint;
  }

  errorBound(): number {
    return this.options.errorBound;
  }

  publicKeyPayload(): Record<string, unknown> {
    return {
      engine: this.publicKeyCache?.engine,
      keyVersion: this.publicKeyCache?.keyVersion ?? null,
      fingerprint: this.publicKeyCache?.fingerprint ?? null,
      ringDimension: this.publicKeyCache?.ringDimension ?? null,
      modulus: this.publicKeyCache?.modulus ?? null,
      scaleBits: this.publicKeyCache?.scaleBits ?? null,
      embeddingDimension: this.publicKeyCache?.embeddingDimension ?? null,
      securityLevelBits: this.publicKeyCache?.securityLevelBits ?? null,
      publicKeyA: this.publicKeyCache?.publicKeyA,
      publicKeyB: this.publicKeyCache?.publicKeyB,
      errorBound: this.options.errorBound,
      templateLayout: "high",
      queryLayout: "low",
      metric: "cosine-similarity",
    };
  }

  async enroll(input: {
    wallet: string;
    ciphertext: string;
    commitment: string;
    modelVersion: string;
    dimension: number;
    templateVersion: number;
    sampleCount: number;
    meanQuality: number;
  }): Promise<{ templateId: string; commitment: string; templateVersion: number; fheKeyVersion: number; fheEngine: string; status: string }> {
    return this.request("POST", "/v1/fhe/enroll", input);
  }

  async evaluate(input: {
    wallet: string;
    queryCiphertext: string;
    queryCommitment: string;
    dimension: number;
  }): Promise<{ product: FheCiphertext; templateCommitment: string; queryCommitment: string; evaluationId: string; evaluationMs: number }> {
    const response = await this.request<{
      product: FheCiphertext;
      templateCommitment: string;
      queryCommitment: string;
      evaluationId: string;
      evaluationMs: number;
    }>("POST", "/v1/fhe/evaluate", {
      wallet: input.wallet,
      queryCiphertext: input.queryCiphertext,
      queryCommitment: input.queryCommitment,
      dimension: input.dimension,
    });
    return { ...response, queryCommitment: input.queryCommitment };
  }

  async partialDecrypt(input: { product: FheCiphertext; keyFingerprint: string }): Promise<string> {
    return this.request<string>("POST", "/v1/fhe/partial-decrypt", {
      product: input.product,
      keyFingerprint: input.keyFingerprint,
    });
  }

  /**
   * Template metadata (commitment, version, dimension) — never the ciphertext.
   *
   * Cached for a few seconds so a burst of challenges does not hammer the
   * coprocessor, and invalidated on enrollment.
   */
  async activeTemplate(wallet: string): Promise<TemplateMetadata | undefined> {
    const key = wallet.toLowerCase();
    const cached = this.templateCache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    try {
      const value = await this.request<TemplateMetadata>("GET", `/v1/fhe/template/${key}`);
      this.templateCache.set(key, { value, expiresAt: Date.now() + 5_000 });
      return value;
    } catch (error) {
      if (error instanceof HttpError && error.code === "template_not_found") return undefined;
      throw error;
    }
  }

  forgetTemplate(wallet: string): void {
    this.templateCache.delete(wallet.toLowerCase());
  }

  /**
   * Erase every template record for a wallet via the coprocessor (M3.5).
   * Invalidates the metadata cache so a subsequent `activeTemplate` reflects
   * the erasure instead of serving the deleted commitment for up to 5s.
   */
  async deleteTemplate(wallet: string): Promise<{ deleted: number; wallet: string }> {
    const key = wallet.toLowerCase();
    const result = await this.request<{ deleted: number; wallet: string }>(
      "DELETE",
      `/v1/fhe/template/${key}`,
    );
    this.forgetTemplate(key);
    return result;
  }

  private readonly templateCache = new Map<
    string,
    { value: TemplateMetadata; expiresAt: number }
  >();

  health(): Promise<Record<string, unknown>> {
    return this.request("GET", "/health");
  }

  private async request<T>(method: string, endpoint: string, body?: unknown): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.options.baseUrl.replace(/\/$/, "")}${endpoint}`, {
        method,
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.options.serviceToken}`,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (error) {
      throw new HttpError(503, "fhe_unavailable", `FHE coprocessor unreachable: ${(error as Error).message}`);
    }

    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      throw new HttpError(502, "fhe_bad_response", "FHE coprocessor returned a non-JSON response");
    }

    if (!response.ok) {
      const record = parsed as { error?: string; message?: string };
      const status = record.error === "template_not_found" ? 404 : 502;
      throw new HttpError(status, record.error ?? "fhe_error", record.message ?? "FHE coprocessor error");
    }
    return parsed as T;
  }
}
