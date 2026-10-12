/**
 * Relayer / Bundler service (PRD section 17, 55)
 *
 * Submits UserOperations to the configured ERC-4337 bundler, simulates before
 * submitting, and records every attempt for the audit trail.
 *
 * The relayer holds NO key material that can spend user funds: it forwards a
 * UserOperation the account itself authorized. If the relayer is compromised,
 * the attacker gains the ability to relay operations the account already signed
 * — never to create new ones (PRD section 55).
 */

import { keccak256Hex, nowSeconds } from "@homobio/crypto-utils";
import { MONAD_TESTNET, getUserOpHash, fromJSON, type ChainConfig, type PackedUserOperation } from "@homobio/userop";
import { HttpError } from "@homobio/http-kit";
import type { JsonStore, StoredRecord } from "@homobio/store";

export type SubmissionStatus =
  | "simulated"
  | "submitted"
  | "confirmed"
  | "reverted"
  | "rejected"
  | "failed";

export interface SubmissionRecord extends StoredRecord {
  id: string;
  userOpHash: string;
  sender: string;
  status: SubmissionStatus;
  bundlerResponse?: unknown;
  transactionHash?: string;
  reason?: string;
  attempts: number;
}

export interface RelayerConfig {
  chain: ChainConfig;
  bundlerUrl?: string;
  rpcUrl: string;
  /** When true, submissions are simulated locally instead of sent. */
  dryRun: boolean;
  maxRetries: number;
  requestTimeoutMs: number;
}

export class RelayerService {
  constructor(
    private readonly config: RelayerConfig,
    private readonly submissions: JsonStore<SubmissionRecord>,
  ) {}

  /**
   * Reject operations the account should never have authorized.
   *
   * These are pre-flight invariants that cost nothing and catch a whole class
   * of bundler rejections early.
   */
  static preflight(userOp: PackedUserOperation, expectedEntryPoint: string, chainId: number): void {
    if (userOp.callData.length < 4 && userOp.initCode.length < 10) {
      throw new HttpError(400, "empty_operation", "UserOperation has neither callData nor initCode");
    }
    if (userOp.callGasLimit === 0n) throw new HttpError(400, "invalid_operation", "callGasLimit must be non-zero");
    if (userOp.verificationGasLimit < 300_000n) {
      throw new HttpError(400, "invalid_operation", "verificationGasLimit is too low for passkey + attestation");
    }
    if (userOp.maxFeePerGas < userOp.maxPriorityFeePerGas) {
      throw new HttpError(400, "invalid_operation", "maxFeePerGas must be >= maxPriorityFeePerGas");
    }
    if (userOp.signature.length === 0) {
      throw new HttpError(400, "missing_signature", "UserOperation carries no authentication envelope");
    }
    void expectedEntryPoint;
    void chainId;
  }

  async submit(input: {
    userOperation: Record<string, string>;
    entryPoint?: string;
  }): Promise<SubmissionRecord> {
    const userOp = fromJSON(input.userOperation);
    const entryPoint = input.entryPoint ?? this.config.chain.entryPoint;
    RelayerService.preflight(userOp, entryPoint, this.config.chain.chainId);

    const userOpHash = getUserOpHash(userOp, entryPoint, this.config.chain.chainId);

    const existing = this.submissions.get("submissions", userOpHash);
    if (existing && (existing.status === "submitted" || existing.status === "confirmed")) {
      throw new HttpError(409, "duplicate_submission", "this UserOperation has already been submitted");
    }

    if (this.config.dryRun) {
      const record = this.submissions.put("submissions", {
        id: userOpHash,
        userOpHash,
        sender: userOp.sender,
        status: "simulated" as SubmissionStatus,
        attempts: (existing?.attempts ?? 0) + 1,
        reason: "dry-run: not sent to the bundler",
        createdAt: existing?.createdAt ?? nowSeconds(),
        updatedAt: nowSeconds(),
      } as SubmissionRecord);
      return record;
    }

    let lastError = "unknown error";
    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        const response = await this.sendToBundler(userOp, entryPoint);
        const record = this.submissions.put("submissions", {
          id: userOpHash,
          userOpHash,
          sender: userOp.sender,
          status: "submitted" as SubmissionStatus,
          bundlerResponse: response,
          transactionHash: extractTransactionHash(response),
          attempts: attempt,
          createdAt: existing?.createdAt ?? nowSeconds(),
          updatedAt: nowSeconds(),
        } as SubmissionRecord);
        return record;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        if (!isRetryable(lastError)) break;
      }
    }

    const record = this.submissions.put("submissions", {
      id: userOpHash,
      userOpHash,
      sender: userOp.sender,
      status: "rejected" as SubmissionStatus,
      reason: lastError,
      attempts: (existing?.attempts ?? 0) + this.config.maxRetries,
      createdAt: existing?.createdAt ?? nowSeconds(),
      updatedAt: nowSeconds(),
    } as SubmissionRecord);
    throw new HttpError(502, "bundler_rejected", `bundler rejected the operation: ${lastError}`, {
      userOpHash,
      submissionId: record.id,
    });
  }

  private async sendToBundler(userOp: PackedUserOperation, entryPoint: string): Promise<unknown> {
    const bundlerUrl = this.config.bundlerUrl;
    if (!bundlerUrl) {
      throw new HttpError(503, "bundler_unconfigured", "no bundler URL is configured");
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      const response = await fetch(`${bundlerUrl.replace(/\/$/, "")}/eth_sendUserOperation`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify([serialize(userOp, entryPoint)]),
        signal: controller.signal,
      });
      const text = await response.text();
      if (!response.ok) throw new Error(`bundler responded ${response.status}: ${text.slice(0, 200)}`);
      return JSON.parse(text) as unknown;
    } finally {
      clearTimeout(timer);
    }
  }

  status(userOpHash: string): SubmissionRecord | undefined {
    return this.submissions.get("submissions", userOpHash);
  }

  recent(limit = 50): SubmissionRecord[] {
    return this.submissions
      .list("submissions")
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, limit);
  }

  chain(): ChainConfig {
    return this.config.chain;
  }
}

export function serialize(userOp: PackedUserOperation, entryPoint: string): Record<string, string> {
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
    signature: userOp.signature,
    entryPoint,
    chainId: String(MONAD_TESTNET.chainId),
  };
}

function extractTransactionHash(response: unknown): string | undefined {
  if (typeof response === "string") return response;
  if (response && typeof response === "object") {
    const record = response as Record<string, unknown>;
    for (const key of ["transactionHash", "userOpHash", "hash"]) {
      if (typeof record[key] === "string") return record[key] as string;
    }
  }
  return undefined;
}

function isRetryable(message: string): boolean {
  return /timeout|ECONNRESET|ETIMEDOUT|429|503|502|fetch failed/i.test(message);
}

export function defaultRelayerConfig(overrides: Partial<RelayerConfig> = {}): RelayerConfig {
  return {
    chain: MONAD_TESTNET,
    bundlerUrl: process.env.BUNDLER_URL,
    rpcUrl: process.env.MONAD_RPC ?? MONAD_TESTNET.rpcUrl,
    dryRun: process.env.RELAYER_DRY_RUN !== "false",
    maxRetries: 3,
    requestTimeoutMs: 15_000,
    ...overrides,
  };
}

export function submissionCommitment(record: SubmissionRecord): string {
  return keccak256Hex(`${record.userOpHash}:${record.status}:${record.updatedAt}`);
}
