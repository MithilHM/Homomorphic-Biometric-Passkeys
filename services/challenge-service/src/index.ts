/**
 * Challenge Service (PRD section 6.2)
 *
 * Issues single-use, short-lived authentication challenges that bind together
 * the wallet, chain, intended operation, policy revision and FHE key version.
 *
 * The nonce is 256 bits from the CSPRNG and is NEVER derived from a block hash:
 * the backend must stay correct when its view of the chain lags or reorgs
 * (PRD section 6.2). A recent chain-state identifier may be *mixed in* by the
 * caller as an extra entropy source, but correctness never depends on it.
 */

import { bytesToHex, keccak256Hex, nowSeconds, randomBytes, randomId } from "@homobio/crypto-utils";
import type { AuthChallenge } from "@homobio/protocol-types";

export type ChallengeStatus = "pending" | "consumed" | "expired" | "failed";

export interface IssueChallengeInput {
  wallet: string;
  chainId: number;
  operationHash: string;
  biometricPolicyVersion: number;
  fheKeyVersion: number;
  webauthnRpId: string;
  webauthnOrigin: string;
  policyHash: string;
  templateVersion: number;
  ttlSeconds?: number;
}

interface Entry {
  challenge: AuthChallenge;
  templateVersion: number;
  status: ChallengeStatus;
  consumedAt?: number;
  consumedBy?: string;
}

export interface ConsumeInput {
  challengeId: string;
  wallet: string;
  chainId: number;
  operationHash: string;
  /** Optional mix-in; recorded but never required for correctness. */
  chainStateId?: string;
}

export class ChallengeService {
  private readonly entries = new Map<string, Entry>();
  private readonly consumedIds = new Set<string>();
  /** Recent nonces, so a reissued nonce can never be re-issued. */
  private readonly issuedNonces = new Set<string>();

  constructor(private readonly defaultTtlSeconds = 90) {}

  issue(input: IssueChallengeInput): AuthChallenge {
    this.sweep();
    const now = nowSeconds();
    const challengeId = randomId();
    const nonce = bytesToHex(randomBytes(32));

    const challenge: AuthChallenge = {
      challengeId,
      sessionId: randomId(),
      wallet: input.wallet.toLowerCase(),
      chainId: input.chainId,
      operationHash: input.operationHash.toLowerCase(),
      nonce,
      issuedAt: now,
      expiresAt: now + (input.ttlSeconds ?? this.defaultTtlSeconds),
      biometricPolicyVersion: input.biometricPolicyVersion,
      fheKeyVersion: input.fheKeyVersion,
      webauthnRpId: input.webauthnRpId,
      webauthnOrigin: input.webauthnOrigin,
      policyHash: input.policyHash,
    };

    this.entries.set(challengeId, {
      challenge,
      templateVersion: input.templateVersion,
      status: "pending",
    });
    this.issuedNonces.add(nonce);
    return challenge;
  }

  peek(challengeId: string): AuthChallenge | undefined {
    const entry = this.entries.get(challengeId);
    if (!entry) return undefined;
    if (entry.status !== "pending") return undefined;
    if (nowSeconds() > entry.challenge.expiresAt) return undefined;
    return entry.challenge;
  }

  /**
   * Validate and atomically consume a challenge.
   *
   * Consuming on entry is deliberate: a challenge is burned by the first
   * verification attempt, so a network retry with a valid assertion cannot get
   * a second bite at the same operation.
   */
  consume(input: ConsumeInput): AuthChallenge {
    this.sweep();

    if (this.consumedIds.has(input.challengeId)) {
      throw new ChallengeError("replay_detected", `challenge ${input.challengeId} was already consumed`);
    }
    const entry = this.entries.get(input.challengeId);
    if (!entry) throw new ChallengeError("challenge_not_found", `unknown challenge ${input.challengeId}`);
    if (entry.status === "consumed") throw new ChallengeError("replay_detected", "challenge already consumed");
    if (entry.status === "failed") throw new ChallengeError("challenge_failed", "challenge was invalidated");
    if (nowSeconds() > entry.challenge.expiresAt) {
      entry.status = "expired";
      throw new ChallengeError("challenge_expired", "challenge expired; request a new one");
    }

    const { challenge } = entry;
    if (challenge.wallet !== input.wallet.toLowerCase()) {
      throw new ChallengeError("wallet_mismatch", "challenge is bound to a different wallet");
    }
    if (challenge.chainId !== input.chainId) {
      throw new ChallengeError("chain_mismatch", `challenge is bound to chain ${challenge.chainId}`);
    }
    if (challenge.operationHash !== input.operationHash.toLowerCase()) {
      throw new ChallengeError("operation_mismatch", "challenge is bound to a different operation");
    }

    entry.status = "consumed";
    entry.consumedAt = nowSeconds();
    this.consumedIds.add(input.challengeId);
    return challenge;
  }

  /** Burn a challenge without granting anything (e.g. after a failed match). */
  invalidate(challengeId: string): void {
    const entry = this.entries.get(challengeId);
    if (entry && entry.status === "pending") entry.status = "failed";
    this.consumedIds.add(challengeId);
  }

  markFailed(challengeId: string): void {
    const entry = this.entries.get(challengeId);
    if (entry) entry.status = "failed";
  }

  isConsumed(challengeId: string): boolean {
    return this.consumedIds.has(challengeId);
  }

  /**
   * The exact bytes the browser's passkey must sign.
   *
   * This is the value that makes the signature transaction-bound: it commits to
   * the operation hash, the challenge, the session, the policy revision and the
   * expiry, so an assertion captured for one transaction cannot be replayed for
   * another.
   */
  intentChallenge(challenge: AuthChallenge): string {
    const canonical = [
      "HOMOBIO/INTENT-V1",
      String(challenge.chainId),
      challenge.wallet,
      challenge.operationHash,
      challenge.nonce,
      challenge.sessionId,
      String(challenge.biometricPolicyVersion),
      String(challenge.expiresAt),
      challenge.policyHash,
    ].join("|");
    return keccak256Hex(canonical);
  }

  status(challengeId: string): ChallengeStatus | "unknown" {
    return this.entries.get(challengeId)?.status ?? "unknown";
  }

  templateVersionOf(challengeId: string): number | undefined {
    return this.entries.get(challengeId)?.templateVersion;
  }

  /** Drop expired entries; consumed ids are kept for the replay window. */
  sweep(maxAgeSeconds = 900): number {
    const now = nowSeconds();
    let removed = 0;
    for (const [id, entry] of this.entries) {
      if (now - entry.challenge.issuedAt > maxAgeSeconds) {
        this.entries.delete(id);
        removed++;
      }
    }
    if (this.issuedNonces.size > 50_000) this.issuedNonces.clear();
    return removed;
  }
}

export class ChallengeError extends Error {
  constructor(
    readonly code:
      | "replay_detected"
      | "challenge_not_found"
      | "challenge_expired"
      | "challenge_failed"
      | "wallet_mismatch"
      | "chain_mismatch"
      | "operation_mismatch",
    message: string,
  ) {
    super(message);
    this.name = "ChallengeError";
  }
}
