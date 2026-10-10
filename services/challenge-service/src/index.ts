/**
 * Challenge Service
 * Issues replay-resistant cryptographic challenges binding:
 * - Wallet address
 * - Chain ID (Monad)
 * - UserOperation hash / Transaction intent
 * - Cryptographic 256-bit nonce
 * - Policy and FHE key versions
 * - WebAuthn Relying Party ID
 */

import { AuthChallenge } from '@homobio/protocol-types';
import * as crypto from 'crypto';

export class ChallengeService {
  private activeChallenges: Map<string, AuthChallenge> = new Map();
  private consumedChallenges: Set<string> = new Set();
  private defaultTTLSeconds: number = 60; // 60 seconds lifetime

  constructor(ttlSeconds: number = 60) {
    this.defaultTTLSeconds = ttlSeconds;
  }

  /**
   * Issue a new single-use cryptographic challenge.
   */
  public issueChallenge(params: {
    wallet: string;
    chainId: number;
    operationHash: string;
    biometricPolicyVersion?: number;
    fheKeyVersion?: number;
    webauthnRpId: string;
  }): AuthChallenge {
    const now = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomUUID();
    const nonce = crypto.randomBytes(32).toString('hex');

    const challenge: AuthChallenge = {
      challengeId,
      wallet: params.wallet.toLowerCase(),
      chainId: params.chainId,
      operationHash: params.operationHash.toLowerCase(),
      nonce,
      issuedAt: now,
      expiresAt: now + this.defaultTTLSeconds,
      biometricPolicyVersion: params.biometricPolicyVersion || 1,
      fheKeyVersion: params.fheKeyVersion || 1,
      webauthnRpId: params.webauthnRpId
    };

    this.activeChallenges.set(challengeId, challenge);
    return challenge;
  }

  /**
   * Validate and consume a challenge.
   * Throws an error if invalid, expired, already consumed, or parameter mismatch occurs.
   */
  public consumeChallenge(params: {
    challengeId: string;
    wallet: string;
    operationHash: string;
    chainId?: number;
  }): AuthChallenge {
    const { challengeId, wallet, operationHash, chainId } = params;

    if (this.consumedChallenges.has(challengeId)) {
      throw new Error(`Challenge ${challengeId} has already been consumed (replay attack detected)`);
    }

    const challenge = this.activeChallenges.get(challengeId);
    if (!challenge) {
      throw new Error(`Challenge ${challengeId} not found`);
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > challenge.expiresAt) {
      this.activeChallenges.delete(challengeId);
      throw new Error(`Challenge ${challengeId} has expired`);
    }

    if (challenge.wallet.toLowerCase() !== wallet.toLowerCase()) {
      throw new Error(`Challenge wallet mismatch: expected ${challenge.wallet}, got ${wallet}`);
    }

    if (challenge.operationHash.toLowerCase() !== operationHash.toLowerCase()) {
      throw new Error(`Challenge operation hash mismatch: expected ${challenge.operationHash}, got ${operationHash}`);
    }

    if (chainId && challenge.chainId !== chainId) {
      throw new Error(`Challenge chain ID mismatch: expected ${challenge.chainId}, got ${chainId}`);
    }

    // Mark as consumed immediately
    this.activeChallenges.delete(challengeId);
    this.consumedChallenges.add(challengeId);

    return challenge;
  }

  public getChallenge(challengeId: string): AuthChallenge | undefined {
    return this.activeChallenges.get(challengeId);
  }

  /**
   * Periodic cleanup of expired challenges.
   */
  public purgeExpired(): number {
    const now = Math.floor(Date.now() / 1000);
    let purged = 0;
    for (const [id, ch] of this.activeChallenges.entries()) {
      if (now > ch.expiresAt) {
        this.activeChallenges.delete(id);
        purged++;
      }
    }
    return purged;
  }
}
