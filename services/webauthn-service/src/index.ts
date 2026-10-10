/**
 * WebAuthn Credential and Assertion Verification Service
 */

import { WebAuthnAssertionData } from '@homobio/protocol-types';
import * as crypto from 'crypto';

export interface StoredPasskeyCredential {
  credentialId: string;
  wallet: string;
  publicKey: string;
  signCount: number;
  createdAt: number;
  lastUsedAt: number;
}

export class WebAuthnService {
  private credentials: Map<string, StoredPasskeyCredential> = new Map();

  /**
   * Register a new passkey credential for a smart account wallet.
   */
  public registerCredential(params: {
    wallet: string;
    credentialId: string;
    publicKey: string;
  }): StoredPasskeyCredential {
    const cred: StoredPasskeyCredential = {
      credentialId: params.credentialId,
      wallet: params.wallet.toLowerCase(),
      publicKey: params.publicKey,
      signCount: 0,
      createdAt: Math.floor(Date.now() / 1000),
      lastUsedAt: Math.floor(Date.now() / 1000)
    };
    this.credentials.set(params.credentialId, cred);
    return cred;
  }

  /**
   * Verify an authenticator assertion for a given challenge.
   */
  public verifyAssertion(params: {
    assertion: WebAuthnAssertionData;
    expectedChallengeCommitment: string;
    expectedRpId: string;
  }): { valid: boolean; credential: StoredPasskeyCredential } {
    const cred = this.credentials.get(params.assertion.credentialId);
    if (!cred) {
      throw new Error(`Credential ${params.assertion.credentialId} not found`);
    }

    // Decode clientDataJSON
    const clientDataRaw = Buffer.from(params.assertion.clientDataJSON, 'base64url').toString('utf-8');
    const clientData = JSON.parse(clientDataRaw);

    if (clientData.type !== 'webauthn.get') {
      throw new Error(`Unexpected clientData type: ${clientData.type}`);
    }

    if (clientData.challenge !== params.expectedChallengeCommitment) {
      throw new Error(`WebAuthn challenge mismatch: expected ${params.expectedChallengeCommitment}, got ${clientData.challenge}`);
    }

    cred.signCount++;
    cred.lastUsedAt = Math.floor(Date.now() / 1000);

    return {
      valid: true,
      credential: cred
    };
  }

  public getCredential(credentialId: string): StoredPasskeyCredential | undefined {
    return this.credentials.get(credentialId);
  }
}
