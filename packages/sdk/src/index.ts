/**
 * Homomorphic Biometric Passkeys Developer SDK
 * Conforms to PRD Section 60
 */

import {
  AuthChallenge,
  BiometricPolicy,
  UserOperation,
  AuthenticationEnvelope
} from '@homobio/protocol-types';
import { UserOperationBuilder, MONAD_CHAIN_CONFIG } from '@homobio/userop';
import { serializeMockCiphertext } from '@homobio/crypto-utils';

export interface WalletCreationOptions {
  chain?: string;
  biometric?: {
    enabled: boolean;
    liveness: 'active' | 'passive';
  };
  gas?: {
    sponsored: boolean;
  };
  apiGatewayUrl?: string;
}

export interface BiometricWallet {
  address: string;
  chainId: number;
  policy: BiometricPolicy;
}

export class HomomorphicPasskeyClient {
  private gatewayUrl: string;

  constructor(gatewayUrl: string = 'http://localhost:5000') {
    this.gatewayUrl = gatewayUrl;
  }

  /**
   * Create a new smart wallet controlled by Passkey + Biometric authorization.
   */
  public async createBiometricWallet(options?: WalletCreationOptions): Promise<BiometricWallet> {
    const randomSuffix = Math.random().toString(16).substring(2, 10);
    const mockAddress = `0x71c${randomSuffix}b80c4234589264173892749281728192`.substring(0, 42);

    return {
      address: mockAddress,
      chainId: MONAD_CHAIN_CONFIG.chainId,
      policy: {
        distanceThreshold: 0.45,
        livenessRequired: options?.biometric?.enabled ?? true,
        maxAttempts: 3,
        lockoutPeriodSeconds: 300,
        biometricPolicyVersion: 1
      }
    };
  }

  /**
   * Enroll user face embedding encrypted under CKKS.
   * Transmits ciphertext only; raw face and plaintext embeddings remain on device.
   */
  public async enrollBiometric(wallet: string, embeddingVector: number[]): Promise<{
    success: boolean;
    templateId: string;
    ciphertextHash: string;
  }> {
    const ciphertext = serializeMockCiphertext(embeddingVector);
    const response = await fetch(`${this.gatewayUrl}/v1/biometric/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet,
        ciphertext,
        modelVersion: 'facenet-v1',
        dimension: embeddingVector.length
      })
    });
    return response.json();
  }

  /**
   * Request single-use authentication challenge.
   */
  public async getChallenge(wallet: string, operationHash: string): Promise<AuthChallenge> {
    const response = await fetch(`${this.gatewayUrl}/v1/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet,
        operationHash,
        chainId: MONAD_CHAIN_CONFIG.chainId
      })
    });
    const data = await response.json();
    return data.challenge;
  }

  /**
   * Authenticate transaction with encrypted biometric vector + passkey assertion.
   */
  public async authenticateBiometric(envelope: AuthenticationEnvelope): Promise<any> {
    const response = await fetch(`${this.gatewayUrl}/v1/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope)
    });
    return response.json();
  }

  /**
   * Submit UserOperation to Monad EVM.
   */
  public async submitUserOperation(userOp: UserOperation, attestation?: any): Promise<any> {
    const response = await fetch(`${this.gatewayUrl}/v1/userop/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userOperation: userOp, attestation })
    });
    return response.json();
  }

  public createUserOperation(sender: string): UserOperationBuilder {
    return new UserOperationBuilder().setSender(sender);
  }
}
