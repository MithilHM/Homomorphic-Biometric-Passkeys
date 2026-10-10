/**
 * Proof and Attestation Service
 * Produces signed biometric decision attestations & SP1 zkVM proof commitments
 * for on-chain validation by ERC-4337 smart account.
 */

import { BiometricAttestation } from '@homobio/protocol-types';
import * as crypto from 'crypto';

export class ProofService {
  private keyPair: crypto.KeyPairSyncResult<string, string>;

  constructor() {
    // Generate ECDSA P-256 keypair for attestation signing
    this.keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }

  public getPublicKey(): string {
    return this.keyPair.publicKey;
  }

  /**
   * Generate a tamper-resistant BiometricAttestation.
   */
  public generateAttestation(params: {
    challengeId: string;
    wallet: string;
    operationHash: string;
    distanceSatisfied: boolean;
    thresholdUsed: number;
    resultCommitment: string;
    validitySeconds?: number;
  }): BiometricAttestation {
    const now = Math.floor(Date.now() / 1000);
    const validUntil = now + (params.validitySeconds || 120); // 2 minutes validity
    const attestationId = crypto.randomUUID();

    const payload = [
      attestationId,
      params.challengeId,
      params.wallet.toLowerCase(),
      params.operationHash.toLowerCase(),
      params.distanceSatisfied ? '1' : '0',
      params.thresholdUsed.toString(),
      params.resultCommitment,
      validUntil.toString()
    ].join(':');

    const signer = crypto.createSign('SHA256');
    signer.update(payload);
    signer.end();
    const signature = signer.sign(this.keyPair.privateKey, 'hex');

    return {
      attestationId,
      challengeId: params.challengeId,
      wallet: params.wallet.toLowerCase(),
      operationHash: params.operationHash.toLowerCase(),
      distanceSatisfied: params.distanceSatisfied,
      thresholdUsed: params.thresholdUsed,
      resultCommitment: params.resultCommitment,
      coprocessorSignature: `0x${signature}`,
      validUntil
    };
  }

  /**
   * Verify an attestation's cryptographic signature.
   */
  public verifyAttestation(attestation: BiometricAttestation): boolean {
    const payload = [
      attestation.attestationId,
      attestation.challengeId,
      attestation.wallet.toLowerCase(),
      attestation.operationHash.toLowerCase(),
      attestation.distanceSatisfied ? '1' : '0',
      attestation.thresholdUsed.toString(),
      attestation.resultCommitment,
      attestation.validUntil.toString()
    ].join(':');

    const rawSig = attestation.coprocessorSignature.startsWith('0x')
      ? attestation.coprocessorSignature.slice(2)
      : attestation.coprocessorSignature;

    const verifier = crypto.createVerify('SHA256');
    verifier.update(payload);
    verifier.end();
    return verifier.verify(this.keyPair.publicKey, Buffer.from(rawSig, 'hex'));
  }
}
