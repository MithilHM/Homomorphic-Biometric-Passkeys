/**
 * Protocol Types for Homomorphic Biometric Passkeys
 * Privacy-preserving biometric authentication + WebAuthn Passkeys + FHE + ZK + ERC-4337 on Monad
 */

export interface AuthChallenge {
  challengeId: string;
  wallet: string;
  chainId: number;
  operationHash: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  biometricPolicyVersion: number;
  fheKeyVersion: number;
  webauthnRpId: string;
}

export interface BiometricTemplateMetadata {
  templateId: string;
  wallet: string;
  modelVersion: string;
  dimension: number;
  createdAt: number;
  updatedAt: number;
  fheKeyVersion: number;
  ciphertextHash: string;
}

export interface EncryptedEmbeddingPayload {
  templateId?: string;
  ciphertext: string; // Base64 encoded CKKS ciphertext
  dimension: number;
  modelVersion: string;
  fheParams: {
    polyModulusDegree: number;
    scale: number;
    securityLevel: number;
  };
}

export interface WebAuthnAssertionData {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

export interface UserOperation {
  sender: string;
  nonce: string;
  initCode: string;
  callData: string;
  callGasLimit: string;
  verificationGasLimit: string;
  preVerificationGas: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  paymasterAndData: string;
  signature: string;
}

export interface BiometricAttestation {
  attestationId: string;
  challengeId: string;
  wallet: string;
  operationHash: string;
  distanceSatisfied: boolean;
  thresholdUsed: number;
  resultCommitment: string;
  coprocessorSignature: string;
  validUntil: number;
}

export interface AuthenticationEnvelope {
  challenge: AuthChallenge;
  webauthnAssertion: WebAuthnAssertionData;
  encryptedBiometricQuery: EncryptedEmbeddingPayload;
  userOperation: UserOperation;
  attestation?: BiometricAttestation;
}

export enum AccountLifecycleState {
  CREATED = 'CREATED',
  ENROLLED = 'ENROLLED',
  ACTIVE = 'ACTIVE',
  LOCKED = 'LOCKED',
  RECOVERY = 'RECOVERY',
  REVOKED = 'REVOKED'
}

export interface BiometricPolicy {
  distanceThreshold: number; // e.g. 0.8 for Euclidean distance squared or cosine
  livenessRequired: boolean;
  maxAttempts: number;
  lockoutPeriodSeconds: number;
  biometricPolicyVersion: number;
}
