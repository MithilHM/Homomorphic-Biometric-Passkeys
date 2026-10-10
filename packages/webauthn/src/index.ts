/**
 * WebAuthn / Passkey subsystem
 * Implements W3C WebAuthn Level 3 credential registration and assertion
 * Cryptographically binds transaction intent and biometric verification session
 */

import { WebAuthnAssertionData } from '@homobio/protocol-types';

export interface PasskeyCreationParams {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  challenge: Uint8Array;
}

export interface IntentBindingParams {
  chainId: number;
  wallet: string;
  userOpHash: string;
  challengeNonce: string;
  biometricSessionId: string;
  policyVersion: number;
  expiration: number;
}

/**
 * Encode an ArrayBuffer to a URL-safe Base64 string.
 */
export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = typeof btoa !== 'undefined' ? btoa(binary) : Buffer.from(binary, 'binary').toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compute the cryptographically bound challenge commitment from transaction intent.
 * This guarantees the passkey cannot be detached or reused for a different transaction.
 */
export async function deriveIntentChallenge(params: IntentBindingParams): Promise<string> {
  const canonicalString = [
    params.chainId.toString(),
    params.wallet.toLowerCase(),
    params.userOpHash,
    params.challengeNonce,
    params.biometricSessionId,
    params.policyVersion.toString(),
    params.expiration.toString()
  ].join(':');

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(canonicalString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return bufferToBase64Url(hashBuffer);
  } else {
    // Node.js fallback
    const cryptoNode = await import('crypto');
    return cryptoNode.createHash('sha256').update(canonicalString).digest('base64url');
  }
}

/**
 * Register a new WebAuthn credential (Passkey).
 */
export async function createPasskeyCredential(params: PasskeyCreationParams): Promise<{
  credentialId: string;
  publicKey: string;
  rawAttestation: string;
}> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('WebAuthn API is only available in a supported browser environment');
  }

  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge: params.challenge,
    rp: {
      name: params.rpName,
      id: params.rpId
    },
    user: {
      id: new TextEncoder().encode(params.userId),
      name: params.userName,
      displayName: params.userDisplayName
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },  // ES256 (P-256)
      { alg: -257, type: 'public-key' } // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'preferred',
      residentKey: 'required'
    },
    timeout: 60000,
    attestation: 'none'
  };

  const credential = (await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  })) as PublicKeyCredential;

  return {
    credentialId: credential.id,
    publicKey: bufferToBase64Url(credential.rawId),
    rawAttestation: bufferToBase64Url((credential.response as AuthenticatorAttestationResponse).attestationObject)
  };
}

/**
 * Authenticate with an existing WebAuthn credential (Passkey) covering the intent challenge.
 */
export async function getPasskeyAssertion(
  credentialId: string,
  challengeBuffer: Uint8Array,
  rpId: string
): Promise<WebAuthnAssertionData> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('WebAuthn API is only available in a browser environment');
  }

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: challengeBuffer,
      rpId,
      allowCredentials: [
        {
          id: new TextEncoder().encode(credentialId),
          type: 'public-key'
        }
      ],
      userVerification: 'preferred',
      timeout: 60000
    }
  })) as PublicKeyCredential;

  const response = assertion.response as AuthenticatorAssertionResponse;

  return {
    credentialId: assertion.id,
    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
    authenticatorData: bufferToBase64Url(response.authenticatorData),
    signature: bufferToBase64Url(response.signature),
    userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : undefined
  };
}
