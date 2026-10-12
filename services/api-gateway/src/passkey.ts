/**
 * Browser WebAuthn challenge issuance for credential registration.
 *
 * The challenge is a random 32-byte value; the account binding lives in the
 * `user.id` (the wallet address), which is what a discoverable credential is
 * looked up by later.
 */

import { randomId, nowSeconds, bytesToBase64Url, randomBytes } from "@homobio/crypto-utils";

export interface PasskeyChallenge {
  challengeId: string;
  challenge: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  userName: string;
  userDisplayName: string;
  expiresAt: number;
  pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
  authenticatorSelection: {
    residentKey: "required";
    requireResidentKey: true;
    userVerification: "required";
  };
  attestation: "none";
  timeout: number;
}

export function createPasskeyChallenge(input: {
  wallet: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  displayName: string;
  ttlSeconds?: number;
}): PasskeyChallenge {
  return {
    challengeId: randomId(),
    challenge: bytesToBase64Url(randomBytes(32)),
    rpId: input.rpId,
    rpName: input.rpName,
    userHandle: input.userHandle,
    userName: input.wallet,
    userDisplayName: input.displayName,
    expiresAt: nowSeconds() + (input.ttlSeconds ?? 300),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      // High-value wallet authority: always require user verification.
      userVerification: "required",
    },
    // No authenticator attestation: the product does not need it (PRD 7.1).
    attestation: "none",
    timeout: 60_000,
  };
}
