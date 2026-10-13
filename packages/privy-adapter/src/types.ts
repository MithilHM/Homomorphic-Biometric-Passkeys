/**
 * Types for the Privy Passkey & Auth Provider integration.
 *
 * Bridges Privy's hardware-bound passkey infrastructure (P-256 secure enclave)
 * into our ERC-4337 Smart Account authentication pipeline on Monad.
 */

export interface PrivyAuthConfig {
  appId?: string;
  clientId?: string;
  mode?: "privy" | "sandbox" | "auto";
  rpId?: string;
  rpName?: string;
}

export interface PrivyPasskeyCredential {
  credentialId: string;
  rawId: string;
  type: "public-key";
  spkiBase64Url: string;
  publicKeyHex: string;
  publicKeyFingerprint: string;
  userHandle: string;
  transports?: string[];
  authenticatorAttachment?: "platform" | "cross-platform";
  createdAt: number;
}

export interface PrivyUser {
  id: string; // did:privy:c...
  walletAddress: string;
  passkey?: PrivyPasskeyCredential;
  linkedAccounts: Array<{
    type: "passkey" | "wallet" | "email";
    address?: string;
    verifiedAt: number;
  }>;
}

export interface PrivyAssertionResult {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

export interface PrivyRegistrationResult {
  credential: PrivyPasskeyCredential;
  user: PrivyUser;
  rawResponse: {
    credentialId: string;
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
}

export interface PasskeyProvider {
  readonly id: "privy" | "native";
  readonly name: string;
  isAvailable(): Promise<boolean>;
  register(options: {
    wallet: string;
    challenge: string;
    userHandle: string;
    displayName: string;
    rpId: string;
    rpName: string;
  }): Promise<PrivyPasskeyCredential>;
  authenticate(options: {
    challenge: string;
    credentialId?: string;
    rpId: string;
  }): Promise<PrivyAssertionResult>;
  getUser(): PrivyUser | null;
}
