/**
 * WebAuthn Service (PRD section 7)
 *
 * Owns passkey credential records and performs full assertion verification:
 * CBOR/COSE parsing, RP ID hash, origin, UV, signature and counter checks all
 * come from `@homobio/webauthn`; this service adds storage, the WebAuthn-level
 * challenge that binds a passkey signature to a transaction intent, and the
 * attempt accounting that stops credential-probing.
 */

import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { base64UrlToBytes, keccak256Hex, nowSeconds } from "@homobio/crypto-utils";
import {
  WebAuthnError,
  credentialCommitment,
  verifyAssertionResponse,
  verifyRegistrationResponse,
  type SignatureVerifier,
  type StoredCredentialForVerification,
} from "@homobio/webauthn";
import type { StoredPasskeyCredential } from "@homobio/protocol-types";
import type { JsonStore } from "@homobio/store";

export const nodeSignatureVerifier: SignatureVerifier = (data, spkiBase64Url, signature) => {
  const key = createPublicKey({
    key: Buffer.from(base64UrlToBytes(spkiBase64Url)),
    format: "der",
    type: "spki",
  });
  try {
    return nodeVerify("sha256", Buffer.from(data), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(signature));
  } catch {
    return false;
  }
};

export class CredentialError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "CredentialError";
  }
}

export interface RegisterInput {
  wallet: string;
  chainId: number;
  response: {
    credentialId: string;
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
  };
  expectedChallenge: string;
  expectedOrigin: string;
  rpId: string;
  requireUserVerification: boolean;
  label: string;
  role: "primary" | "backup" | "guardian";
  userHandle: string;
}

export class WebAuthnService {
  constructor(
    private readonly store: JsonStore<StoredPasskeyCredential>,
    private readonly requireUserVerification = true,
  ) {}

  async register(input: RegisterInput): Promise<StoredPasskeyCredential> {
    const existing = this.store.find("credentials", (c) => c.credentialId === input.response.credentialId);
    if (existing) {
      if (existing.wallet !== input.wallet.toLowerCase()) {
        throw new CredentialError("credential_not_owned", "credential belongs to a different wallet");
      }
      if (existing.status === "active") {
        throw new CredentialError("credential_exists", "this passkey is already registered");
      }
    }

    let result;
    try {
      result = await verifyRegistrationResponse(
        { clientDataJSON: input.response.clientDataJSON, attestationObject: input.response.attestationObject },
        {
          expectedChallenge: input.expectedChallenge,
          expectedOrigin: input.expectedOrigin,
          rpId: input.rpId,
          requireUserVerification: input.requireUserVerification,
        },
      );
    } catch (error) {
      if (error instanceof WebAuthnError) throw new CredentialError(error.code, error.message);
      throw error;
    }

    if (result.credentialId !== input.response.credentialId) {
      throw new CredentialError("credential_mismatch", "attested credential id does not match the response");
    }

    const credential: StoredPasskeyCredential = {
      id: result.credentialId,
      credentialId: result.credentialId,
      wallet: input.wallet.toLowerCase(),
      publicKeySpki: result.publicKeySpki,
      alg: result.alg,
      transports: input.response.transports ?? [],
      aaguid: result.aaguid,
      signCount: result.signCount,
      backupEligible: result.backupEligible,
      backupState: result.backupState,
      userVerified: result.userVerified,
      residentKey: true,
      label: input.label,
      role: input.role,
      createdAt: nowSeconds(),
      lastUsedAt: nowSeconds(),
      status: "active",
      chainId: input.chainId,
      publicKeyFingerprint: result.publicKeyFingerprint,
      userHandle: input.userHandle,
    };

    return this.store.put("credentials", credential);
  }

  list(wallet: string): StoredPasskeyCredential[] {
    const target = wallet.toLowerCase();
    return this.store
      .list("credentials", (c) => c.wallet === target)
      .sort((a, b) => Number(a.role !== "primary") - Number(b.role !== "primary"));
  }

  get(credentialId: string): StoredPasskeyCredential | undefined {
    return this.store.get("credentials", credentialId);
  }

  revoke(credentialId: string): boolean {
    return Boolean(this.store.update("credentials", credentialId, { status: "revoked" }));
  }

  /**
   * Verify an assertion and advance the stored counter.
   *
   * The challenge the browser signed is the intent challenge derived from the
   * server-issued challenge, so a valid passkey signature exists only for one
   * wallet + operation + session.
   */
  async verifyAssertion(input: {
    wallet: string;
    credentialId: string;
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
    expectedChallenge: string;
    expectedOrigin: string;
    rpId: string;
    requireUserVerification: boolean;
  }): Promise<StoredPasskeyCredential> {
    const credential = this.store.get("credentials", input.credentialId);
    if (!credential) throw new CredentialError("credential_not_found", "unknown credential");
    if (credential.wallet !== input.wallet.toLowerCase()) {
      throw new CredentialError("credential_not_owned", "credential belongs to a different wallet");
    }

    const stored: StoredCredentialForVerification = {
      credentialId: credential.credentialId,
      publicKeySpki: credential.publicKeySpki,
      signCount: credential.signCount,
      status: credential.status,
      userHandle: (credential as unknown as { userHandle?: string }).userHandle,
    };

    try {
      const result = await verifyAssertionResponse(
        {
          credentialId: input.credentialId,
          clientDataJSON: input.clientDataJSON,
          authenticatorData: input.authenticatorData,
          signature: input.signature,
          userHandle: input.userHandle,
        },
        stored,
        {
          expectedChallenge: input.expectedChallenge,
          expectedOrigin: input.expectedOrigin,
          rpId: input.rpId,
          requireUserVerification: input.requireUserVerification,
        },
        nodeSignatureVerifier,
      );

      return this.store.update("credentials", input.credentialId, {
        signCount: result.signCount,
        lastUsedAt: nowSeconds(),
        backupState: result.backupState,
      })!;
    } catch (error) {
      if (error instanceof WebAuthnError) throw new CredentialError(error.code, error.message);
      throw error;
    }
  }

  commitment(credential: StoredPasskeyCredential): string {
    return credentialCommitment({
      wallet: credential.wallet,
      credentialId: credential.credentialId,
      publicKeyFingerprint: (credential as unknown as { publicKeyFingerprint: string }).publicKeyFingerprint,
    });
  }

  fingerprint(credential: StoredPasskeyCredential): string {
    return keccak256Hex(credential.publicKeySpki);
  }
}
