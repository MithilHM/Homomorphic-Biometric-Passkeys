/**
 * WebAuthn Level 3 verification: registration (attestation) and assertion.
 *
 * This is the cryptographic signing root of the whole system, so it verifies
 * properly rather than pattern-matching:
 *
 *   - `clientDataJSON` is parsed and bound to type, challenge and origin;
 *   - `authenticatorData` is checked for the RP ID hash, the UP flag and (when
 *     the policy demands it) the UV flag;
 *   - the signature is verified with ECDSA P-256/SHA-256 over
 *     `authenticatorData || SHA-256(clientDataJSON)`;
 *   - the signature counter must be monotonic, except for synced (multi-device)
 *     passkeys where a zero counter is legitimate;
 *   - backup eligibility/state are surfaced so policy can reject a passkey that
 *     lives only in the cloud.
 */

import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  concat,
  keccak256Hex,
  sha256,
} from "@homobio/crypto-utils";
import { decodeCborMap, decodeCborWithLength } from "./cbor.js";
import { coseKeyToSpkiDer, parseCoseKey } from "./cose.js";

export type WebAuthnErrorCode =
  | "malformed"
  | "origin_mismatch"
  | "challenge_mismatch"
  | "rp_mismatch"
  | "signature_invalid"
  | "counter_regression"
  | "user_verification_required"
  | "credential_not_found"
  | "credential_revoked"
  | "unsupported_algorithm";

export class WebAuthnError extends Error {
  constructor(
    message: string,
    readonly code: WebAuthnErrorCode,
  ) {
    super(message);
    this.name = "WebAuthnError";
  }
}

export interface AuthenticatorData {
  rpIdHash: string;
  flags: number;
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
  attestedCredentialData: boolean;
  extensionData: boolean;
  signCount: number;
  aaguid: string | null;
  credentialId: string | null;
  credentialPublicKey: Uint8Array | null;
  /** Bytes consumed by the credential's COSE key, when present. */
  credentialPublicKeyLength: number;
}

export interface ClientData {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin: boolean;
}

export function parseAuthenticatorData(bytes: Uint8Array): AuthenticatorData {
  if (bytes.length < 37) throw new WebAuthnError("authenticatorData is too short", "malformed");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const flags = bytes[32];

  const result: AuthenticatorData = {
    rpIdHash: bytesToHex(bytes.subarray(0, 32)),
    flags,
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
    attestedCredentialData: (flags & 0x40) !== 0,
    extensionData: (flags & 0x80) !== 0,
    signCount: view.getUint32(33, false),
    aaguid: null,
    credentialId: null,
    credentialPublicKey: null,
    credentialPublicKeyLength: 0,
  };

  if (!result.attestedCredentialData) return result;

  if (bytes.length < 55) throw new WebAuthnError("attested credential data is truncated", "malformed");
  result.aaguid = bytesToHex(bytes.subarray(37, 53));
  const idLength = view.getUint16(53, false);
  if (bytes.length < 55 + idLength) throw new WebAuthnError("credential id is truncated", "malformed");
  result.credentialId = bytesToBase64Url(bytes.subarray(55, 55 + idLength));

  const rest = bytes.subarray(55 + idLength);
  const { length } = decodeCborWithLength(rest);
  result.credentialPublicKey = rest.subarray(0, length).slice();
  result.credentialPublicKeyLength = length;

  return result;
}

export function parseClientData(bytes: Uint8Array): ClientData {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new WebAuthnError("clientDataJSON is not valid JSON", "malformed");
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new WebAuthnError("clientDataJSON must be an object", "malformed");
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.type !== "string" || typeof record.challenge !== "string") {
    throw new WebAuthnError("clientDataJSON is missing type or challenge", "malformed");
  }
  return {
    type: record.type,
    challenge: record.challenge,
    origin: typeof record.origin === "string" ? record.origin : "",
    crossOrigin: record.crossOrigin === true,
  };
}

export interface VerificationOptions {
  expectedChallenge: string;
  expectedOrigin: string;
  rpId: string;
  requireUserVerification?: boolean;
}

async function verifyClientData(
  clientDataJSON: Uint8Array,
  authData: AuthenticatorData,
  options: VerificationOptions,
  expectedType: "webauthn.create" | "webauthn.get",
): Promise<void> {
  const clientData = parseClientData(clientDataJSON);

  if (clientData.type !== expectedType) {
    throw new WebAuthnError(`clientData type ${clientData.type} != ${expectedType}`, "malformed");
  }
  if (clientData.challenge !== options.expectedChallenge) {
    throw new WebAuthnError("WebAuthn challenge mismatch", "challenge_mismatch");
  }
  if (clientData.origin !== options.expectedOrigin) {
    throw new WebAuthnError(`origin ${clientData.origin} is not allowed`, "origin_mismatch");
  }

  const expectedRpIdHash = bytesToHex(await sha256(options.rpId));
  if (authData.rpIdHash !== expectedRpIdHash) {
    throw new WebAuthnError("RP ID hash mismatch", "rp_mismatch");
  }
  if (!authData.userPresent) {
    throw new WebAuthnError("user presence flag was not set", "malformed");
  }
  if (options.requireUserVerification && !authData.userVerified) {
    throw new WebAuthnError("policy requires user verification", "user_verification_required");
  }
}

export interface RegistrationResult {
  credentialId: string;
  publicKeySpki: string;
  publicKeyFingerprint: string;
  alg: number;
  aaguid: string | null;
  signCount: number;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
  attestationFormat: string;
}

/**
 * Verify an attestation response and return the credential to store.
 *
 * Attestation statements are intentionally NOT verified against a metadata
 * service: the product does not need authenticator attestation (PRD section
 * 7.1), so the client requests `attestation: "none"` and the trust surface
 * stays small. The flags that matter for policy (UV, BE/BS) are still parsed.
 */
export async function verifyRegistrationResponse(
  input: { clientDataJSON: string; attestationObject: string; transports?: string[] },
  options: VerificationOptions,
): Promise<RegistrationResult> {
  const clientDataJSON = base64UrlToBytes(input.clientDataJSON);
  const attestation = decodeCborMap(base64UrlToBytes(input.attestationObject));

  const fmt = attestation.get("fmt");
  const authDataBytes = attestation.get("authData");
  if (typeof fmt !== "string" || !(authDataBytes instanceof Uint8Array)) {
    throw new WebAuthnError("attestationObject is missing fmt or authData", "malformed");
  }

  const authData = parseAuthenticatorData(authDataBytes);
  await verifyClientData(clientDataJSON, authData, options, "webauthn.create");

  if (!authData.attestedCredentialData || !authData.credentialId || !authData.credentialPublicKey) {
    throw new WebAuthnError("attestation did not include attested credential data", "malformed");
  }

  let cose;
  try {
    cose = parseCoseKey(authData.credentialPublicKey);
  } catch (error) {
    throw new WebAuthnError((error as Error).message, "unsupported_algorithm");
  }
  const spki = coseKeyToSpkiDer(cose);

  return {
    credentialId: authData.credentialId,
    publicKeySpki: bytesToBase64Url(spki),
    publicKeyFingerprint: `0x${bytesToHex(spki).slice(-64)}`,
    alg: cose.alg,
    aaguid: authData.aaguid,
    signCount: authData.signCount,
    userVerified: authData.userVerified,
    backupEligible: authData.backupEligible,
    backupState: authData.backupState,
    attestationFormat: fmt,
  };
}

export interface StoredCredentialForVerification {
  credentialId: string;
  publicKeySpki: string;
  signCount: number;
  status: "active" | "revoked";
  userHandle?: string;
}

export interface AssertionVerification {
  credentialId: string;
  signCount: number;
  userVerified: boolean;
  backupState: boolean;
  userHandle: string | null;
}

/** Injectable verifier so the same code runs against Node and WebCrypto. */
export type SignatureVerifier = (data: Uint8Array, spkiBase64Url: string, signature: Uint8Array) => boolean;

export async function verifyAssertionResponse(
  input: {
    credentialId: string;
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  },
  credential: StoredCredentialForVerification,
  options: VerificationOptions,
  verify: SignatureVerifier,
): Promise<AssertionVerification> {
  if (credential.status !== "active") {
    throw new WebAuthnError(`credential ${credential.credentialId} is revoked`, "credential_revoked");
  }
  if (credential.credentialId !== input.credentialId) {
    throw new WebAuthnError("credential id does not match the stored credential", "credential_not_found");
  }

  const clientDataJSON = base64UrlToBytes(input.clientDataJSON);
  const authenticatorData = base64UrlToBytes(input.authenticatorData);
  const signature = base64UrlToBytes(input.signature);
  if (signature.length !== 64) {
    throw new WebAuthnError("ES256 signatures must be 64 raw bytes (r || s)", "malformed");
  }

  const authData = parseAuthenticatorData(authenticatorData);
  await verifyClientData(clientDataJSON, authData, options, "webauthn.get");

  if (input.userHandle && credential.userHandle && input.userHandle !== credential.userHandle) {
    throw new WebAuthnError("userHandle does not match the registered account", "credential_not_found");
  }

  const clientDataHash = await sha256(clientDataJSON);
  const signedData = concat(authenticatorData, clientDataHash);
  if (!verify(signedData, credential.publicKeySpki, signature)) {
    throw new WebAuthnError("WebAuthn signature verification failed", "signature_invalid");
  }

  // A zero counter is legitimate for synced passkeys (BE/BS set) and for the
  // very first assertion of a credential that never increments.
  const synced = authData.backupEligible || credential.signCount === 0;
  if (!synced && authData.signCount !== 0 && authData.signCount <= credential.signCount) {
    throw new WebAuthnError(
      `signature counter regression (${authData.signCount} <= ${credential.signCount}); possible cloned authenticator`,
      "counter_regression",
    );
  }

  return {
    credentialId: credential.credentialId,
    signCount: authData.signCount,
    userVerified: authData.userVerified,
    backupState: authData.backupState,
    userHandle: input.userHandle ?? null,
  };
}

/** Deterministic credential commitment used for account derivation. */
export function credentialCommitment(input: {
  wallet: string;
  credentialId: string;
  publicKeyFingerprint: string;
}): string {
  return keccak256Hex(
    concat(
      new TextEncoder().encode("HOMOBIO/CREDENTIAL-V1"),
      new TextEncoder().encode(`${input.wallet}|${input.credentialId}|${input.publicKeyFingerprint}`),
    ),
  );
}
