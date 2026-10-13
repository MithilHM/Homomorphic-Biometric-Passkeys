/**
 * Browser-side WebAuthn helpers.
 *
 * The client is responsible for producing the raw authenticator responses and
 * nothing else: it never sees a private key, and it never decides whether its
 * own assertion is valid.
 */

import { base64UrlToBytes, bytesToBase64Url, randomBytes } from "@homobio/crypto-utils";

/** WebCrypto's `BufferSource` is narrower than `Uint8Array` in TS 5.7+. */
function bufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function isWebAuthnSupported(): boolean {
  return (
    typeof globalThis.PublicKeyCredential !== "undefined" &&
    typeof globalThis.navigator?.credentials?.create === "function" &&
    typeof globalThis.navigator?.credentials?.get === "function"
  );
}

export function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return Promise.resolve(false);
  return globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.() ?? Promise.resolve(false);
}

/** Browser self-report for the diagnostics panel: can this browser do a
 *  UV-capable platform ceremony (Windows Hello, Touch ID, …) right now? */
export async function getPlatformAuthInfo(): Promise<{
  webauthn: boolean;
  platformUv: boolean;
  conditionalMediation: boolean;
}> {
  const webauthn = isWebAuthnSupported();
  const [platformUv, conditionalMediation] = await Promise.all([
    webauthn && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
      ? PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      : Promise.resolve(false),
    webauthn && typeof PublicKeyCredential.isConditionalMediationAvailable === "function"
      ? PublicKeyCredential.isConditionalMediationAvailable()
      : Promise.resolve(false),
  ]);
  return { webauthn, platformUv, conditionalMediation };
}

export function generateChallenge(byteLength = 32): Uint8Array {
  return randomBytes(byteLength);
}

export interface RegistrationRequestOptions {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  challenge: string;
  /** `preferred` for convenience, `required` for high-security policies. */
  userVerification?: UserVerificationRequirement;
  residentKey?: ResidentKeyRequirement;
  timeoutMs?: number;
}

export interface RegistrationResponseData {
  credentialId: string;
  clientDataJSON: string;
  attestationObject: string;
  transports: string[];
}

export async function createCredential(options: RegistrationRequestOptions): Promise<RegistrationResponseData> {
  if (!isWebAuthnSupported()) {
    throw new Error("WebAuthn is not available in this browser");
  }
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: bufferSource(base64UrlToBytes(options.challenge)),
    rp: { id: options.rpId, name: options.rpName },
    user: {
      id: bufferSource(new TextEncoder().encode(options.userId)),
      name: options.userName,
      displayName: options.userDisplayName,
    },
    pubKeyCredParams: [
      // ES256 only: it is what platform authenticators and FIDO2 keys emit, and
      // it maps directly onto the account's P-256 verification adapter.
      { type: "public-key", alg: -7 },
    ],
    authenticatorSelection: {
      residentKey: options.residentKey ?? "preferred",
      requireResidentKey: (options.residentKey ?? "preferred") === "required",
      userVerification: options.userVerification ?? "preferred",
    },
    attestation: "none",
    timeout: options.timeoutMs ?? 60_000,
  };

  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new Error("passkey creation was cancelled");
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === "function" ? response.getTransports() : [];

  return {
    credentialId: credential.id,
    clientDataJSON: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
    attestationObject: bytesToBase64Url(new Uint8Array(response.attestationObject)),
    transports,
  };
}

export interface AssertionRequestOptions {
  rpId: string;
  challenge: string;
  /** Omit to use a discoverable credential instead of an allow-list. */
  credentialId?: string;
  /** Transports recorded at registration. Passing them routes the request to
   *  the right authenticator (e.g. `internal` → the platform prompt) instead
   *  of the generic OS picker, which may not offer the local option at all. */
  transports?: string[];
  userVerification?: UserVerificationRequirement;
  timeoutMs?: number;
}

export interface AssertionResponseData {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

export async function getAssertion(options: AssertionRequestOptions): Promise<AssertionResponseData> {
  if (!isWebAuthnSupported()) {
    throw new Error("WebAuthn is not available in this browser");
  }
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: bufferSource(base64UrlToBytes(options.challenge)),
    rpId: options.rpId,
    userVerification: options.userVerification ?? "preferred",
    timeout: options.timeoutMs ?? 60_000,
  };
  if (options.credentialId) {
    publicKey.allowCredentials = [
      {
        type: "public-key",
        id: bufferSource(base64UrlToBytes(options.credentialId)),
        transports: filterTransports(options.transports),
      },
    ];
  }

  const assertion = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!assertion) throw new Error("passkey assertion was cancelled");
  const response = assertion.response as AuthenticatorAssertionResponse;

  return {
    credentialId: assertion.id,
    clientDataJSON: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
    authenticatorData: bytesToBase64Url(new Uint8Array(response.authenticatorData)),
    signature: bytesToBase64Url(new Uint8Array(response.signature)),
    userHandle: response.userHandle ? bytesToBase64Url(new Uint8Array(response.userHandle)) : undefined,
  };
}

/**
 * Keep only spec-defined transports: one unknown string makes the whole
 * `credentials.get()` call throw a `TypeError` in the browser.
 */
function filterTransports(transports?: string[]): AuthenticatorTransport[] | undefined {
  if (!transports || transports.length === 0) return undefined;
  const known: AuthenticatorTransport[] = ["usb", "nfc", "ble", "hybrid", "internal"];
  const filtered = transports.filter((t): t is AuthenticatorTransport => known.includes(t as AuthenticatorTransport));
  return filtered.length > 0 ? filtered : undefined;
}
/**
 * The challenge the browser must sign.
 *
 * It is the domain-separated hash of the *whole* authentication intent, so a
 * passkey signature is worthless for any other transaction (PRD P4). The value
 * is produced by the server; this helper only names it.
 */
export function intentChallengeDescription(input: {
  chainId: number;
  wallet: string;
  operationHash: string;
  sessionId: string;
  policyHash: string;
  expiresAt: number;
}): string {
  return `Authorize ${input.wallet} on chain ${input.chainId} for operation ${input.operationHash.slice(0, 10)}… (session ${input.sessionId.slice(0, 8)}, expires ${new Date(input.expiresAt * 1000).toISOString()})`;
}
