/**
 * Protocol types + canonical encodings.
 *
 * Everything in this file is mirrored 1:1 by Solidity in `contracts/protocol/`.
 * The TypeScript side encodes with big-endian integers; the Solidity side uses
 * `abi.encodePacked`, which produces byte-identical output —
 * `contracts/test/cross-language.test.ts` asserts that against vectors generated
 * by `solc` so the two implementations can never silently drift.
 */

import {
  ascii,
  bytesToHex,
  canonicalJson,
  concat,
  hexToBytes,
  keccak256,
  lengthPrefixed,
  u64,
  uintToBytes,
} from "@homobio/crypto-utils";

export const PROTOCOL_VERSION = 2;

/** Must stay byte-identical to `bytes constant AUTH_DOMAIN` in AuthDomain.sol. */
export const AUTH_DOMAIN = "HOMOBIO/AUTH-V1";
export const ENROLL_DOMAIN = "HOMOBIO/ENROLL-V1";
export const ENVELOPE_DOMAIN = "HOMOBIO/ENVELOPE-V1";
export const SESSION_DOMAIN = "HOMOBIO/SESSION-V1";
export const RESULT_DOMAIN = "HOMOBIO/RESULT-V1";
export const DECISION_PROGRAM_DOMAIN = "HOMOBIO/DECISION-PROGRAM-V1";

export enum ProofSystem {
  /** Threshold-decryption committee + ECDSA attestation. The MVP default. */
  ThresholdAttestation = 1,
  /** SP1 zkVM proof over the same public inputs. */
  Sp1 = 2,
}

export enum AccountLifecycleState {
  CREATED = "CREATED",
  ENROLLED = "ENROLLED",
  ACTIVE = "ACTIVE",
  LOCKED = "LOCKED",
  RECOVERY = "RECOVERY",
  REVOKED = "REVOKED",
}

export enum AuthSessionStatus {
  Pending = "pending",
  Consumed = "consumed",
  Expired = "expired",
  Failed = "failed",
}

export interface BiometricPolicy {
  policyId: string;
  version: number;
  tier: "convenience" | "standard" | "high-security";
  biometricRequired: boolean;
  passkeyRequired: boolean;
  livenessRequired: boolean;
  /**
   * Cosine-similarity threshold. A live capture must reach at least this value
   * against the enrolled template. Calibrated per model version — never a
   * hard-coded cross-model constant (PRD section 40).
   */
  cosineThreshold: number;
  /** Noise margin (similarity units) the FHE engine must be able to prove. */
  noiseMargin: number;
  maxTransactionValueWei: string;
  sessionEnabled: boolean;
  sessionDurationSeconds: number;
  recoveryDelaySeconds: number;
  maxAttempts: number;
  lockoutSeconds: number;
  /** Engine allowed to produce decisions; accounts may pin the production one. */
  requiredFheEngine?: string;
}

export interface AuthChallenge {
  challengeId: string;
  sessionId: string;
  wallet: string;
  chainId: number;
  operationHash: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  biometricPolicyVersion: number;
  fheKeyVersion: number;
  webauthnRpId: string;
  webauthnOrigin: string;
  /** keccak256 of the policy document that this challenge is bound to. */
  policyHash: string;
}

export interface FheParameters {
  ringDimension: number;
  modulus: string;
  securityLevelBits: number;
}

export interface CiphertextEnvelope {
  /** Serialised homomorphic ciphertext, base64url. */
  ciphertext: string;
  dimension: number;
  modelVersion: string;
  fheKeyVersion: number;
  fheEngine: string;
  /** Bumped whenever the component encoding changes. */
  encodingVersion: number;
  /** Fixed-point exponent applied before encryption (log2). */
  scaleBits: number;
  parameters: FheParameters;
  /** keccak256 of the raw ciphertext bytes — this is what goes on-chain. */
  commitment: string;
}

export interface BiometricTemplateRecord {
  templateId: string;
  wallet: string;
  chainId: number;
  modelVersion: string;
  embeddingDimension: number;
  encodingVersion: number;
  scaleBits: number;
  fheKeyVersion: number;
  fheEngine: string;
  ciphertextCommitment: string;
  templateVersion: number;
  status: "active" | "retired" | "deleted";
  createdAt: number;
  updatedAt: number;
  sampleCount: number;
  meanQuality: number;
}

export interface WebAuthnAssertionData {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
  transports?: string[];
}

export interface StoredPasskeyCredential {
  /** Store key; equal to `credentialId`. */
  id: string;
  credentialId: string;
  wallet: string;
  chainId?: number;
  /** Base64url SPKI DER of the P-256 public key. */
  publicKeySpki: string;
  /** Last 32 bytes of the SPKI DER; stable, loggable key identifier. */
  publicKeyFingerprint?: string;
  userHandle?: string;
  /** COSE algorithm identifier (-7 = ES256, -257 = RS256). */
  alg: number;
  transports: string[];
  aaguid: string | null;
  signCount: number;
  backupEligible: boolean;
  backupState: boolean;
  userVerified: boolean;
  residentKey: boolean;
  label: string;
  role: "primary" | "backup" | "guardian";
  createdAt: number;
  lastUsedAt: number;
  status: "active" | "revoked";
}

/**
 * The authorization object (PRD section 15).
 *
 * It deliberately contains NO image data, NO plaintext embedding and NO
 * plaintext distance — only a decision bit plus commitments.
 */
export interface BiometricAuthorization {
  version: number;
  wallet: string;
  chainId: number;
  userOpHash: string;
  sessionId: string;
  policyHash: string;
  templateVersion: number;
  fheKeyVersion: number;
  decision: boolean;
  /** Threshold that was applied, in millionths of the cosine scale. */
  thresholdBps: number;
  /** keccak256(sessionId || templateCommitment || queryCommitment || decision). */
  resultCommitment: string;
  issuedAt: number;
  expiresAt: number;
  proofSystem: ProofSystem;
  verifierVersion: number;
  /** keccak256 of the canonical authorization struct; signed by the committee key. */
  attestationHash: string;
  /** 65-byte secp256k1 signature over the EIP-191 prefixed attestation hash. */
  signature: string;
  /** Opaque proof blob (SP1 bytes when proofSystem = Sp1). */
  proof?: string;
  /** keccak256 of the FHE decision program that produced `decision`. */
  decisionProgramHash: string;
}

export interface AuthenticationEnvelope {
  chainId: number;
  wallet: string;
  challengeId: string;
  sessionId: string;
  operationHash: string;
  nonce: string;
  policyHash: string;
  templateVersion: number;
  fheKeyVersion: number;
  webauthnAssertion: WebAuthnAssertionData;
  encryptedBiometricQuery: CiphertextEnvelope;
  biometricAuthorization?: BiometricAuthorization;
  expiresAt: number;
}

export interface SessionKey {
  sessionKey: string;
  wallet: string;
  chainId: number;
  validUntil: number;
  allowedTargets: string[];
  allowedSelectors: string[];
  maxValuePerTxWei: string;
  nonceDomain: number;
  createdAt: number;
  status: "active" | "revoked" | "expired";
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function uuidToBytes(id: string): Uint8Array {
  if (!UUID_RE.test(id)) throw new Error(`invalid uuid: ${id}`);
  return hexToBytes(id.replace(/-/g, ""));
}

export function bytesToUuid(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Session ids are `bytes16` on-chain but are minted as UUIDs by the services.
 * Both encodings are accepted so a caller can use whichever it already holds;
 * they always produce the same 16 bytes.
 */
export function sessionIdToBytes(sessionId: string): Uint8Array {
  if (UUID_RE.test(sessionId)) return uuidToBytes(sessionId);
  if (/^[0-9a-fA-F]{32}$/.test(sessionId)) return hexToBytes(sessionId);
  throw new Error(`invalid session id: ${sessionId}`);
}

export function normalizeAddress(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`invalid EVM address: ${address}`);
  return address.toLowerCase();
}

export function addressToBytes(address: string): Uint8Array {
  return hexToBytes(normalizeAddress(address));
}

function hash(domain: string, ...parts: Uint8Array[]): Uint8Array {
  return keccak256(concat(ascii(domain), ...parts));
}

/** keccak256(policy document) — binds a challenge to an exact policy revision. */
export function policyHashHex(policy: BiometricPolicy): string {
  return bytesToHex(hash(ENROLL_DOMAIN, new TextEncoder().encode(canonicalJson(policy))));
}

export interface AuthorizationFields {
  version: number;
  wallet: string;
  chainId: number;
  userOpHash: string;
  sessionId: string;
  policyHash: string;
  templateVersion: number;
  fheKeyVersion: number;
  decision: boolean;
  thresholdBps: number;
  resultCommitment: string;
  issuedAt: number;
  expiresAt: number;
  proofSystem: ProofSystem | number;
  verifierVersion: number;
  decisionProgramHash: string;
}

/**
 * The canonical authorization hash.
 *
 * Solidity equivalent — contracts/protocol/AuthDomain.sol:
 *
 *   keccak256(abi.encodePacked(
 *     "HOMOBIO/AUTH-V1", uint8 version, address wallet, uint64 chainId,
 *     bytes32 userOpHash, bytes16 sessionId, bytes32 policyHash,
 *     uint32 templateVersion, uint32 fheKeyVersion, uint8 decision,
 *     uint32 thresholdBps, bytes32 resultCommitment, uint64 issuedAt,
 *     uint64 expiresAt, uint32 proofSystem, uint32 verifierVersion,
 *     bytes32 decisionProgramHash))
 */
export function authorizationHashBytes(auth: AuthorizationFields): Uint8Array {
  const u8 = (v: number) => uintToBytes(BigInt(v), 1);
  const u32 = (v: number) => uintToBytes(BigInt(v), 4);
  return hash(
    AUTH_DOMAIN,
    u8(auth.version),
    addressToBytes(auth.wallet),
    u64(auth.chainId),
    hexToBytes(auth.userOpHash),
    sessionIdToBytes(auth.sessionId),
    hexToBytes(auth.policyHash),
    u32(auth.templateVersion),
    u32(auth.fheKeyVersion),
    u8(auth.decision ? 1 : 0),
    u32(auth.thresholdBps),
    hexToBytes(auth.resultCommitment),
    u64(auth.issuedAt),
    u64(auth.expiresAt),
    u32(Number(auth.proofSystem)),
    u32(auth.verifierVersion),
    hexToBytes(auth.decisionProgramHash),
  );
}

export function authorizationHashHex(auth: AuthorizationFields): string {
  return bytesToHex(authorizationHashBytes(auth));
}

/**
 * keccak256 of the full authentication envelope — everything the account
 * re-derives before it accepts an operation.
 */
export function envelopeHashHex(envelope: {
  wallet: string;
  chainId: number;
  operationHash: string;
  challengeId: string;
  sessionId: string;
  nonce: string;
  policyHash: string;
  authorizationHash: string;
  expiresAt: number;
}): string {
  return bytesToHex(
    hash(
      ENVELOPE_DOMAIN,
      lengthPrefixed(
        addressToBytes(envelope.wallet),
        u64(envelope.chainId),
        hexToBytes(envelope.operationHash),
        sessionIdToBytes(envelope.challengeId),
        sessionIdToBytes(envelope.sessionId),
        hexToBytes(envelope.nonce),
        hexToBytes(envelope.policyHash),
        hexToBytes(envelope.authorizationHash),
        u64(envelope.expiresAt),
      ),
    ),
  );
}

/** keccak256 result commitment: binds the two ciphertexts actually compared. */
export function resultCommitmentHex(input: {
  sessionId: string;
  templateCommitment: string;
  queryCommitment: string;
  decision: boolean;
}): string {
  return bytesToHex(
    hash(
      RESULT_DOMAIN,
      sessionIdToBytes(input.sessionId),
      hexToBytes(input.templateCommitment),
      hexToBytes(input.queryCommitment),
      uintToBytes(input.decision ? 1 : 0, 1),
    ),
  );
}

/** Deterministic hash of the decision program the coprocessor claims to have run. */
export function decisionProgramHash(input: {
  engine: string;
  metric: string;
  embeddingDimension: number;
  scaleBits: number;
  ringDimension: number;
  securityLevelBits: number;
}): string {
  return bytesToHex(
    hash(
      DECISION_PROGRAM_DOMAIN,
      lengthPrefixed(
        new TextEncoder().encode(input.engine),
        new TextEncoder().encode(input.metric),
        uintToBytes(input.embeddingDimension, 4),
        uintToBytes(input.scaleBits, 4),
        uintToBytes(input.ringDimension, 4),
        uintToBytes(input.securityLevelBits, 4),
      ),
    ),
  );
}

/**
 * Session-key commitment stored on-chain.
 *
 * Arrays are hashed as concatenations and sorted by the caller, so the SDK and
 * the contract agree on one byte string. `packages/userop` sorts before calling.
 * Mirrored by `AuthDomain.sessionKeyHash`.
 */
export function sessionKeyHashHex(session: {
  sessionKey: string;
  wallet: string;
  chainId: number;
  validUntil: number;
  maxValuePerTxWei: string;
  nonceDomain: number;
  /** `readonly` so literal-typed test fixtures can be passed straight through. */
  readonly allowedTargets: readonly string[];
  readonly allowedSelectors: readonly string[];
}): string {
  const targets = session.allowedTargets.map(normalizeAddress);
  const selectors = session.allowedSelectors.map((s) => hexToBytes(s));
  return bytesToHex(
    hash(
      SESSION_DOMAIN,
      addressToBytes(normalizeAddress(session.sessionKey)),
      addressToBytes(normalizeAddress(session.wallet)),
      u64(session.chainId),
      u64(session.validUntil),
      uintToBytes(BigInt(session.maxValuePerTxWei), 32),
      uintToBytes(BigInt(session.nonceDomain), 4),
      keccak256(concat(...targets.map(addressToBytes))),
      keccak256(concat(...selectors)),
    ),
  );
}

/** Similarity <-> basis-point helpers (1e6 == cosine 1.0). */
export function similarityToBps(similarity: number): number {
  return Math.round(similarity * 1_000_000);
}

export function bpsToSimilarity(bps: number): number {
  return bps / 1_000_000;
}
