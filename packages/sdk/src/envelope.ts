/**
 * The `userOp.signature` envelope, byte-for-byte what
 * `BiometricSmartAccount._decodeAuthorization` reads.
 *
 *   0x48 | uint16 bodyLength
 *        | bytes32 envelopeHash
 *        | uint16 assertionLength | assertion
 *        | Authorization fields (fixed width, 242 bytes)
 *        | bytes   committee signature (65 bytes)
 *
 * The layout is duplicated in Solidity; the field order here IS the protocol.
 * Keeping the account's decoder index-based means no offset table can drift.
 */

import { bytesToHex, hexToBytes, base64UrlToBytes } from "@homobio/crypto-utils";
import type { AuthorizationFields } from "@homobio/protocol-types";

export const AUTHORIZATION_MAGIC = 0x48;

export interface AuthorizationEnvelopeInput {
  envelopeHash: string;
  attestationHash: string;
  /** 65-byte secp256k1 signature, base64url or 0x-hex. */
  attestationSignature: string;
  /** The WebAuthn assertion, base64url. */
  webauthnAssertion: string;
  /** Every field the account re-derives the attestation hash from. */
  authorization: AuthorizationFields & { attestationHash: string };
}

function u8(value: number): string {
  return value.toString(16).padStart(2, "0");
}

function u16(value: number): string {
  return (value & 0xffff).toString(16).padStart(4, "0");
}

function u32(value: number): string {
  return (value >>> 0).toString(16).padStart(8, "0");
}

function u64(value: number): string {
  return BigInt(value).toString(16).padStart(16, "0");
}

function b32(value: string): string {
  return bytesToHex(hexToBytes(value.startsWith("0x") ? value : `0x${value}`));
}

function b16(value: string): string {
  return bytesToHex(hexToBytes(value.replace(/-/g, "")));
}

function toBytes(value: string): Uint8Array {
  if (value.startsWith("0x")) return hexToBytes(value);
  return base64UrlToBytes(value);
}

export function packAuthorizationEnvelope(input: AuthorizationEnvelopeInput): string {
  const flat = input;

  const assertion = bytesToHex(toBytes(flat.webauthnAssertion));
  const signature = bytesToHex(toBytes(flat.attestationSignature));
  if (signature.length !== 130) {
    throw new Error(`attestation signature must be 65 bytes, got ${signature.length / 2}`);
  }

  const a = flat.authorization;
  const body =
    b32(flat.envelopeHash) +
    u16(assertion.length / 2) +
    assertion +
    u8(a.version) +
    bytesToHex(hexToBytes(a.wallet)) +
    u64(a.chainId) +
    b32(a.userOpHash) +
    b16(a.sessionId) +
    b32(a.policyHash) +
    u32(a.templateVersion) +
    u32(a.fheKeyVersion) +
    u8(a.decision ? 1 : 0) +
    u32(a.thresholdBps) +
    b32(a.resultCommitment) +
    u64(a.issuedAt) +
    u64(a.expiresAt) +
    u32(a.proofSystem) +
    u32(a.verifierVersion) +
    b32(a.decisionProgramHash) +
    b32(flat.attestationHash) +
    signature;

  const magic = u8(AUTHORIZATION_MAGIC);
  return `0x${magic}${u16(body.length / 2)}${body}`;
}
