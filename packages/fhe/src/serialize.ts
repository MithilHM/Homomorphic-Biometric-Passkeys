/**
 * Ciphertext wire format.
 *
 * The format is deliberately rigid and fully validated on parse: a coprocessor
 * must never be tricked into evaluating attacker-controlled polynomials, and
 * the gateway must reject oversized or malformed payloads before they reach the
 * FHE worker (PRD section 6.1).
 *
 *   magic    : 4 bytes  "HBFH"
 *   version  : 1 byte   encoding version
 *   flags    : 1 byte   bit0 = ciphertext carries an s^2 term
 *   ringDim  : 2 bytes  big-endian
 *   coeffs   : ringDim * 8 bytes per present polynomial, big-endian, mod q
 */

import { bytesToHex, hexToBytes, keccak256Hex } from "@homobio/crypto-utils";

export const CIPHERTEXT_MAGIC = 0x48424648; // "HBFH"
export const CIPHERTEXT_VERSION = 1;
export const FLAG_QUADRATIC = 0b1;

const COEFF_BYTES = 8;
const HEADER_BYTES = 8;

export interface ParsedCiphertext {
  version: number;
  ringDimension: number;
  hasQuadraticTerm: boolean;
  /** Polys in wire order: [p0?, p1, p2] */
  polys: bigint[][];
  commitment: string;
}

function encodePoly(coeffs: bigint[], q: bigint): Uint8Array {
  const out = new Uint8Array(coeffs.length * COEFF_BYTES);
  const view = new DataView(out.buffer);
  for (let i = 0; i < coeffs.length; i++) {
    const v = coeffs[i] < 0n ? coeffs[i] + q : coeffs[i];
    if (v < 0n || v >= q) throw new Error(`coefficient ${i} is not reduced modulo q`);
    view.setBigUint64(i * COEFF_BYTES, v, false);
  }
  return out;
}

export function serializeCiphertext(
  polys: bigint[][],
  ringDimension: number,
  q: bigint,
): Uint8Array {
  if (polys.length < 2 || polys.length > 3) throw new Error("ciphertext must carry 2 or 3 polynomials");
  const bytes = new Uint8Array(HEADER_BYTES + polys.length * ringDimension * COEFF_BYTES);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, CIPHERTEXT_MAGIC, false);
  view.setUint8(4, CIPHERTEXT_VERSION);
  view.setUint8(5, polys.length === 3 ? FLAG_QUADRATIC : 0);
  view.setUint16(6, ringDimension, false);
  let offset = HEADER_BYTES;
  for (const poly of polys) {
    if (poly.length !== ringDimension) throw new Error("polynomial has the wrong length");
    bytes.set(encodePoly(poly, q), offset);
    offset += ringDimension * COEFF_BYTES;
  }
  return bytes;
}

export function parseCiphertext(bytes: Uint8Array, expectedRingDimension: number, q: bigint): ParsedCiphertext {
  if (bytes.length < HEADER_BYTES) throw new Error("ciphertext is too short");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, false) !== CIPHERTEXT_MAGIC) throw new Error("bad ciphertext magic");
  const version = view.getUint8(4);
  if (version !== CIPHERTEXT_VERSION) throw new Error(`unsupported ciphertext version ${version}`);
  const flags = view.getUint8(5);
  const ringDimension = view.getUint16(6, false);
  if (ringDimension !== expectedRingDimension) {
    throw new Error(`ciphertext ring dimension ${ringDimension} != expected ${expectedRingDimension}`);
  }
  const hasQuadraticTerm = (flags & FLAG_QUADRATIC) !== 0;
  const count = hasQuadraticTerm ? 3 : 2;
  const expectedLength = HEADER_BYTES + count * ringDimension * COEFF_BYTES;
  if (bytes.length !== expectedLength) {
    throw new Error(`ciphertext length ${bytes.length} != expected ${expectedLength}`);
  }

  const polys: bigint[][] = [];
  let offset = HEADER_BYTES;
  for (let p = 0; p < count; p++) {
    const poly = new Array<bigint>(ringDimension);
    for (let i = 0; i < ringDimension; i++) {
      const v = view.getBigUint64(offset + i * COEFF_BYTES, false);
      if (v >= q) throw new Error(`coefficient out of range at ${p}:${i}`);
      poly[i] = v;
    }
    polys.push(poly);
    offset += ringDimension * COEFF_BYTES;
  }

  return {
    version,
    ringDimension,
    hasQuadraticTerm,
    polys: hasQuadraticTerm ? [polys[0], polys[1], polys[2]] : [[], polys[0], polys[1]],
    commitment: `0x${keccak256Hex(bytes)}`,
  };
}

export function bytesToBase64UrlString(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlStringToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("ciphertext is not valid base64url");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * keccak256 of a raw ciphertext byte string, returned as a 0x-prefixed hex hash.
 *
 * The commitment is what an account stores on-chain, so it must be computed
 * over the *bytes that travelled*, never over a re-serialised structure.
 */
export function commitmentOf(bytes: Uint8Array): string {
  return `0x${keccak256Hex(bytes)}`;
}

/** Same value for a base64url wire string, without decoding it twice. */
export function commitmentOfBase64Url(value: string): string {
  return commitmentOf(base64UrlStringToBytes(value));
}

export { bytesToHex, hexToBytes };
