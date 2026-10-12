/**
 * COSE key handling (RFC 8152) and conversion to SPKI DER for Node's verifier.
 *
 * We accept ES256 (P-256 / SHA-256) only: that is what platform authenticators
 * and FIDO2 security keys produce in practice, and every extra algorithm is
 * extra attack surface in a signing-root parser.
 */

import { bytesToHex } from "@homobio/crypto-utils";
import { decodeCborMap, type CborValue } from "./cbor.js";

export const COSE_ALG_ES256 = -7;
export const COSE_KTY_EC2 = 2;
export const COSE_CRV_P256 = 1;

const P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);

export interface CoseKey {
  kty: number;
  alg: number;
  crv: number;
  x: Uint8Array;
  y: Uint8Array;
}

function requireBytes(map: Map<number | string, CborValue>, key: number, label: string): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array)) throw new Error(`COSE key is missing ${label}`);
  return value;
}

function requireInt(map: Map<number | string, CborValue>, key: number, label: string): number {
  const value = map.get(key);
  if (typeof value !== "number") throw new Error(`COSE key is missing ${label}`);
  return value;
}

export function parseCoseKey(bytes: Uint8Array): CoseKey {
  const map = decodeCborMap(bytes);
  const kty = requireInt(map, 1, "kty");
  const alg = requireInt(map, 3, "alg");
  const crv = requireInt(map, -1, "crv");

  if (kty !== COSE_KTY_EC2) {
    throw new Error(`unsupported COSE key type ${kty}; only EC2 (P-256) is accepted`);
  }
  if (crv !== COSE_CRV_P256) {
    throw new Error(`unsupported COSE curve ${crv}; only P-256 is accepted`);
  }
  if (alg !== COSE_ALG_ES256) {
    throw new Error(`unsupported COSE algorithm ${alg}; only ES256 is accepted`);
  }

  const x = requireBytes(map, -2, "x");
  const y = requireBytes(map, -3, "y");
  if (x.length !== 32 || y.length !== 32) throw new Error("P-256 coordinates must be 32 bytes");
  return { kty, alg, crv, x, y };
}

/** ES256 COSE key -> SPKI DER, the format `crypto.createPublicKey` expects. */
export function coseKeyToSpkiDer(key: CoseKey): Uint8Array {
  const out = new Uint8Array(P256_SPKI_PREFIX.length + 64);
  out.set(P256_SPKI_PREFIX, 0);
  out.set(key.x, P256_SPKI_PREFIX.length);
  out.set(key.y, P256_SPKI_PREFIX.length + 32);
  return out;
}

/** Last 32 bytes of the SPKI DER — a stable, loggable key identifier. */
export function cosePublicKeyFingerprint(spkiDer: Uint8Array): string {
  return `0x${bytesToHex(spkiDer).slice(-64)}`;
}
