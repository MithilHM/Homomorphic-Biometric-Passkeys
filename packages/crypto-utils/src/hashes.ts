/**
 * Hashing + domain separation helpers.
 *
 * Every cross-service / cross-contract commitment in the protocol flows through
 * `domainHash`, so that a value produced for one context can never be replayed
 * into another (PRD P4: user intent must be cryptographically bound).
 */

import { concat, ascii, lengthPrefixed, uintToBytes, bytesToHex, bytesToBase64Url } from "./bytes.js";
import { keccak256 } from "./keccak.js";

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto SubtleCrypto is unavailable in this runtime");
  return c.subtle;
};

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const buf = await subtle().digest("SHA-256", bytes as unknown as BufferSource);
  return new Uint8Array(buf);
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return bytesToHex(await sha256(data));
}

export async function sha256B64Url(data: Uint8Array | string): Promise<string> {
  return bytesToBase64Url(await sha256(data));
}

/** keccak256 as hex string (Ethereum convention). */
export function keccak256Hex(data: Uint8Array | string): string {
  return bytesToHex(keccak256(data));
}

export const HASH_LENGTH = 32;

/** keccak256(abi.encodePacked("HOMOBIO/<domain>", ...lengthPrefixedFields)) */
export function domainHash(domain: string, ...fields: Uint8Array[]): Uint8Array {
  return keccak256(concat(ascii(`HOMOBIO/${domain}`), lengthPrefixed(...fields)));
}

export function domainHashHex(domain: string, ...fields: Uint8Array[]): string {
  return bytesToHex(domainHash(domain, ...fields));
}

/** Domain-separated hash of a canonical JSON document (stable key ordering). */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalise(value));
}

function canonicalise(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    if (typeof value === "bigint") return value.toString();
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("canonical JSON cannot encode non-finite numbers");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalise);
  if (ArrayBuffer.isView(value)) {
    return bytesToHex(value as unknown as Uint8Array);
  }
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    if (obj[key] === undefined) continue;
    out[key] = canonicalise(obj[key]);
  }
  return out;
}

export async function canonicalJsonHash(value: unknown): Promise<string> {
  return keccak256Hex(new TextEncoder().encode(canonicalJson(value)));
}

/** Nonce encoding shared by challenges, session keys and policy ids. */
export function nonceToBytes(nonce: string): Uint8Array {
  if (/^0x[0-9a-fA-F]*$/.test(nonce)) {
    const clean = nonce.slice(2);
    return hexBytes(clean);
  }
  if (/^[0-9a-fA-F]{64}$/.test(nonce)) return hexBytes(nonce);
  return new TextEncoder().encode(nonce);
}

function hexBytes(clean: string): Uint8Array {
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function u64(value: number | bigint): Uint8Array {
  return uintToBytes(value, 8);
}

export function u256(value: number | bigint): Uint8Array {
  return uintToBytes(value, 32);
}
