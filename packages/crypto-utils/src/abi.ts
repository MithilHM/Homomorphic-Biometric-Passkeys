/**
 * Minimal, deterministic Solidity ABI encoder.
 *
 * Only the subset the protocol needs is supported: `uintN`, `address`,
 * `bytes32`, `bool` and dynamic `bytes`. The output is byte-identical to
 * Solidity's `abi.encode` / `abi.encodePacked`, which is what lets the account
 * re-derive every commitment on-chain and lets our cross-language tests compare
 * against `solc`-compiled expectations.
 *
 * `test/abi.test.ts` cross-checks this encoder against viem's reference
 * implementation for every shape the protocol uses.
 */

import { concat, lengthPrefixed, uintToBytes, hexToBytes, bytesToHex } from "./bytes.js";

export type AbiType =
  | `uint${number}`
  | `bytes${"" | 1 | 2 | 3 | 4 | 8 | 12 | 16 | 20 | 24 | 28 | 32}`
  | "address"
  | "bytes32"
  | "bool"
  | "bytes";

export interface AbiParam {
  type: AbiType;
  value: string | number | bigint | boolean | Uint8Array;
}

const WORD = 32;

function isDynamic(type: AbiType): boolean {
  return type === "bytes";
}

function padRight32(data: Uint8Array): Uint8Array {
  const rem = data.length % WORD;
  if (rem === 0) return data;
  return concat(data, new Uint8Array(WORD - rem));
}

function encodeStatic(type: AbiType, value: AbiParam["value"]): Uint8Array {
  if (type.startsWith("bytes") && type !== "bytes") {
    const width = Number(type.slice(5));
    const bytes = value instanceof Uint8Array ? value : hexToBytes(String(value));
    if (bytes.length !== width) throw new Error(`${type} must be ${width} bytes`);
    return bytes;
  }
  switch (type) {
    case "bool":
      return uintToBytes(value ? 1n : 0n, WORD);
    case "address": {
      const bytes = hexToBytes(String(value));
      if (bytes.length !== 20) throw new Error("address must be 20 bytes");
      return concat(new Uint8Array(12), bytes);
    }
    case "bytes32": {
      const bytes = hexToBytes(String(value));
      if (bytes.length !== 32) throw new Error("bytes32 must be 32 bytes");
      return bytes;
    }
    default: {
      const bits = Number(type.slice(4));
      if (!Number.isFinite(bits) || bits % 8 !== 0 || bits < 8 || bits > 256) {
        throw new Error(`unsupported uint width: ${type}`);
      }
      return uintToBytes(BigInt(value as string | number | bigint), bits / 8);
    }
  }
}

/** `abi.encode(...)` for the supported subset. */
export function abiEncode(params: AbiParam[]): Uint8Array {
  const headSize = params.length * WORD;
  const heads: Uint8Array[] = [];
  const tails: Uint8Array[] = [];

  for (const p of params) {
    if (isDynamic(p.type)) {
      const data = p.value instanceof Uint8Array ? p.value : hexToBytes(String(p.value));
      heads.push(uintToBytes(BigInt(headSize + tailSize(tails)), WORD));
      tails.push(concat(uintToBytes(BigInt(data.length), WORD), padRight32(data)));
    } else {
      heads.push(encodeStatic(p.type, p.value));
    }
  }

  return concat(...heads, ...tails);
}

function tailSize(tails: Uint8Array[]): number {
  return tails.reduce((acc, t) => acc + t.length, 0);
}

/**
 * `abi.encodePacked(...)` for the supported subset.
 *
 * Unlike `abi.encode`, packed encoding uses minimal width: uintN occupies N/8
 * bytes, bytesN occupies exactly N/8 bytes, and `bytes` is written verbatim.
 */
export function abiEncodePacked(parts: { type: AbiType; value: AbiParam["value"] }[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const p of parts) {
    if (p.type === "bytes") {
      chunks.push(p.value instanceof Uint8Array ? p.value : hexToBytes(String(p.value)));
      continue;
    }
    if (p.type === "bool") {
      chunks.push(Uint8Array.of(p.value ? 1 : 0));
      continue;
    }
    if (p.type === "address") {
      const bytes = hexToBytes(String(p.value));
      if (bytes.length !== 20) throw new Error("address must be 20 bytes");
      chunks.push(bytes);
      continue;
    }
    if (p.type.startsWith("bytes")) {
      // encodeStatic validates the exact byte width for bytesN.
      chunks.push(encodeStatic(p.type, p.value));
      continue;
    }
    const bits = Number(p.type.slice(4));
    if (!Number.isFinite(bits) || bits % 8 !== 0 || bits < 8 || bits > 256) {
      throw new Error(`unsupported packed width: ${p.type}`);
    }
    chunks.push(encodeStatic(p.type, p.value));
  }
  return concat(...chunks);
}

export function abiEncodeHex(params: AbiParam[]): string {
  return bytesToHex(abiEncode(params));
}

/** Convenience: length-prefixed field framing used by the canonical envelope hash. */
export { lengthPrefixed };
