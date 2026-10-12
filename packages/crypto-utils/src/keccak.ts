/**
 * Keccak-256 / SHA3-256.
 *
 * Dependency-free implementation so that the exact same primitive runs in Node,
 * in the browser bundle and in the Solidity cross-check tests. Lanes are 64-bit
 * BigInts: the protocol only needs a handful of hashes per request, and the
 * clarity is worth far more than the nanoseconds.
 *
 * Ethereum's keccak256 uses 0x01 domain padding (NOT SHA3's 0x06). Mixing the
 * two up silently breaks every on-chain commitment, so both are exposed here.
 */

const MASK64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** Rho rotation offsets indexed by lane i = x + 5y. */
const RHO: number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

function rotl64(x: bigint, n: number): bigint {
  if (n === 0) return x & MASK64;
  const s = BigInt(n);
  return ((x << s) | (x >> (64n - s))) & MASK64;
}

/** Keccak-f[1600] on a 25-lane state (lane i = x + 5y, little-endian bytes). */
export function keccakF1600(state: bigint[]): void {
  if (state.length !== 25) throw new Error("keccak state must hold 25 lanes");
  const c = new Array<bigint>(5);

  for (let round = 0; round < 24; round++) {
    // theta
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d;
    }

    // rho + pi
    const b = new Array<bigint>(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const src = x + 5 * y;
        const dstX = y;
        const dstY = (2 * x + 3 * y) % 5;
        b[dstX + 5 * dstY] = rotl64(state[src], RHO[src]);
      }
    }

    // chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5 * y] = (b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & MASK64) & b[((x + 2) % 5) + 5 * y]) & MASK64;
      }
    }

    // iota
    state[0] = (state[0] ^ ROUND_CONSTANTS[round]) & MASK64;
  }
}

const encoder = new TextEncoder();

function sponge(input: Uint8Array, rateBytes: number, padByte: number, outputBytes: number): Uint8Array {
  const state = new Array<bigint>(25).fill(0n);
  const lanesPerBlock = rateBytes / 8;

  const absorb = (block: Uint8Array, offset: number) => {
    for (let w = 0; w < lanesPerBlock; w++) {
      const b = offset + w * 8;
      let lane = 0n;
      for (let k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(block[b + k]);
      state[w] ^= lane;
    }
    keccakF1600(state);
  };

  let offset = 0;
  while (offset + rateBytes <= input.length) {
    absorb(input, offset);
    offset += rateBytes;
  }

  const tail = new Uint8Array(rateBytes);
  tail.set(input.subarray(offset));
  tail[input.length - offset] ^= padByte;
  tail[rateBytes - 1] ^= 0x80;
  absorb(tail, 0);

  const out = new Uint8Array(outputBytes);
  for (let i = 0; i < outputBytes; i++) {
    const lane = state[i >> 3];
    out[i] = Number((lane >> BigInt(8 * (i & 7))) & 0xffn);
  }
  return out;
}

/** Ethereum Keccak-256. */
export function keccak256(input: Uint8Array | string): Uint8Array {
  const bytes = typeof input === "string" ? encoder.encode(input) : input;
  return sponge(bytes, 136, 0x01, 32);
}

/** SHA3-256 (NIST padding, 0x06). */
export function sha3_256(input: Uint8Array | string): Uint8Array {
  const bytes = typeof input === "string" ? encoder.encode(input) : input;
  return sponge(bytes, 136, 0x06, 32);
}

/** Keccak-256 over a 64-byte domain-separated prefix + payload (EIP-712 style). */
export function keccak256Of(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return keccak256(buf);
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
