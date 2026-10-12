/**
 * FHE parameter sets.
 *
 * Numbers here are the *measured* output of `npm run bench` plus the argument in
 * `docs/crypto-parameters.md`. They are deliberately not copied from an example:
 * ring dimension, modulus and fixed-point scale trade ciphertext size, latency
 * and similarity resolution against each other, and the benchmark decides.
 */

import { RingContext } from "./ring.js";
import { findPrime, isProbablePrime } from "./field.js";

export const ENGINE_ID = "rlwe-negacyclic-d1";
export const ENCODING_VERSION = 1;

export interface FheParams {
  engine: string;
  ringDimension: number;
  modulus: string;
  /** Fixed-point exponent: component = round(value * 2^scaleBits). */
  scaleBits: number;
  embeddingDimension: number;
  securityLevelBits: number;
  encodingVersion: number;
}

/**
 * Default set.
 *
 * - N = 1024 over Z_q[X]/(X^1024 + 1) gives ~128-bit RLWE hardness at q = 2^61
 *   (dimension far above Kyber-512's 256 and modulus far above its 3329).
 * - q = 1152921504606877697 = 2^60 + 1 + 512*2^11 is the smallest 61-bit prime
 *   congruent to 1 (mod 2N), which the NTT embedding requires.
 * - scaleBits = 18 keeps the worst-case plaintext magnitude (n * 2^36 ~ 2^43)
 *   far below q/2 while leaving ~2^-9 resolution on the cosine similarity after
 *   one homomorphic multiplication. See `packages/fhe/test/accuracy.test.ts`.
 * - embeddingDimension = 128 keeps 2n - 2 < N so the negacyclic convolution
 *   never wraps and the decrypted coefficient sum is exactly the dot product.
 */
export const DEFAULT_FHE_PARAMS: FheParams = {
  engine: ENGINE_ID,
  ringDimension: 1024,
  modulus: "1152921504606877697",
  scaleBits: 18,
  embeddingDimension: 128,
  securityLevelBits: 128,
  encodingVersion: ENCODING_VERSION,
};

export function verifyParams(params: FheParams): void {
  const n = params.ringDimension;
  const q = BigInt(params.modulus);
  if ((n & (n - 1)) !== 0) throw new Error("ring dimension must be a power of two");
  if ((q - 1n) % BigInt(2 * n) !== 0n) {
    throw new Error("modulus must be 1 (mod 2N) so that the NTT embedding exists");
  }
  if (!isProbablePrime(q)) throw new Error("modulus is not prime");
  if (params.embeddingDimension * 2 - 2 >= n) {
    throw new Error("embedding dimension is too large: the negacyclic convolution would wrap");
  }
  const maxPlaintext = BigInt(params.embeddingDimension) << BigInt(2 * params.scaleBits);
  if (maxPlaintext > q >> 2n) {
    throw new Error("fixed-point scale is too coarse: plaintext would wrap the modulus");
  }
}

export function buildRing(params: FheParams = DEFAULT_FHE_PARAMS): RingContext {
  verifyParams(params);
  return new RingContext(params.ringDimension, BigInt(params.modulus));
}

/** Discover the canonical modulus for a different ring dimension (benchmarks). */
export function paramsForRingDimension(ringDimension: number, overrides: Partial<FheParams> = {}): FheParams {
  return {
    ...DEFAULT_FHE_PARAMS,
    ...overrides,
    ringDimension,
    modulus: findPrime(61, 2 * ringDimension).toString(),
  };
}
