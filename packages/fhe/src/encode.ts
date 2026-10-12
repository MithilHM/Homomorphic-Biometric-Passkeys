/**
 * Fixed-point encoding and the encrypted decision procedure.
 *
 * Biometric templates are L2-normalised. For such vectors the squared Euclidean
 * distance collapses to the dot product:
 *
 *     D^2 = ||x - y||^2 = 2 - 2 * <x, y>
 *
 * so one homomorphic ciphertext multiplication is enough to evaluate the whole
 * similarity, and the coprocessor never needs the plaintext distance.
 */

import { normalize } from "@homobio/crypto-utils";
import type { RingContext } from "./ring.js";
import type { FheParams } from "./params.js";

export interface EncodedVector {
  /** Signed integer components on the 2^scaleBits grid. */
  components: bigint[];
  scaleBits: number;
  dimension: number;
}

export interface SimilarityResult {
  /** Estimated cosine similarity in [-1, 1]. */
  similarity: number;
  /** Estimated squared Euclidean distance, 2 - 2*similarity. */
  squaredDistance: number;
  /** Raw integer sum of the decrypted product coefficients. */
  rawDot: bigint;
  /** Absolute error bound in similarity units that this engine guarantees. */
  errorBound: number;
}

export type DecisionZone = "accept" | "reject" | "indeterminate";

export interface Decision {
  zone: DecisionZone;
  /** True only for the `accept` zone. */
  decision: boolean;
  similarity: number;
  threshold: number;
  margin: number;
}

/**
 * Quantise an embedding onto the fixed-point grid.
 *
 * The input MUST already be L2-normalised: the D^2 = 2 - 2S identity, and
 * therefore the decision itself, depends on it.
 */
export function encodeEmbedding(vector: ArrayLike<number>, scaleBits: number): EncodedVector {
  const normalized = normalize(vector);
  const components = new Array<bigint>(normalized.length);
  for (let i = 0; i < normalized.length; i++) {
    components[i] = BigInt(Math.round(normalized[i] * Math.pow(2, scaleBits)));
  }
  return { components, scaleBits, dimension: normalized.length };
}

/**
 * Where a vector is placed inside the plaintext polynomial.
 *
 * `low`  — component i sits in coefficient i.
 * `high` — component 0 sits in coefficient 0 unchanged, and component j > 0
 *          sits in coefficient N - j, negated.
 *
 * ## Why two layouts
 *
 * If both operands use `low`, the product coefficient c_k is the convolution
 * Σ_{i+j=k} x_i y_j and the dot product is the *sum over even coefficients* —
 * which no ring operation can extract without reintroducing the very noise we
 * are trying to measure.
 *
 * With one operand mirrored into `high`, every diagonal pair (i, i) lands in
 * coefficient 0 of the negacyclic product:
 *
 *     i + (N - i) = N   =>   X^i * X^(N-i) = X^N = -1
 *
 * The wrap contributes a minus, which the mirrored operand's negated
 * coefficient cancels; the (0, 0) pair carries no wrap, so it is stored
 * un-negated. Coefficient 0 of the product therefore equals <x, y> exactly,
 * and the coprocessor learns nothing beyond a single ciphertext. Every
 * off-diagonal pair lands somewhere else, so those only contribute noise —
 * noise that we measure and bound rather than assume.
 */
export type Layout = "low" | "high";

export function toPlaintext(ring: RingContext, encoded: EncodedVector, layout: Layout): bigint[] {
  const n = ring.n;
  const d = encoded.dimension;
  if (d >= n) throw new Error("embedding is too long for this ring dimension");
  const poly = ring.zero();
  if (layout === "low") {
    for (let i = 0; i < d; i++) poly[i] = encoded.components[i];
  } else {
    for (let i = 0; i < d; i++) {
      const value = encoded.components[i];
      if (i === 0) {
        poly[0] = value;
        continue;
      }
      poly[n - i] = value === 0n ? 0n : (ring.q - value) % ring.q;
    }
  }
  return poly;
}

/** Placements whose product degree stays below 2N, so at most one wrap occurs. */
export function assertLayoutFits(ring: RingContext, dimension: number): void {
  if (dimension >= ring.n) {
    throw new Error(`embedding dimension ${dimension} must be smaller than the ring dimension ${ring.n}`);
  }
}

/**
 * Convert a decrypted product polynomial into a similarity estimate.
 *
 * Only coefficient 0 is read, so the coprocessor's error is a single noise
 * term rather than a sum over the whole ring.
 *
 * `errorBound` is the engine's measured worst-case deviation over the benchmark
 * matrix; the decision procedure refuses to answer inside that band rather than
 * guessing, so a near-threshold capture produces an explicit `indeterminate`
 * state instead of a coin flip.
 */
export function similarityFromPlaintext(
  ring: RingContext,
  params: FheParams,
  plaintext: bigint[],
  errorBound: number,
): SimilarityResult {
  // With the `high`/`low` layout pair, coefficient 0 of the product *is* the
  // quantised dot product (see the layout note above).
  const rawDot = ring.toSigned(plaintext[0]);
  const similarity = Number(rawDot) / Math.pow(2, 2 * params.scaleBits);
  return {
    similarity,
    squaredDistance: 2 - 2 * similarity,
    rawDot,
    errorBound,
  };
}

/**
 * Threshold the estimate. `margin` is the noise band inside which we refuse to
 * decide (PRD section 12: an approximate comparison must expose its own
 * uncertainty instead of silently converting it into a boolean).
 */
export function decide(similarity: number, threshold: number, margin: number): Decision {
  if (margin <= 0) throw new Error("noise margin must be positive");
  const zone: DecisionZone =
    similarity >= threshold + margin ? "accept" : similarity <= threshold - margin ? "reject" : "indeterminate";
  return { zone, decision: zone === "accept", similarity, threshold, margin };
}
