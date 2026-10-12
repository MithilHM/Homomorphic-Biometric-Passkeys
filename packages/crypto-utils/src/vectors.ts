/**
 * Embedding vector maths + the fixed-point codec that the FHE layer operates on.
 *
 * Biometric templates are L2-normalised float32 vectors. The homomorphic engine
 * never sees floats: every component is quantised to a signed integer with a
 * shared power-of-two scale, so the dot product can be evaluated exactly in an
 * integer ring and only converted back to a similarity score inside the
 * decryption committee.
 */

export interface VectorStats {
  length: number;
  norm: number;
  min: number;
  max: number;
  meanAbs: number;
}

export function stats(v: ArrayLike<number>): VectorStats {
  let sq = 0;
  let min = Infinity;
  let max = -Infinity;
  let abs = 0;
  for (let i = 0; i < v.length; i++) {
    sq += v[i] * v[i];
    abs += Math.abs(v[i]);
    if (v[i] < min) min = v[i];
    if (v[i] > max) max = v[i];
  }
  return {
    length: v.length,
    norm: Math.sqrt(sq),
    min,
    max,
    meanAbs: v.length ? abs / v.length : 0,
  };
}

/** L2 normalisation. A zero vector maps to zeros rather than NaN. */
export function normalize(vector: ArrayLike<number>): Float64Array {
  let sq = 0;
  for (let i = 0; i < vector.length; i++) sq += vector[i] * vector[i];
  const norm = Math.sqrt(sq);
  const out = new Float64Array(vector.length);
  if (norm === 0) return out;
  for (let i = 0; i < vector.length; i++) out[i] = vector[i] / norm;
  return out;
}

export function dot(a: ArrayLike<number>, b: ArrayLike<number>): number {
  if (a.length !== b.length) throw new Error(`dimension mismatch: ${a.length} vs ${b.length}`);
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += a[i] * b[i];
  return sum;
}

export function euclideanDistanceSquared(a: ArrayLike<number>, b: ArrayLike<number>): number {
  if (a.length !== b.length) throw new Error(`dimension mismatch: ${a.length} vs ${b.length}`);
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return sum;
}

/**
 * For L2-normalised embeddings:  D^2 = 2 - 2*S  where S = <x, y>.
 * This is the quantity evaluated inside the FHE domain (PRD section 10.2).
 */
export function squaredDistanceFromCosine(cosine: number): number {
  return 2 - 2 * cosine;
}

export function clamp(value: number, lo: number, hi: number): number {
  return value < lo ? lo : value > hi ? hi : value;
}

/**
 * Quantise a normalised embedding onto the integer grid `scale * Z`.
 * Returns symmetric signed integers so that the homomorphic dot product is exact.
 */
export function quantize(vector: ArrayLike<number>, scaleBits: number): Int32Array {
  const scale = Math.pow(2, scaleBits);
  const out = new Int32Array(vector.length);
  for (let i = 0; i < vector.length; i++) {
    const q = Math.round(vector[i] * scale);
    if (!Number.isSafeInteger(q)) throw new Error(`component ${i} overflowed the quantisation grid`);
    out[i] = q;
  }
  return out;
}

export function dequantize(vector: ArrayLike<number>, scaleBits: number): Float64Array {
  const scale = Math.pow(2, scaleBits);
  const out = new Float64Array(vector.length);
  for (let i = 0; i < vector.length; i++) out[i] = vector[i] / scale;
  return out;
}

/** Integer dot product; mirrors exactly what the FHE engine computes. */
export function integerDot(a: ArrayLike<number>, b: ArrayLike<number>): number {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += a[i] * b[i];
  return sum;
}

/** Median of the pairwise impostor distances — the basis of threshold calibration. */
export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = clamp(p, 0, 1) * (sorted.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
}

/** Deterministic pseudo-random unit vector generator for tests and benchmarks. */
export function seededUnitVector(dim: number, seed: number): Float64Array {
  const out = new Float64Array(dim);
  let state = (seed >>> 0) || 1;
  let norm = 0;
  for (let i = 0; i < dim; i++) {
    // xorshift32 -> uniform in [-1, 1)
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    const u = (state / 0xffffffff) * 2 - 1;
    out[i] = u;
    norm += u * u;
  }
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < dim; i++) out[i] /= norm;
  return out;
}

/** Perturb a unit vector by `jitter` (used to build "same person, new capture"). */
export function jitterUnitVector(base: ArrayLike<number>, jitter: number, seed: number): Float64Array {
  const dim = base.length;
  const noise = seededUnitVector(dim, seed);
  const out = new Float64Array(dim);
  for (let i = 0; i < dim; i++) out[i] = base[i] + noise[i] * jitter;
  return normalize(out);
}
