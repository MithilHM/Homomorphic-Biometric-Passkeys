/**
 * Cryptographic and Math Utilities for Homomorphic Biometric Passkeys
 */

export const CKKS_CONFIG = {
  POLY_MODULUS_DEGREE: 8192,
  COEFF_MOD_BIT_SIZES: [60, 40, 40, 60],
  SCALE: Math.pow(2, 40),
  SECURITY_LEVEL: 128,
  SCHEME: 'CKKS',
  EMBEDDING_DIMENSION: 512
};

/**
 * Perform L2 normalization on a floating-point embedding vector.
 */
export function normalizeEmbedding(vector: number[] | Float32Array): number[] {
  let sumSq = 0;
  for (let i = 0; i < vector.length; i++) {
    sumSq += vector[i] * vector[i];
  }
  const norm = Math.sqrt(sumSq);
  if (norm === 0) return Array.from(vector).map(() => 0);
  return Array.from(vector).map(v => v / norm);
}

/**
 * Compute Euclidean distance squared between two vectors.
 * D^2 = sum((x_i - y_i)^2)
 */
export function euclideanDistanceSquared(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new Error(`Dimension mismatch: ${a.length} vs ${b.length}`);
  }
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return sum;
}

/**
 * Compute Cosine similarity between two vectors.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

/**
 * Mock client-side CKKS ciphertext representation for browser & test integration.
 */
export interface SerializedCiphertext {
  version: number;
  dim: number;
  polyDegree: number;
  payload: string; // Base64
}

export function serializeMockCiphertext(vector: number[]): string {
  const normalized = normalizeEmbedding(vector);
  const data = JSON.stringify({
    scheme: 'CKKS',
    degree: CKKS_CONFIG.POLY_MODULUS_DEGREE,
    slots: CKKS_CONFIG.POLY_MODULUS_DEGREE / 2,
    vector: normalized,
    timestamp: Date.now()
  });
  return typeof btoa !== 'undefined' ? btoa(data) : Buffer.from(data).toString('base64');
}

export function deserializeMockCiphertext(b64: string): { vector: number[] } {
  const jsonStr = typeof atob !== 'undefined' ? atob(b64) : Buffer.from(b64, 'base64').toString('utf-8');
  return JSON.parse(jsonStr);
}
