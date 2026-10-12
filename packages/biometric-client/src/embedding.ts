/**
 * Alignment, quality scoring and embedding extraction.
 *
 * `EMBEDDING_VERSION` is part of the protocol: an enrolled template is only
 * comparable against a live capture produced by the same model version and the
 * same preprocessing. Changing either is a biometric protocol migration
 * (PRD section 39), not a configuration change — which is why the version is
 * carried on every template and every ciphertext.
 */

import { keccak256Hex, normalize } from "@homobio/crypto-utils";
import type { EmbeddingResult, FaceBox, QualityReport, RgbaImage } from "./types.js";

export const EMBEDDING_VERSION = "rp-canonical-v1";
export const CANONICAL_SIZE = 128;
export const EMBEDDING_DIMENSION = 128;

/* -------------------------------------------------------------------------- */
/*                                  Alignment                                  */
/* -------------------------------------------------------------------------- */

/**
 * Crop and resample the face box into a canonical grayscale square.
 *
 * Nearest-neighbour sampling is deliberate: it is deterministic, allocation-free
 * and produces identical bytes in every browser, which matters because the
 * template has to be reproducible across devices for the test vectors to mean
 * anything.
 */
export function alignFace(image: RgbaImage, box: FaceBox, size = CANONICAL_SIZE): Float32Array {
  const out = new Float32Array(size * size);
  for (let y = 0; y < size; y++) {
    const sy = box.y + (y / size) * box.height;
    const y0 = Math.max(0, Math.min(image.height - 1, Math.floor(sy)));
    const y1 = Math.max(0, Math.min(image.height - 1, y0 + 1));
    const wy = sy - y0;
    for (let x = 0; x < size; x++) {
      const sx = box.x + (x / size) * box.width;
      const x0 = Math.max(0, Math.min(image.width - 1, Math.floor(sx)));
      const x1 = Math.max(0, Math.min(image.width - 1, x0 + 1));
      const wx = sx - x0;

      const p00 = lumaAt(image, x0, y0);
      const p10 = lumaAt(image, x1, y0);
      const p01 = lumaAt(image, x0, y1);
      const p11 = lumaAt(image, x1, y1);

      const top = p00 + (p10 - p00) * wx;
      const bottom = p01 + (p11 - p01) * wx;
      out[y * size + x] = top + (bottom - top) * wy;
    }
  }
  return out;
}

/** Mean luminance of a single pixel. Exposed so the pipeline can share it. */
export function lumaAt(image: RgbaImage, x: number, y: number): number {
  const index = (y * image.width + x) * 4;
  if (index + 2 >= image.data.length) return 0;
  return 0.299 * image.data[index] + 0.587 * image.data[index + 1] + 0.114 * image.data[index + 2];
}

/* -------------------------------------------------------------------------- */
/*                              Quality scoring                                */
/* -------------------------------------------------------------------------- */

export interface QualityInput {
  /** Frame luminance, reported for diagnostics. */
  luminance: number;
  /** Luminance inside the face box; the exposure gate uses this. */
  faceLuminance: number;
  sharpness: number;
  face: FaceBox | undefined;
  frameWidth: number;
  frameHeight: number;
  faceCount: number;
}

const MIN_FACE_LUMINANCE = 55;
const MAX_FACE_LUMINANCE = 225;

export function scoreQuality(input: QualityInput): QualityReport {
  const reasons: string[] = [];

  if (input.faceCount === 0) {
    return {
      score: 0,
      reasons: ["no_face"],
      acceptable: false,
      luminance: input.luminance,
      sharpness: input.sharpness,
      faceSize: 0,
      centered: false,
    };
  }
  if (input.faceCount > 1) reasons.push("multiple_faces");

  if (input.faceLuminance < MIN_FACE_LUMINANCE) reasons.push("low_light");
  else if (input.faceLuminance > MAX_FACE_LUMINANCE) reasons.push("overexposed");
  if (input.sharpness < 12) reasons.push("blurry");

  const faceSize = input.face ? (input.face.width * input.face.height) / (input.frameWidth * input.frameHeight) : 0;
  if (faceSize < 0.05) reasons.push("face_too_small");

  const centered = input.face
    ? Math.abs(input.face.x + input.face.width / 2 - input.frameWidth / 2) < input.frameWidth * 0.22
    : false;
  if (!centered) reasons.push("off_center");

  let score = 1;
  score -= input.faceCount > 1 ? 0.6 : 0;
  score -= input.faceLuminance < MIN_FACE_LUMINANCE ? 0.25 : 0;
  score -= input.faceLuminance > MAX_FACE_LUMINANCE ? 0.2 : 0;
  score -= input.sharpness < 12 ? 0.2 : 0;
  score -= faceSize < 0.05 ? 0.2 : 0;
  score -= centered ? 0 : 0.1;
  score = Math.max(0, Math.min(1, score));

  // Hard gates: a frame that fails any of these is unusable no matter how the
  // weighted score lands. Silently accepting a dark or blurred capture would
  // push the failure downstream into a false biometric mismatch.
  const hardGates =
    input.faceCount === 1 &&
    input.faceLuminance >= MIN_FACE_LUMINANCE &&
    input.faceLuminance <= MAX_FACE_LUMINANCE &&
    input.sharpness >= 12 &&
    faceSize >= 0.05;

  return {
    score,
    reasons,
    acceptable: score >= 0.6 && hardGates,
    luminance: input.luminance,
    sharpness: input.sharpness,
    faceSize,
    centered,
  };
}

/* -------------------------------------------------------------------------- */
/*                                Embedding                                    */
/* -------------------------------------------------------------------------- */

/**
 * Deterministic feature projection.
 *
 * The canonical crop is reduced with a DCT-style basis and a fixed random
 * projection whose seed is derived from the model version. That gives a stable,
 * versioned descriptor with the properties the similarity stage needs:
 * L2-normalised, sensitive to structure rather than absolute brightness, and
 * reproducible for the calibration vectors.
 *
 * For a production deployment this is where a FaceNet/ArcFace ONNX graph runs
 * (PRD section 8.5); `EMBEDDING_VERSION` would become the model's version hash
 * and the enrollment would be invalidated for migration.
 */
export function embedAligned(aligned: Float32Array, size = CANONICAL_SIZE): EmbeddingResult {
  // 1. Remove global illumination and contrast.
  let mean = 0;
  for (const value of aligned) mean += value;
  mean /= aligned.length;
  let variance = 0;
  for (const value of aligned) variance += (value - mean) ** 2;
  const std = Math.sqrt(variance / aligned.length) || 1;

  const normalized = new Float32Array(aligned.length);
  for (let i = 0; i < aligned.length; i++) normalized[i] = (aligned[i] - mean) / std;

  // 2. 8x8 block means -> a 64-dimensional low-frequency descriptor.
  const blocks = 8;
  const blockSize = size / blocks;
  const descriptor = new Float64Array(blocks * blocks);
  for (let by = 0; by < blocks; by++) {
    for (let bx = 0; bx < blocks; bx++) {
      let sum = 0;
      for (let y = 0; y < blockSize; y++) {
        for (let x = 0; x < blockSize; x++) {
          sum += normalized[(by * blockSize + y) * size + (bx * blockSize + x)];
        }
      }
      descriptor[by * blocks + bx] = sum / (blockSize * blockSize);
    }
  }

  // 3. Horizontal and vertical gradients add orientation information, which is
  //    what makes the descriptor sensitive to pose.
  const features = new Float64Array(descriptor.length * 3);
  for (let i = 0; i < descriptor.length; i++) {
    const bx = i % blocks;
    const by = (i / blocks) | 0;
    const left = descriptor[by * blocks + Math.max(0, bx - 1)];
    const right = descriptor[by * blocks + Math.min(blocks - 1, bx + 1)];
    const up = descriptor[Math.max(0, by - 1) * blocks + bx];
    const down = descriptor[Math.min(blocks - 1, by + 1) * blocks + bx];
    features[i] = descriptor[i];
    features[descriptor.length + i] = (right - left) * 0.5;
    features[descriptor.length * 2 + i] = (down - up) * 0.5;
  }

  // 4. Fixed projection to EMBEDDING_DIMENSION, seeded by the model version.
  const vector = project(features, EMBEDDING_DIMENSION);
  const l2 = normalize(vector);
  const checksum = keccak256Hex(
    Int32Array.from(l2, (v) => Math.round(v * 1_000_000)).join(","),
  ).slice(0, 16);

  return { vector: l2, modelVersion: EMBEDDING_VERSION, dimension: EMBEDDING_DIMENSION, checksum };
}

/** Deterministic seeded projection (no global RNG: must be reproducible). */
function project(input: Float64Array, outputDim: number): Float64Array {
  const out = new Float64Array(outputDim);
  let state = hashSeed(EMBEDDING_VERSION);
  for (let i = 0; i < outputDim; i++) {
    let accumulator = 0;
    for (let j = 0; j < input.length; j++) {
      state = (state * 1664525 + 1013904223) >>> 0;
      const weight = ((state >>> 8) / 0xffffff) * 2 - 1;
      accumulator += weight * input[j];
    }
    // A second, sparser projection gives the descriptor a sparse component.
    let sparse = 0;
    for (let j = 0; j < input.length; j++) {
      if (j % 3 === i % 3) sparse += input[j];
    }
    out[i] = accumulator / Math.sqrt(input.length) + sparse * 0.25;
  }
  return out;
}

function hashSeed(text: string): number {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash || 1;
}
