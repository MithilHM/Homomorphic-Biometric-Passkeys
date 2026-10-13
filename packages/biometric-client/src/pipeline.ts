/**
 * Template construction and the camera/analysis pipeline.
 *
 * Enrollment aggregates several captures rather than trusting one frame, which
 * is what makes the template stable under changes in lighting, angle and
 * expression (PRD section 9.1). Outlier samples are rejected against the
 * running mean before aggregation, so one bad frame cannot poison the template.
 */

import { dot, normalize } from "@homobio/crypto-utils";
import { detectFaces } from "./detect.js";
import { LivenessSession, eyeRegionLuminance, randomChallenge } from "./liveness.js";
import { EMBEDDING_DIMENSION, EMBEDDING_VERSION, alignFace, embedAligned, scoreQuality } from "./embedding.js";
import type {
  FailureExplanation,
  LivenessResult,
  QualityReport,
  RgbaImage,
  TemplateAggregation,
  TemplateSample,
} from "./types.js";

export const ENROLLMENT_SAMPLE_COUNT = 7;
export const OUTLIER_THRESHOLD = 0.82;

/**
 * Aggregate enrollment samples into a template.
 *
 * `T = Normalize(mean(accepted samples))`, with samples below
 * `OUTLIER_THRESHOLD` cosine similarity to the running mean rejected. The
 * spread of the accepted set is reported so the caller can refuse an
 * enrollment whose captures are wildly inconsistent (usually a lighting or
 * framing problem, not a face).
 */
export function aggregateTemplate(samples: TemplateSample[], dimension = EMBEDDING_DIMENSION): TemplateAggregation {
  if (samples.length === 0) throw new Error("cannot build a template without samples");

  const sorted = [...samples].sort((a, b) => b.quality - a.quality);
  const accepted: Float64Array[] = [];
  let rejected = 0;

  for (const sample of sorted) {
    // Slice to the negotiated dimension first, then normalize: the outlier
    // test must compare unit vectors of equal length (T1).
    const candidate = Float64Array.from(normalize(sample.vector.slice(0, dimension)));
    if (accepted.length === 0) {
      accepted.push(candidate);
      continue;
    }
    const centroid = meanVector(accepted);
    if (dot(centroid, candidate) >= OUTLIER_THRESHOLD) {
      accepted.push(candidate);
    } else {
      rejected++;
    }
  }

  const vector = meanVector(accepted);
  const spread =
    accepted.length > 1
      ? Math.max(...accepted.map((v) => 1 - dot(v, vector)))
      : 0;

  return {
    vector,
    acceptedSamples: accepted.length,
    rejectedSamples: rejected,
    intraClassSpread: spread,
    modelVersion: EMBEDDING_VERSION,
  };
}

function meanVector(vectors: Float64Array[]): Float64Array {
  const out = new Float64Array(vectors[0].length);
  for (const vector of vectors) {
    for (let i = 0; i < out.length; i++) out[i] += vector[i];
  }
  return normalize(out);
}

/** Analyse one frame: detect, score, and (optionally) extract an embedding. */
export interface FrameAnalysis {
  quality: QualityReport;
  faces: number;
  embedding?: Float64Array;
  eyeLuminance?: number;
}

export function analyzeFrame(image: RgbaImage, options: { extractEmbedding?: boolean } = {}): FrameAnalysis {
  const detection = detectFaces(image);
  const face = detection.faces[0];
  const quality = scoreQuality({
    luminance: detection.luminance,
    faceLuminance: detection.faceLuminance,
    sharpness: detection.sharpness,
    face,
    frameWidth: image.width,
    frameHeight: image.height,
    faceCount: detection.faces.length,
  });

  if (!options.extractEmbedding || !quality.acceptable || !face) {
    return { quality, faces: detection.faces.length };
  }

  const aligned = alignFace(image, face);
  const embedding = embedAligned(aligned);
  return {
    quality,
    faces: detection.faces.length,
    embedding: embedding.vector,
    eyeLuminance: eyeRegionLuminance(image.data, image.width, image.height, face),
  };
}

/**
 * A liveness session bound to real frames.
 *
 * The session is created per authentication attempt with a fresh randomised
 * challenge, so a pre-recorded motion sequence cannot satisfy it: the prompt
 * itself is not known in advance.
 */
export class BiometricCaptureSession {
  readonly liveness: LivenessSession;
  private readonly samples: TemplateSample[] = [];
  private lastResult?: LivenessResult;

  constructor(private readonly options: { allow?: Array<"turn_left" | "turn_right" | "blink" | "move_closer"> } = {}) {
    this.liveness = new LivenessSession({ challenge: randomChallenge(this.options.allow) });
  }

  get instruction(): string {
    return this.liveness.challenge.instruction;
  }

  get capturedSamples(): TemplateSample[] {
    return [...this.samples];
  }

  get livenessResult(): LivenessResult | undefined {
    return this.lastResult;
  }

  /** Push a frame; returns the liveness result once the challenge is satisfied. */
  push(image: RgbaImage): { quality: QualityReport; liveness?: LivenessResult } {
    const analysis = analyzeFrame(image, { extractEmbedding: true });
    if (analysis.quality.acceptable && analysis.embedding && analysis.eyeLuminance !== undefined) {
      this.samples.push({ vector: analysis.embedding, quality: analysis.quality.score });
      const face = detectFaces(image).faces[0];
      const result = this.liveness.push({
        box: face ?? { x: 0, y: 0, width: 1, height: 1, confidence: 0 },
        eyeRegionLuminance: analysis.eyeLuminance,
        timestamp: Date.now(),
      });
      if (result) this.lastResult = result;
      return { quality: analysis.quality, liveness: result };
    }
    return { quality: analysis.quality };
  }
}

/** Human-readable failure states (PRD section 32.3 / 57). */
export function explainFailure(code: FailureExplanation["code"], detail?: string): FailureExplanation {
  const table: Record<FailureExplanation["code"], Omit<FailureExplanation, "code">> = {
    camera_denied: {
      title: "Camera access is required",
      detail: "Face verification happens on your device, so the camera is needed.",
      action: "Allow camera access in your browser settings and try again.",
      retryable: true,
    },
    camera_unavailable: {
      title: "No camera available",
      detail: "This device did not expose a usable camera.",
      action: "Connect a camera, or use a backup passkey to authorize instead.",
      retryable: false,
    },
    no_face: {
      title: "No face detected",
      detail: "We could not find a face in the camera frame.",
      action: "Move into the frame, face the camera, and try again.",
      retryable: true,
    },
    multiple_faces: {
      title: "Only one person can be present",
      detail: "More than one face was detected in the frame.",
      action: "Make sure you are alone in the frame and retry.",
      retryable: true,
    },
    low_light: {
      title: "Not enough light",
      detail: "The frame is too dark to verify reliably.",
      action: "Move somewhere brighter or turn on a light facing you.",
      retryable: true,
    },
    poor_quality: {
      title: "Image quality is too low",
      detail: "The capture was blurry, too small, or off-centre.",
      action: "Hold still, centre your face, and retry.",
      retryable: true,
    },
    liveness_failed: {
      title: "Liveness check failed",
      detail: "We could not confirm this was a live interaction.",
      action: "Follow the on-screen instruction and retry.",
      retryable: true,
    },
    passkey_cancelled: {
      title: "Passkey authentication cancelled",
      detail: "The passkey prompt was dismissed before completing.",
      action: "Start the authentication again and confirm with your passkey.",
      retryable: true,
    },
    passkey_not_supported: {
      title: "Passkeys are not supported",
      detail: "This browser cannot create or use a passkey.",
      action: "Use a recent version of Chrome, Safari, Edge or Firefox on a passkey-capable device.",
      retryable: false,
    },
    fhe_error: {
      title: "Secure comparison failed",
      detail: "The encrypted comparison could not be completed. No transaction was submitted.",
      action: "Retry the authentication.",
      retryable: true,
    },
    proof_error: {
      title: "Authorization proof invalid",
      detail: "The authorization could not be verified, so nothing was submitted.",
      action: "Retry; if this repeats, your session has been logged as a security event.",
      retryable: true,
    },
    bundler_rejected: {
      title: "Transaction could not enter the network",
      detail: "The bundler rejected the operation.",
      action: "Check your network connection and retry.",
      retryable: true,
    },
    transaction_reverted: {
      title: "Transaction execution failed",
      detail: "The transaction was included but reverted on chain.",
      action: "Review the transaction details and try again.",
      retryable: true,
    },
    challenge_expired: {
      title: "Authentication session expired",
      detail: "Security challenges are short-lived by design.",
      action: "Start the authentication again.",
      retryable: true,
    },
    biometric_mismatch: {
      title: "Biometric verification failed",
      detail: "Your face did not match the enrolled template. No transaction was submitted.",
      action: "Retry, or use a recovery passkey if your appearance has changed.",
      retryable: true,
    },
    indeterminate: {
      title: "Result was too close to call",
      detail: "The encrypted comparison landed inside the engine's noise band, so we refuse to guess.",
      action: "Capture one more sample; slight lighting or angle changes usually resolve it.",
      retryable: true,
    },
  };
  const entry = table[code];
  return { code, ...entry, detail: detail ? `${entry.detail} (${detail})` : entry.detail };
}

/** Synthetic sample generator used by the test suite and the offline demo. */
export function syntheticSamples(count: number, seed = 1): TemplateSample[] {
  // A shared base identity with small per-sample variation: this is what a real
  // enrollment looks like (same person, different frames).
  const base = seededUnitVectorLocal(EMBEDDING_DIMENSION, seed, 1, (i) => Math.sin(i * 0.7 + seed));
  const out: TemplateSample[] = [];
  for (let i = 0; i < count; i++) {
    out.push({
      vector: seededUnitVectorLocal(EMBEDDING_DIMENSION, seed * 31 + i, 0.03, (k) => base[k]),
      quality: 0.9,
    });
  }
  return out;
}

/**
 * Deterministic unit vector generator that works identically in Node and the
 * browser, for demos, offline capture paths and calibration vectors.
 *
 * A pure `Math.random()` implementation would make every captured "enrollment"
 * different, which would make the demo meaningless and the calibration
 * vectors irreproducible.
 */
export function seededUnitVectorLocal(
  dimension: number,
  seed: number,
  jitter = 0,
  base?: (index: number) => number,
): Float64Array {
  const out = new Float64Array(dimension);
  let state = (seed >>> 0) || 0x9e3779b9;
  let norm = 0;
  for (let i = 0; i < dimension; i++) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    const noise = (state / 0xffffffff) * 2 - 1;
    const value = (base ? base(i) : 0) + noise * (jitter === 0 ? 1 : jitter);
    out[i] = value;
    norm += value * value;
  }
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < dimension; i++) out[i] /= norm;
  return out;
}
