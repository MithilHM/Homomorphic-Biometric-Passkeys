/**
 * Client-side biometric pipeline types.
 *
 * The camera frame never leaves this module: detection, alignment, quality
 * scoring and embedding all operate on `ImageData` in memory, and the only
 * output that crosses the network boundary is a quantized vector that is
 * immediately encrypted (PRD P1).
 */

export interface RgbaImage {
  width: number;
  height: number;
  data: Uint8ClampedArray;
}

export interface FaceBox {
  x: number;
  y: number;
  width: number;
  height: number;
  confidence: number;
}

export interface DetectionResult {
  faces: FaceBox[];
  /** Mean luminance of the whole frame. */
  luminance: number;
  /** Mean luminance inside the face box — the exposure signal that matters. */
  faceLuminance: number;
  /** Sharpness proxy (variance of the Laplacian), used for motion blur. */
  sharpness: number;
}

export interface QualityReport {
  score: number;
  reasons: string[];
  acceptable: boolean;
  luminance: number;
  sharpness: number;
  faceSize: number;
  centered: boolean;
}

export type LivenessAction = "turn_left" | "turn_right" | "blink" | "move_closer" | "hold_still";

export interface LivenessChallenge {
  action: LivenessAction;
  instruction: string;
  /** Minimum observable motion required to accept this action. */
  tolerance: number;
}

export interface LivenessResult {
  passed: boolean;
  /** Randomised challenge that was issued for this attempt. */
  challenge: LivenessChallenge;
  /** Per-action observations, for the audit trail (no pixels, no embedding). */
  observations: Record<string, number>;
  failureReason?: string;
}

export interface EmbeddingResult {
  vector: Float64Array;
  modelVersion: string;
  dimension: number;
  /** Deterministic checksum of the quantized vector, safe to log. */
  checksum: string;
}

export interface TemplateSample {
  vector: Float64Array;
  quality: number;
}

export interface TemplateAggregation {
  vector: Float64Array;
  acceptedSamples: number;
  rejectedSamples: number;
  intraClassSpread: number;
  modelVersion: string;
}

export type PipelineStage =
  | "idle"
  | "request_permission"
  | "camera_ready"
  | "face_detected"
  | "liveness_challenge"
  | "face_quality_ok"
  | "embedding_generated"
  | "encrypting"
  | "passkey_prompt"
  | "processing"
  | "proof_ready"
  | "submitting"
  | "success";

export type PipelineFailure =
  | "camera_denied"
  | "camera_unavailable"
  | "no_face"
  | "multiple_faces"
  | "low_light"
  | "poor_quality"
  | "liveness_failed"
  | "passkey_cancelled"
  | "passkey_not_supported"
  | "fhe_error"
  | "proof_error"
  | "bundler_rejected"
  | "transaction_reverted"
  | "challenge_expired"
  | "biometric_mismatch"
  | "indeterminate";

export interface FailureExplanation {
  code: PipelineFailure;
  title: string;
  detail: string;
  /** Concrete next action for the user. */
  action: string;
  retryable: boolean;
}
