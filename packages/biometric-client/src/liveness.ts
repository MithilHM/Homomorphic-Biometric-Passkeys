/**
 * Active liveness (PRD section 8.3).
 *
 * A face detector is NOT a liveness system. This module adds randomised
 * challenge-response: the server-neutral client picks an action at random and
 * requires the user to actually perform it, measured from frame-to-frame
 * geometry. A held-up photograph fails every motion challenge; a replayed video
 * fails the temporal-consistency check, because a recorded session replays the
 * same motion trajectory.
 *
 * What this is NOT: a defence against a sophisticated deepfake. That requires
 * the production path (passive liveness, depth, sensor attestation) described in
 * the PRD. Failing that, the module reports `liveness_failed` rather than
 * pretending the check was stronger than it is.
 */

import { randomBytes } from "@homobio/crypto-utils";
import type { FaceBox, LivenessAction, LivenessChallenge, LivenessResult } from "./types.js";

export const LIVENESS_VERSION = "active-challenge-v1";

const ACTIONS: Array<{ action: LivenessAction; instruction: string; tolerance: number }> = [
  { action: "turn_left", instruction: "Turn your head slowly to the left", tolerance: 0.055 },
  { action: "turn_right", instruction: "Turn your head slowly to the right", tolerance: 0.055 },
  { action: "blink", instruction: "Blink twice, slowly", tolerance: 0.6 },
  { action: "move_closer", instruction: "Move a little closer to the camera", tolerance: 0.12 },
];

const HOLD_STILL_DEFAULT_TOLERANCE = 5;

/** Reject unknown actions and non-finite tolerances at construction (L7). */
function sanitizeChallenge(challenge: LivenessChallenge): LivenessChallenge {
  const known = ACTIONS.find((a) => a.action === challenge.action);
  if (known) {
    if (Number.isFinite(challenge.tolerance) && challenge.tolerance > 0) return { ...challenge };
    return { ...known };
  }
  if (challenge.action === "hold_still") {
    const tolerance = Number.isFinite(challenge.tolerance) && challenge.tolerance > 0
      ? challenge.tolerance
      : HOLD_STILL_DEFAULT_TOLERANCE;
    return { action: "hold_still", instruction: challenge.instruction || "Hold still", tolerance };
  }
  const fallback = ACTIONS[0];
  return { action: fallback.action, instruction: fallback.instruction, tolerance: fallback.tolerance };
}

export function randomChallenge(allowed?: LivenessAction[]): LivenessChallenge {
  const pool = allowed && allowed.length > 0 ? ACTIONS.filter((a) => allowed.includes(a.action)) : ACTIONS;
  const source = pool.length > 0 ? pool : ACTIONS;
  const choice = source[randomBytes(1)[0] % source.length];
  return { action: choice.action, instruction: choice.instruction, tolerance: choice.tolerance };
}

export interface FrameObservation {
  box: FaceBox;
  /** Mean luminance of the upper-face band, used as a blink signal. */
  eyeRegionLuminance: number;
  timestamp: number;
}

export interface LivenessSessionOptions {
  challenge?: LivenessChallenge;
  /** Minimum number of frames the session must span. */
  minFrames?: number;
  /** Maximum number of frames before the attempt is abandoned. */
  maxFrames?: number;
}

export class LivenessSession {
  readonly challenge: LivenessChallenge;
  private readonly frames: FrameObservation[] = [];
  private readonly minFrames: number;
  private readonly maxFrames: number;
  private finished = false;

  constructor(options: LivenessSessionOptions = {}) {
    this.challenge = sanitizeChallenge(options.challenge ?? randomChallenge());
    this.minFrames = options.minFrames ?? 6;
    this.maxFrames = options.maxFrames ?? 180;
  }

  get frameCount(): number {
    return this.frames.length;
  }

  get isFinished(): boolean {
    return this.finished;
  }

  /** Feed one analysed frame. Returns a result once enough motion has accrued. */
  push(observation: FrameObservation): LivenessResult | undefined {
    if (this.finished) return undefined;
    this.frames.push(observation);
    if (this.frames.length < this.minFrames) return undefined;
    if (this.frames.length < this.maxFrames) {
      const partial = this.evaluate(false);
      return partial.passed ? { ...partial, passed: true } : undefined;
    }
    return this.evaluate(true);
  }

  /** Force evaluation (timeout, or the caller decided enough frames were seen). */
  finish(): LivenessResult {
    return this.evaluate(true);
  }

  private evaluate(final: boolean): LivenessResult {
    const observations = this.measure();
    const tolerance = this.challenge.tolerance;
    let passed = false;
    let failureReason: string | undefined;

    switch (this.challenge.action) {
      case "turn_left":
      case "turn_right": {
        // A head turn moves the face box horizontally relative to its centre
        // while keeping roughly the same area.
        const drift = Math.max(...observations.horizontalDrift ?? [0]);
        passed = drift >= tolerance;
        if (!passed) failureReason = `not enough head movement (${drift.toFixed(3)} < ${tolerance})`;
        break;
      }
      case "move_closer": {
        const growth = Math.max(...(observations.areaGrowth ?? [0]));
        passed = growth >= tolerance;
        if (!passed) failureReason = `face did not approach the camera (${growth.toFixed(3)} < ${tolerance})`;
        break;
      }
      case "blink": {
        const dips = observations.blinkCount ?? 0;
        passed = dips >= 2;
        if (!passed) failureReason = `expected two blinks, observed ${dips}`;
        break;
      }
      case "hold_still": {
        const jitter = observations.maxJitter ?? 0;
        passed = jitter <= tolerance;
        if (!passed) failureReason = "the frame kept moving; a still image is required";
        break;
      }
    }

    if (!passed && !final) {
      // Not enough evidence yet: keep collecting frames.
      return {
        passed: false,
        challenge: this.challenge,
        observations: observations.metrics,
        failureReason: "collecting more frames",
      };
    }

    // L2: sufficient motion passes immediately — the old code returned
    // `passed: final && passed`, so an early pass was reported as false while
    // still marking the session finished, bricking `push()` forever after.
    this.finished = true;
    return {
      passed,
      challenge: this.challenge,
      observations: observations.metrics,
      failureReason: passed ? undefined : failureReason,
    };
  }

  private measure(): {
    horizontalDrift?: number[];
    areaGrowth?: number[];
    blinkCount?: number;
    maxJitter?: number;
    metrics: Record<string, number>;
  } {
    const frames = this.frames;
    const centres = frames.map((f) => f.box.x + f.box.width / 2);
    const areas = frames.map((f) => f.box.width * f.box.height);
    const luminances = frames.map((f) => f.eyeRegionLuminance);

    let horizontalDrift = 0;
    if (centres.length > 1) {
      const min = Math.min(...centres);
      const max = Math.max(...centres);
      // L4: normalize by the face width, not by the box right-edge coordinate
      // (which made the tolerance position-dependent: bypass on the left,
      // false rejects on the right).
      const faceWidth = frames[0].box.width;
      horizontalDrift = (max - min) / Math.max(1, faceWidth);
    }

    // Directional AND persistent growth: the face must end up LARGER (closer)
    // than it started, measured against its largest observed size — not just
    // the final frame. A user who approaches early then settles back while
    // samples collect has still proven live motion; only a static image (or
    // backing away from the start) fails. Matches turn_* max-drift semantics.
    let areaGrowth = 0;
    if (areas.length > 1) areaGrowth = (Math.max(...areas) - areas[0]) / Math.max(1, areas[0]);

    // Blink detection: a local dip in eye-region luminance relative to the
    // surrounding frames. The window is centred on the candidate frame and
    // excludes the frame itself, so an isolated blink registers as one dip
    // rather than being averaged into its own baseline.
    // L5: edge-triggered — one sustained closure is one event, not one per
    // dark frame. A dip counts only when the previous frame was not a dip.
    let blinkCount = 0;
    let prevWasDip = false;
    if (luminances.length >= 3) {
      for (let i = 1; i < luminances.length - 1; i++) {
        const neighbours: number[] = [];
        for (let k = Math.max(0, i - 3); k <= Math.min(luminances.length - 1, i + 3); k++) {
          if (k !== i) neighbours.push(luminances[k]);
        }
        const baseline = neighbours.reduce((a, b) => a + b, 0) / neighbours.length;
        const isDip = baseline - luminances[i] > baseline * 0.15;
        if (isDip && !prevWasDip) blinkCount++;
        prevWasDip = isDip;
      }
    }

    const jitter = centres.length > 1 ? Math.max(...centres) - Math.min(...centres) : 0;

    return {
      horizontalDrift: [horizontalDrift],
      areaGrowth: [areaGrowth],
      blinkCount,
      maxJitter: jitter,
      metrics: {
        frames: frames.length,
        horizontalDrift: Number(horizontalDrift.toFixed(4)),
        areaGrowth: Number(areaGrowth.toFixed(4)),
        blinkCount,
        jitter: Number(jitter.toFixed(3)),
        meanEyeLuminance: Number((luminances.reduce((a, b) => a + b, 0) / luminances.length).toFixed(2)),
      },
    };
  }
}

/** Mean luminance of the upper third of the face box (the eye band). */
export function eyeRegionLuminance(
  data: Uint8ClampedArray,
  imageWidth: number,
  imageHeight: number,
  box: FaceBox,
): number {
  const x0 = clampIndex(Math.floor(box.x + box.width * 0.15), imageWidth);
  const x1 = clampIndex(Math.ceil(box.x + box.width * 0.85), imageWidth);
  const y0 = clampIndex(Math.floor(box.y + box.height * 0.22), imageHeight);
  const y1 = clampIndex(Math.ceil(box.y + box.height * 0.5), imageHeight);

  let sum = 0;
  let count = 0;
  for (let y = y0; y < y1; y++) {
    for (let x = x0; x < x1; x++) {
      const index = (y * imageWidth + x) * 4;
      if (index + 2 >= data.length) continue;
      sum += 0.299 * data[index] + 0.587 * data[index + 1] + 0.114 * data[index + 2];
      count++;
    }
  }
  return count === 0 ? 0 : sum / count;
}

function clampIndex(value: number, limit: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(limit, value));
}
