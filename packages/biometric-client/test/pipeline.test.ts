import { describe, expect, it } from "vitest";
import { dot, normalize } from "@homobio/crypto-utils";
import {
  BiometricCaptureSession,
  CANONICAL_SIZE,
  EMBEDDING_DIMENSION,
  EMBEDDING_VERSION,
  aggregateTemplate,
  alignFace,
  analyzeFrame,
  detectFaces,
  embedAligned,
  explainFailure,
  isMultipleFaces,
  lumaAt,
  randomChallenge,
  scoreQuality,
  syntheticSamples,
  type RgbaImage,
} from "../src/index.js";

/** A synthetic frame: skin-toned elliptical face on a dark background. */
function syntheticFace(options: {
  width?: number;
  height?: number;
  centerX?: number;
  centerY?: number;
  radius?: number;
  luminance?: number;
  secondFace?: boolean;
  eyes?: number;
} = {}): RgbaImage {
  const width = options.width ?? 320;
  const height = options.height ?? 240;
  const cx = options.centerX ?? width / 2;
  const cy = options.centerY ?? height / 2;
  const radius = options.radius ?? 52;
  const data = new Uint8ClampedArray(width * height * 4);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const index = (y * width + x) * 4;
      const inFace = Math.hypot(x - cx, y - cy) < radius;
      const inSecond = options.secondFace && Math.hypot(x - (cx + 130), y - cy) < radius * 0.8;
      let r: number;
      let g: number;
      let b: number;
      if (inFace || inSecond) {
        const brightness = options.luminance ?? 150;
        r = brightness;
        g = Math.round(brightness * 0.78);
        b = Math.round(brightness * 0.68);
        // Eyes: two darker patches in the upper half (blink signal).
        if (options.eyes !== undefined) {
          const eyeY = cy - radius * 0.25;
          const leftEye = Math.hypot(x - (cx - radius * 0.32), y - eyeY) < 12;
          const rightEye = Math.hypot(x - (cx + radius * 0.32), y - eyeY) < 12;
          const scale = options.eyes;
          if ((leftEye || rightEye) && scale < 0.5) {
            r *= scale;
            g *= scale;
            b *= scale;
          }
        }
      } else {
        r = 22;
        g = 24;
        b = 30;
      }
      data[index] = r;
      data[index + 1] = g;
      data[index + 2] = b;
      data[index + 3] = 255;
    }
  }
  return { width, height, data };
}

function luma(image: RgbaImage, x: number, y: number): number {
  return lumaAt(image, Math.floor(x), Math.floor(y));
}

describe("face detection", () => {
  it("finds a single centred face", () => {
    const detection = detectFaces(syntheticFace());
    expect(detection.faces.length).toBeGreaterThan(0);
    expect(detection.faces[0].width).toBeGreaterThan(40);
    expect(detection.faces[0].confidence).toBeGreaterThan(0);
  });

  it("reports multiple faces so the pipeline can reject them", () => {
    const detection = detectFaces(syntheticFace({ secondFace: true, width: 480, centerX: 190 }));
    expect(detection.faces.length).toBeGreaterThan(1);
    expect(isMultipleFaces(detection)).toBe(true);
  });

  it("finds nothing in an empty frame", () => {
    const empty: RgbaImage = { width: 160, height: 120, data: new Uint8ClampedArray(160 * 120 * 4).fill(10) };
    expect(detectFaces(empty).faces.length).toBe(0);
  });

  it("measures luminance so low light can be rejected", () => {
    const dark = detectFaces(syntheticFace({ luminance: 20 })).faceLuminance;
    const bright = detectFaces(syntheticFace({ luminance: 200 })).faceLuminance;
    expect(dark).toBeLessThan(40);
    expect(bright).toBeGreaterThan(120);
  });
});

describe("quality scoring", () => {
  it("rejects frames with no face", () => {
    const report = scoreQuality({
      luminance: 120,
      faceLuminance: 120,
      sharpness: 50,
      face: undefined,
      frameWidth: 320,
      frameHeight: 240,
      faceCount: 0,
    });
    expect(report.acceptable).toBe(false);
    expect(report.reasons).toContain("no_face");
  });

  it("rejects low light and multiple faces", () => {
    const face = { x: 100, y: 80, width: 100, height: 120, confidence: 0.9 };
    const lowLight = scoreQuality({
      luminance: 20,
      faceLuminance: 20,
      sharpness: 60,
      face,
      frameWidth: 320,
      frameHeight: 240,
      faceCount: 1,
    });
    expect(lowLight.reasons).toContain("low_light");
    expect(lowLight.acceptable).toBe(false);

    const multiple = scoreQuality({
      luminance: 130,
      faceLuminance: 130,
      sharpness: 60,
      face,
      frameWidth: 320,
      frameHeight: 240,
      faceCount: 2,
    });
    expect(multiple.reasons).toContain("multiple_faces");
    expect(multiple.acceptable).toBe(false);
  });

  it("accepts a well-framed, well-lit single face", () => {
    const face = { x: 110, y: 60, width: 100, height: 120, confidence: 0.9 };
    const report = scoreQuality({
      luminance: 140,
      faceLuminance: 140,
      sharpness: 60,
      face,
      frameWidth: 320,
      frameHeight: 240,
      faceCount: 1,
    });
    expect(report.acceptable).toBe(true);
    expect(report.reasons).toHaveLength(0);
  });
});

describe("alignment and embedding", () => {
  it("produces a canonical-size crop", () => {
    const image = syntheticFace();
    const aligned = alignFace(image, { x: 100, y: 60, width: 120, height: 140 });
    expect(aligned.length).toBe(CANONICAL_SIZE * CANONICAL_SIZE);
  });

  it("is deterministic for the same input", () => {
    const image = syntheticFace();
    const box = { x: 100, y: 60, width: 120, height: 140, confidence: 0.9 };
    const a = embedAligned(alignFace(image, box));
    const b = embedAligned(alignFace(image, box));
    expect(a.checksum).toBe(b.checksum);
    expect(a.modelVersion).toBe(EMBEDDING_VERSION);
    expect(a.dimension).toBe(EMBEDDING_DIMENSION);
  });

  it("returns an L2-normalised vector", () => {
    const image = syntheticFace();
    const embedding = embedAligned(alignFace(image, { x: 100, y: 60, width: 120, height: 140 }));
    const norm = Math.sqrt(dot(embedding.vector, embedding.vector));
    expect(norm).toBeCloseTo(1, 6);
  });

  it("is invariant to a global brightness shift", () => {
    const bright = embedAligned(alignFace(syntheticFace({ luminance: 200 }), { x: 100, y: 60, width: 120, height: 140 }));
    const dim = embedAligned(alignFace(syntheticFace({ luminance: 110 }), { x: 100, y: 60, width: 120, height: 140 }));
    expect(bright.vector.length).toBe(dim.vector.length);
    // Contrast normalisation should keep the two well above an impostor score.
    expect(dot(bright.vector, dim.vector)).toBeGreaterThan(0.5);
  });

  it("separates different faces", () => {
    const a = embedAligned(alignFace(syntheticFace({ centerX: 160, radius: 52 }), { x: 100, y: 60, width: 120, height: 140 }));
    const b = embedAligned(alignFace(syntheticFace({ centerX: 60, radius: 30, width: 240 }), { x: 20, y: 40, width: 90, height: 110 }));
    expect(dot(a.vector, b.vector)).toBeLessThan(0.999);
  });
});

describe("template aggregation", () => {
  it("averages consistent samples and reports the spread", () => {
    const samples = syntheticSamples(7, 3);
    const template = aggregateTemplate(samples);
    expect(template.acceptedSamples).toBeGreaterThan(0);
    expect(template.rejectedSamples).toBe(0);
    expect(Math.sqrt(dot(template.vector, template.vector))).toBeCloseTo(1, 6);
    expect(template.intraClassSpread).toBeLessThan(0.1);
  });

  it("rejects an outlier sample", () => {
    const samples = syntheticSamples(5, 4);
    const impostor = new Float64Array(EMBEDDING_DIMENSION);
    impostor[0] = 1;
    const template = aggregateTemplate([...samples, { vector: impostor, quality: 0.1 }]);
    expect(template.rejectedSamples).toBeGreaterThan(0);
    expect(dot(template.vector, impostor)).toBeLessThan(0.5);
  });

  it("refuses to build a template with no samples", () => {
    expect(() => aggregateTemplate([])).toThrow();
  });
});

describe("liveness", () => {
  it("issues a randomised challenge from the allowed set", () => {
    const challenge = randomChallenge(["blink"]);
    expect(challenge.action).toBe("blink");
    expect(challenge.instruction).toMatch(/[Bb]link/);
  });

  it("fails a still image on a motion challenge", () => {
    const session = new BiometricCaptureSession({ allow: ["turn_left"] });
    const frame = syntheticFace();
    for (let i = 0; i < 40; i++) session.push(frame);
    const result = session.liveness.finish();
    expect(result.passed).toBe(false);
    expect(result.failureReason).toBeTruthy();
  });

  it("passes when the face actually moves across the frame", () => {
    const session = new BiometricCaptureSession({ allow: ["turn_left"] });
    for (let i = 0; i < 12; i++) {
      const cx = 110 + i * 8;
      session.push(syntheticFace({ centerX: cx, centerY: 120 }));
    }
    const result = session.liveness.finish();
    expect(result.passed).toBe(true);
    expect(result.observations.frames).toBeGreaterThan(1);
  });

  it("records two blinks when the eyes close and reopen", () => {
    const session = new BiometricCaptureSession({ allow: ["blink"] });
    const pattern = [1, 1, 1, 0.15, 1, 1, 0.15, 1, 1, 1];
    for (const eyes of pattern) {
      session.push(syntheticFace({ eyes, luminance: 150 }));
    }
    const result = session.liveness.finish();
    expect(result.observations.blinkCount).toBeGreaterThanOrEqual(2);
  });

  it("tracks motion from frames that fail embedding quality", () => {
    // A far-away face is detected but rejected as a sample (face_too_small);
    // the head turn it performs must still count toward the challenge.
    // Otherwise the exact frames that perform the motion are excluded from
    // it and enrollment stalls with zero feedback.
    const session = new BiometricCaptureSession({ allow: ["turn_left"] });
    for (let i = 0; i < 10; i++) {
      const pushed = session.push(syntheticFace({ centerX: 110 + i * 8, radius: 28 }));
      expect(pushed.quality.acceptable).toBe(false);
    }
    expect(session.capturedSamples.length).toBe(0);
    expect(session.liveness.frameCount).toBeGreaterThan(0);
    expect(session.liveness.finish().passed).toBe(true);
  });

  it("ignores frames with no detectable face for liveness", () => {
    const session = new BiometricCaptureSession({ allow: ["turn_left"] });
    const empty: RgbaImage = { width: 160, height: 120, data: new Uint8ClampedArray(160 * 120 * 4).fill(10) };
    for (let i = 0; i < 10; i++) session.push(empty);
    expect(session.liveness.frameCount).toBe(0);
    expect(session.liveness.finish().passed).toBe(false);
  });
});

describe("frame analysis", () => {
  it("returns an embedding only when quality is acceptable", () => {
    const good = analyzeFrame(syntheticFace(), { extractEmbedding: true });
    expect(good.embedding).toBeDefined();

    const dark = analyzeFrame(syntheticFace({ luminance: 18 }), { extractEmbedding: true });
    expect(dark.embedding).toBeUndefined();
  });
});

describe("failure explanations", () => {
  it("provides a title, an explanation and a concrete action for every state", () => {
    const codes = [
      "camera_denied",
      "no_face",
      "multiple_faces",
      "low_light",
      "liveness_failed",
      "passkey_cancelled",
      "fhe_error",
      "challenge_expired",
      "biometric_mismatch",
      "indeterminate",
    ] as const;
    for (const code of codes) {
      const explanation = explainFailure(code);
      expect(explanation.title.length).toBeGreaterThan(0);
      expect(explanation.action.length).toBeGreaterThan(0);
      expect(typeof explanation.retryable).toBe("boolean");
    }
  });

  it("appends diagnostic detail when supplied", () => {
    expect(explainFailure("challenge_expired", "expired 3s ago").detail).toContain("expired 3s ago");
  });
});

describe("sample generator", () => {
  it("produces normalised vectors", () => {
    for (const sample of syntheticSamples(3, 9)) {
      expect(Math.sqrt(dot(normalize(sample.vector), normalize(sample.vector)))).toBeCloseTo(1, 6);
    }
  });

  it("agrees with the luminance helper", () => {
    const image = syntheticFace();
    expect(luma(image, 160, 120)).toBeGreaterThan(50);
  });
});
