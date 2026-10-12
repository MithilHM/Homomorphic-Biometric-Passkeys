/**
 * Face detection on the client.
 *
 * This is a classical, dependency-free detector: skin-tone segmentation in YCbCr
 * followed by connected-component analysis and geometry filtering. It is the
 * *reference* detector, chosen so the whole pipeline runs offline and
 * deterministically in CI.
 *
 * A production deployment swaps in a learned detector behind the same
 * `detectFaces` interface (MediaPipe FaceDetector or an ONNX model); the model
 * version is carried through the whole pipeline, and changing it is a biometric
 * protocol migration (PRD section 39), not a config tweak.
 */

import type { DetectionResult, FaceBox, RgbaImage } from "./types.js";

export const DETECTOR_VERSION = "skin-ycbcr-cc-v1";

/** Convert a frame to a downscaled luma/chroma buffer for analysis. */
function toYCbCr(image: RgbaImage, scale: number) {
  const width = Math.max(1, Math.floor(image.width / scale));
  const height = Math.max(1, Math.floor(image.height / scale));
  const y = new Float32Array(width * height);
  const skin = new Uint8Array(width * height);
  let luminanceSum = 0;

  for (let row = 0; row < height; row++) {
    for (let col = 0; col < width; col++) {
      const sx = Math.min(image.width - 1, col * scale);
      const sy = Math.min(image.height - 1, row * scale);
      const index = (sy * image.width + sx) * 4;
      const r = image.data[index];
      const g = image.data[index + 1];
      const b = image.data[index + 2];

      const yy = 0.299 * r + 0.587 * g + 0.114 * b;
      const cb = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b;
      const cr = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b;

      y[row * width + col] = yy;
      luminanceSum += yy;

      // Classic skin-chrominance bounds (Chai & Ngan), tolerant of lighting.
      const isSkin = cb >= 77 && cb <= 130 && cr >= 133 && cr <= 175 && yy > 45;
      skin[row * width + col] = isSkin ? 1 : 0;
    }
  }

  return { width, height, y, skin, meanLuminance: luminanceSum / (width * height) };
}

/** Connected components over the skin mask, 8-connected, iterative flood fill. */
function components(mask: Uint8Array, width: number, height: number) {
  const labels = new Int32Array(width * height).fill(-1);
  const boxes: Array<{ minX: number; minY: number; maxX: number; maxY: number; area: number }> = [];
  const stack: number[] = [];

  for (let start = 0; start < mask.length; start++) {
    if (mask[start] === 0 || labels[start] !== -1) continue;
    const id = boxes.length;
    const box = { minX: width, minY: height, maxX: -1, maxY: -1, area: 0 };
    stack.push(start);
    labels[start] = id;

    while (stack.length > 0) {
      const pixel = stack.pop()!;
      const px = pixel % width;
      const py = (pixel / width) | 0;
      box.area++;
      if (px < box.minX) box.minX = px;
      if (px > box.maxX) box.maxX = px;
      if (py < box.minY) box.minY = py;
      if (py > box.maxY) box.maxY = py;

      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          if (dx === 0 && dy === 0) continue;
          const nx = px + dx;
          const ny = py + dy;
          if (nx < 0 || ny < 0 || nx >= width || ny >= height) continue;
          const next = ny * width + nx;
          if (mask[next] === 0 || labels[next] !== -1) continue;
          labels[next] = id;
          stack.push(next);
        }
      }
    }
    boxes.push(box);
  }

  return { boxes, labels };
}

export interface DetectOptions {
  /** Downscale factor for the analysis pass. */
  scale?: number;
  /** Minimum face width, as a fraction of the frame. */
  minWidthRatio?: number;
  /** Reject when this many candidate faces are found (multi-face spoofing). */
  maxFaces?: number;
}

export function detectFaces(image: RgbaImage, options: DetectOptions = {}): DetectionResult {
  const scale = options.scale ?? 4;
  const minWidthRatio = options.minWidthRatio ?? 0.16;
  const buffer = toYCbCr(image, scale);
  const { boxes } = components(buffer.skin, buffer.width, buffer.height);

  const minWidth = Math.max(4, Math.floor(buffer.width * minWidthRatio));
  const candidates: FaceBox[] = [];

  for (const box of boxes) {
    const width = box.maxX - box.minX + 1;
    const height = box.maxY - box.minY + 1;
    if (width < minWidth || height < minWidth) continue;
    const ratio = width / height;
    if (ratio < 0.45 || ratio > 1.9) continue;

    // Fill ratio: real faces are compact, hands and background blobs are not.
    const fill = box.area / (width * height);
    if (fill < 0.35) continue;

    const areaRatio = (width * height) / (buffer.width * buffer.height);
    const positionBonus = 1 - Math.min(1, Math.hypot(box.minX / buffer.width - 0.5, box.minY / buffer.height - 0.45));
    const confidence = Math.min(1, 0.35 * fill + 0.4 * Math.min(1, areaRatio * 6) + 0.25 * positionBonus);

    candidates.push({
      x: box.minX * scale,
      y: box.minY * scale,
      width: width * scale,
      height: height * scale,
      confidence,
    });
  }

  candidates.sort((a, b) => b.width * b.height - a.width * a.height);
  const faces = candidates.slice(0, options.maxFaces ?? 4);

  return {
    faces,
    luminance: buffer.meanLuminance,
    // Exposure is judged on the FACE, not the whole frame: a well-lit subject
    // against a dark room is normal, and gating on the global mean would reject
    // every usable capture taken in low-key lighting.
    faceLuminance: faces.length > 0 ? regionLuminance(buffer.y, buffer.width, buffer.height, faces[0], scale) : 0,
    sharpness: laplacianVariance(buffer.y, buffer.width, buffer.height),
  };
}

function regionLuminance(
  y: Float32Array,
  width: number,
  height: number,
  box: FaceBox,
  scale: number,
): number {
  const x0 = Math.max(0, Math.min(width - 1, Math.floor(box.x / scale)));
  const x1 = Math.max(x0 + 1, Math.min(width, Math.ceil((box.x + box.width) / scale)));
  const y0 = Math.max(0, Math.min(height - 1, Math.floor(box.y / scale)));
  const y1 = Math.max(y0 + 1, Math.min(height, Math.ceil((box.y + box.height) / scale)));
  let sum = 0;
  let count = 0;
  for (let py = y0; py < y1; py++) {
    for (let px = x0; px < x1; px++) {
      sum += y[py * width + px];
      count++;
    }
  }
  return count === 0 ? 0 : sum / count;
}

/** Variance of the Laplacian: a cheap, reliable blur detector. */
export function laplacianVariance(y: Float32Array, width: number, height: number): number {
  if (width < 3 || height < 3) return 0;
  let sum = 0;
  let sumSquares = 0;
  let count = 0;
  for (let row = 1; row < height - 1; row++) {
    for (let col = 1; col < width - 1; col++) {
      const i = row * width + col;
      const value = 4 * y[i] - y[i - 1] - y[i + 1] - y[i - width] - y[i + width];
      sum += value;
      sumSquares += value * value;
      count++;
    }
  }
  const mean = sum / count;
  return sumSquares / count - mean * mean;
}

export function isMultipleFaces(detection: DetectionResult): boolean {
  return detection.faces.length > 1;
}
