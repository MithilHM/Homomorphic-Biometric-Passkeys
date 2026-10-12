/**
 * Camera acquisition (PRD section 8.1).
 *
 * HTTPS-only, explicit permission, and the stream is stopped as soon as the
 * session ends. Frames are read into a reusable canvas and handed to the
 * pipeline; they are never written to storage or sent anywhere.
 */

import type { RgbaImage } from "@homobio/biometric-client";

export class CameraController {
  private stream?: MediaStream;
  private canvas?: HTMLCanvasElement;
  private context?: CanvasRenderingContext2D;

  get streaming(): boolean {
    return Boolean(this.stream);
  }

  /** True when the page context can even ask for a camera. */
  static isSupported(): boolean {
    return (
      typeof navigator !== "undefined" &&
      Boolean(navigator.mediaDevices?.getUserMedia) &&
      globalThis.isSecureContext !== false
    );
  }

  async start(): Promise<void> {
    if (this.stream) return;
    if (!CameraController.isSupported()) {
      throw Object.assign(new Error("Camera requires a secure context (https or localhost)"), {
        code: "camera_unavailable",
      });
    }
    this.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } },
      audio: false,
    });

    const video = document.getElementById("camera-preview") as HTMLVideoElement | null;
    if (video) {
      video.srcObject = this.stream;
      await video.play().catch(() => undefined);
    }

    this.canvas = document.createElement("canvas");
    this.canvas.width = 640;
    this.canvas.height = 480;
    this.context = this.canvas.getContext("2d", { willReadFrequently: true }) ?? undefined;
  }

  stop(): void {
    for (const track of this.stream?.getTracks() ?? []) track.stop();
    this.stream = undefined;
    const video = document.getElementById("camera-preview") as HTMLVideoElement | null;
    if (video) video.srcObject = null;
    // Release the backing store so no frame data survives the session.
    this.canvas = undefined;
    this.context = undefined;
  }

  /** Grab one frame. Returns `undefined` when the camera is not running. */
  capture(): RgbaImage | undefined {
    const video = document.getElementById("camera-preview") as HTMLVideoElement | null;
    if (!video || !this.canvas || !this.context || video.readyState < 2) return undefined;

    this.context.drawImage(video, 0, 0, this.canvas.width, this.canvas.height);
    const data = this.context.getImageData(0, 0, this.canvas.width, this.canvas.height);
    return { width: data.width, height: data.height, data: data.data };
  }

  /** Run `handler` for up to `durationMs`, feeding it frames. */
  async sample(handler: (frame: RgbaImage) => boolean, durationMs = 4000): Promise<boolean> {
    const deadline = Date.now() + durationMs;
    while (Date.now() < deadline) {
      const frame = this.capture();
      if (frame && handler(frame)) return true;
      await new Promise((resolve) => setTimeout(resolve, 80));
    }
    return false;
  }
}
