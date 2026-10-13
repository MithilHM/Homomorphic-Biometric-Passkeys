import { useEffect, useRef } from "react";

export type DitherPattern = "floyd" | "bayer" | "none";

export interface DitherVeilProps {
  /** Image URL. Must allow CORS for pixel reads, otherwise a procedural fallback renders. */
  src: string;
  /** Dither algorithm. `floyd` = Floyd–Steinberg diffusion, `bayer` = ordered 4x4. */
  pattern?: DitherPattern;
  /** Pixel cell size in CSS px. Clamped to [1, 32]. */
  pixelSize?: number;
  /** Color of dark cells. */
  inkColor?: string;
  /** Color of light cells / background. */
  paperColor?: string;
  /** Reveal radius in CSS px around the pointer. */
  revealRadius?: number;
  /** Edge softness of the reveal, 0 (hard) to 1 (soft). */
  softness?: number;
  /** Seconds the reveal trail lingers. 0 disables the trail. */
  linger?: number;
  className?: string;
  alt?: string;
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

const BAYER_4X4 = [
  [0, 8, 2, 10],
  [12, 4, 14, 6],
  [3, 11, 1, 9],
  [15, 7, 13, 5],
];

function hexToRgb(hex: string): [number, number, number] {
  const clean = hex.replace("#", "");
  const full = clean.length === 3 ? clean.split("").map((c) => c + c).join("") : clean;
  const n = Number.parseInt(full.slice(0, 6), 16);
  if (Number.isNaN(n)) return [0, 0, 0];
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/**
 * DitherVeil — a React Bits style image veil.
 *
 * The source image is pixelated and reduced to two tones with error-diffusion
 * (Floyd–Steinberg) or ordered (Bayer) dithering. Moving the pointer reveals
 * the true image through a soft mask that lingers and fades — a reveal, not a
 * filter. All heavy work (load, diffuse) happens once; per-frame cost is a
 * few drawImage calls, paused offscreen or when the tab hides.
 */
export default function DitherVeil({
  src,
  pattern = "floyd",
  pixelSize = 2,
  inkColor = "#e9e4d6",
  paperColor = "#14101a",
  revealRadius = 200,
  softness = 0.6,
  linger = 1,
  className = "",
  alt = "",
}: DitherVeilProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef({
    pointer: null as { x: number; y: number; inside: boolean } | null,
    dither: null as HTMLCanvasElement | null,
    full: null as HTMLCanvasElement | null,
    mask: null as HTMLCanvasElement | null,
    cut: null as HTMLCanvasElement | null,
    w: 0,
    h: 0,
    scale: 1,
  });

  const optsRef = useRef({ pattern, pixelSize, inkColor, paperColor, revealRadius, softness, linger });
  optsRef.current = { pattern, pixelSize, inkColor, paperColor, revealRadius, softness, linger };

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;
    const ctx = canvas.getContext("2d", { alpha: false });
    if (!ctx) return;
    const st = stateRef.current;
    let raf = 0;
    let running = false;
    let last = performance.now();
    let disposed = false;
    const reducedMotion =
      typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const build = (img: HTMLImageElement | null) => {
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      // Cap render pixels for cheap per-frame compositing.
      const maxDim = 1400;
      const fit = Math.min(1, maxDim / Math.max(1, rect.width * dpr), maxDim / Math.max(1, rect.height * dpr));
      const w = Math.max(2, Math.round(rect.width * dpr * fit));
      const h = Math.max(2, Math.round(rect.height * dpr * fit));
      const scale = w / Math.max(1, rect.width);
      st.w = w;
      st.h = h;
      st.scale = scale;
      canvas.width = w;
      canvas.height = h;

      // Full-res layer, cover fit.
      const full = document.createElement("canvas");
      full.width = w;
      full.height = h;
      const fctx = full.getContext("2d");
      if (fctx) {
        if (img) {
          const s = Math.max(w / img.naturalWidth, h / img.naturalHeight);
          const dw = img.naturalWidth * s;
          const dh = img.naturalHeight * s;
          fctx.drawImage(img, (w - dw) / 2, (h - dh) / 2, dw, dh);
        } else {
          // Procedural fallback: diagonal duotone gradient, never a broken tile.
          const o = optsRef.current;
          const g = fctx.createLinearGradient(0, 0, w, h);
          g.addColorStop(0, o.paperColor);
          g.addColorStop(0.5, o.inkColor);
          g.addColorStop(1, o.paperColor);
          fctx.fillStyle = g;
          fctx.fillRect(0, 0, w, h);
        }
      }
      st.full = full;

      // Low-res luminance grid.
      const o = optsRef.current;
      const px = clamp(Math.round(o.pixelSize), 1, 32);
      const cols = Math.max(1, Math.ceil(w / px));
      const rows = Math.max(1, Math.ceil(h / px));
      const tiny = document.createElement("canvas");
      tiny.width = cols;
      tiny.height = rows;
      const tctx = tiny.getContext("2d", { willReadFrequently: true });
      let lum = new Float32Array(cols * rows).fill(0.5);
      if (tctx) {
        tctx.drawImage(full, 0, 0, cols, rows);
        try {
          const data = tctx.getImageData(0, 0, cols, rows).data;
          lum = new Float32Array(cols * rows);
          for (let i = 0; i < cols * rows; i++) {
            lum[i] = (0.299 * data[i * 4] + 0.587 * data[i * 4 + 1] + 0.114 * data[i * 4 + 2]) / 255;
          }
        } catch {
          // Tainted canvas (no CORS): fall back to a synthetic wave field.
          for (let y = 0; y < rows; y++) {
            for (let x = 0; x < cols; x++) {
              lum[y * cols + x] = 0.5 + 0.42 * Math.sin((x / cols) * Math.PI * 6) * Math.cos((y / rows) * Math.PI * 4);
            }
          }
        }
      }

      // Diffuse to ink / paper.
      const ink = new Uint8Array(cols * rows);
      if (o.pattern === "floyd") {
        const buf = Float32Array.from(lum);
        for (let y = 0; y < rows; y++) {
          for (let x = 0; x < cols; x++) {
            const i = y * cols + x;
            const old = buf[i] ?? 0.5;
            const next = old < 0.5 ? 0 : 1;
            ink[i] = next;
            const err = old - next;
            if (x + 1 < cols) buf[i + 1] = (buf[i + 1] ?? 0) + (err * 7) / 16;
            if (y + 1 < rows) {
              if (x > 0) buf[i + cols - 1] = (buf[i + cols - 1] ?? 0) + (err * 3) / 16;
              buf[i + cols] = (buf[i + cols] ?? 0) + (err * 5) / 16;
              if (x + 1 < cols) buf[i + cols + 1] = (buf[i + cols + 1] ?? 0) + err / 16;
            }
          }
        }
      } else if (o.pattern === "bayer") {
        for (let y = 0; y < rows; y++) {
          for (let x = 0; x < cols; x++) {
            const t = ((BAYER_4X4[y % 4]?.[x % 4] ?? 0) + 0.5) / 16;
            ink[y * cols + x] = (lum[y * cols + x] ?? 0.5) < t ? 0 : 1;
          }
        }
      } else {
        for (let i = 0; i < cols * rows; i++) ink[i] = (lum[i] ?? 0.5) < 0.5 ? 0 : 1;
      }

      const dither = document.createElement("canvas");
      dither.width = w;
      dither.height = h;
      const dctx = dither.getContext("2d");
      if (dctx) {
        dctx.imageSmoothingEnabled = false;
        dctx.fillStyle = o.paperColor;
        dctx.fillRect(0, 0, w, h);
        dctx.fillStyle = o.inkColor;
        const cw = w / cols;
        const ch = h / rows;
        for (let y = 0; y < rows; y++) {
          for (let x = 0; x < cols; x++) {
            if (ink[y * cols + x] === 1) dctx.fillRect(Math.floor(x * cw), Math.floor(y * ch), Math.ceil(cw), Math.ceil(ch));
          }
        }
      }
      st.dither = dither;

      const mask = document.createElement("canvas");
      mask.width = w;
      mask.height = h;
      st.mask = mask;

      const cut = document.createElement("canvas");
      cut.width = w;
      cut.height = h;
      st.cut = cut;
    };

    const stamp = (mctx: CanvasRenderingContext2D) => {
      const o = optsRef.current;
      const p = st.pointer;
      if (!p || !p.inside) return;
      const r = clamp(o.revealRadius, 8, 1200) * st.scale;
      const x = p.x * st.scale;
      const y = p.y * st.scale;
      const soft = clamp(o.softness, 0, 1);
      const g = mctx.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0, "rgba(255,255,255,0.95)");
      g.addColorStop(clamp(1 - soft, 0.02, 0.98), "rgba(255,255,255,0.85)");
      g.addColorStop(1, "rgba(255,255,255,0)");
      mctx.fillStyle = g;
      mctx.beginPath();
      mctx.arc(x, y, r, 0, Math.PI * 2);
      mctx.fill();
    };

    const frame = (now: number) => {
      if (disposed || !running) return;
      raf = requestAnimationFrame(frame);
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      const o = optsRef.current;
      const { dither, full, mask, cut } = st;
      if (!dither || !full || !mask || !cut) return;
      const mctx = mask.getContext("2d");
      if (!mctx) return;

      // Fade the trail. linger<=0 (or reduced motion) clears every frame.
      const linger = reducedMotion ? 0 : clamp(o.linger, 0, 10);
      if (linger <= 0) {
        mctx.clearRect(0, 0, st.w, st.h);
      } else {
        mctx.globalCompositeOperation = "destination-out";
        mctx.fillStyle = `rgba(0,0,0,${clamp(dt / linger, 0, 1)})`;
        mctx.fillRect(0, 0, st.w, st.h);
        mctx.globalCompositeOperation = "source-over";
      }
      stamp(mctx);

      ctx.drawImage(dither, 0, 0);
      // Reveal = full image clipped by the accumulated mask (scratch reused).
      const cctx = cut.getContext("2d");
      if (!cctx) return;
      cctx.globalCompositeOperation = "source-over";
      cctx.clearRect(0, 0, st.w, st.h);
      cctx.drawImage(full, 0, 0);
      cctx.globalCompositeOperation = "destination-in";
      cctx.drawImage(mask, 0, 0);
      ctx.drawImage(cut, 0, 0);
    };

    const start = () => {
      if (!running && !disposed) {
        running = true;
        last = performance.now();
        raf = requestAnimationFrame(frame);
      }
    };
    const stop = () => {
      running = false;
      cancelAnimationFrame(raf);
    };

    const onMove = (e: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      st.pointer = { x: e.clientX - rect.left, y: e.clientY - rect.top, inside: true };
    };
    const onLeave = () => {
      st.pointer = null;
    };

    const io = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting) start();
      else stop();
    });
    io.observe(container);
    const onVis = () => {
      if (document.hidden) stop();
      else start();
    };
    document.addEventListener("visibilitychange", onVis);
    container.addEventListener("pointermove", onMove);
    container.addEventListener("pointerdown", onMove);
    container.addEventListener("pointerleave", onLeave);

    let ro: ResizeObserver | null = null;
    const img = new Image();
    img.crossOrigin = "anonymous";
    img.onload = () => {
      if (disposed) return;
      build(img);
      // Rebuild on resize (debounced by the observer itself).
      ro = new ResizeObserver(() => build(img));
      ro.observe(container);
    };
    img.onerror = () => {
      if (disposed) return;
      build(null);
      ro = new ResizeObserver(() => build(null));
      ro.observe(container);
    };
    // Build synchronously first so there is never a blank frame.
    build(null);
    img.src = src;

    return () => {
      disposed = true;
      stop();
      io.disconnect();
      ro?.disconnect();
      document.removeEventListener("visibilitychange", onVis);
      container.removeEventListener("pointermove", onMove);
      container.removeEventListener("pointerdown", onMove);
      container.removeEventListener("pointerleave", onLeave);
    };
    // Rebuild the diffused layers only when the source or look changes;
    // pointer motion never rebuilds (it only stamps the mask).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [src, pattern, pixelSize, inkColor, paperColor]);

  return (
    <div ref={containerRef} className={`relative overflow-hidden ${className}`} role="img" aria-label={alt}>
      <canvas ref={canvasRef} className="absolute inset-0 h-full w-full touch-none" />
    </div>
  );
}
