import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { cn } from "./ui";

/* ---------------------------------------------------------------------------
 * Magic-UI idioms, ported dependency-free (no motion lib in this repo).
 * - BorderBeam: traveling light on the border (conic-gradient rotor)
 * - ShinyText: animated shine sweep over muted text
 * - AuroraText: slow-shifting gradient headline
 * - ShimmerButton: conic spark + shine sweep primary CTA
 * - NumberTicker: rAF count-up, reduced-motion aware
 * ------------------------------------------------------------------------- */

export function BorderBeam({
  size = 120,
  duration = 6,
  colorFrom = "#4ade80",
  colorTo = "#836ef9",
  borderWidth = 1.5,
  className,
  style,
}: {
  size?: number;
  duration?: number;
  colorFrom?: string;
  colorTo?: string;
  borderWidth?: number;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      aria-hidden
      className={cn("beam-shell", className)}
      style={
        {
          "--beam-size": `${size}px`,
          "--beam-duration": `${duration}s`,
          "--beam-from": colorFrom,
          "--beam-to": colorTo,
          "--beam-width": `${borderWidth}px`,
          ...style,
        } as CSSProperties
      }
    >
      <div className="beam-rotor" />
    </div>
  );
}

export function ShinyText({
  children,
  className,
  shimmerWidth = 120,
}: {
  children: ReactNode;
  className?: string;
  shimmerWidth?: number;
}) {
  return (
    <span
      className={cn("shiny-text", className)}
      style={{ "--shiny-width": `${shimmerWidth}px` } as CSSProperties}
    >
      {children}
    </span>
  );
}

export function AuroraText({
  children,
  className,
  colors = ["#4ade80", "#38bdf8", "#836ef9", "#4ade80"],
  speed = 1,
}: {
  children: ReactNode;
  className?: string;
  colors?: string[];
  speed?: number;
}) {
  const gradient = `linear-gradient(135deg, ${colors.join(", ")}, ${colors[0]})`;
  return (
    <span className={cn("aurora-wrap", className)}>
      <span className="sr-only">{children}</span>
      <span
        aria-hidden
        className="aurora-text"
        style={{ backgroundImage: gradient, animationDuration: `${10 / speed}s` }}
      >
        {children}
      </span>
    </span>
  );
}

export function ShimmerButton({
  children,
  className,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <button type="button" onClick={onClick} className={cn("shimmer-btn", className)}>
      <span className="shimmer-btn-spark" aria-hidden />
      <span className="shimmer-btn-label">{children}</span>
    </button>
  );
}

export function NumberTicker({
  value,
  className,
  duration = 1200,
}: {
  value: number;
  className?: string;
  duration?: number;
}) {
  const [display, setDisplay] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === "undefined") {
      setDisplay(value);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting && !started.current) {
          started.current = true;
          if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
            setDisplay(value);
            return;
          }
          const t0 = performance.now();
          const tick = (t: number) => {
            const p = Math.min(1, (t - t0) / duration);
            const eased = 1 - Math.pow(1 - p, 3);
            setDisplay(Math.round(eased * value));
            if (p < 1) requestAnimationFrame(tick);
          };
          requestAnimationFrame(tick);
          io.disconnect();
        }
      },
      { threshold: 0.4 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [value, duration]);

  return (
    <span ref={ref} className={className}>
      {display}
    </span>
  );
}
