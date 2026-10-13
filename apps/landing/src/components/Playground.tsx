import { useState } from "react";
import DitherVeil, { type DitherPattern } from "./DitherVeil";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, cn } from "./ui";

const PATTERNS: Array<{ id: DitherPattern; label: string }> = [
  { id: "floyd", label: "Floyd–Steinberg" },
  { id: "bayer", label: "Bayer 4×4" },
  { id: "none", label: "Threshold" },
];

const DUOTONES: Array<{ label: string; ink: string; paper: string }> = [
  { label: "Bone on abyss", ink: "#e9e4d6", paper: "#14101a" },
  { label: "Terminal", ink: "#4ade80", paper: "#07130c" },
  { label: "Blueprint", ink: "#bfdbfe", paper: "#0c1a3a" },
  { label: "Newsprint", ink: "#120f17", paper: "#f4f1ea" },
];

function Slider({
  label,
  value,
  min,
  max,
  step,
  format,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  format: (v: number) => string;
  onChange: (v: number) => void;
}) {
  return (
    <label className="flex flex-col gap-2">
      <span className="flex items-center justify-between text-xs text-muted-foreground">
        <span className="font-medium uppercase tracking-[0.12em]">{label}</span>
        <span className="font-mono text-foreground">{format(value)}</span>
      </span>
      <input
        type="range"
        className="veil-range w-full"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-label={label}
      />
    </label>
  );
}

export default function Playground({ src }: { src: string }) {
  const [pattern, setPattern] = useState<DitherPattern>("floyd");
  const [pixelSize, setPixelSize] = useState(3);
  const [duo, setDuo] = useState(0);
  const [radius, setRadius] = useState(170);
  const [softness, setSoftness] = useState(0.65);
  const [linger, setLinger] = useState(1.2);
  const active = DUOTONES[duo] ?? DUOTONES[0]!;

  return (
    <div className="grid gap-6 lg:grid-cols-[1fr_320px]">
      <div className="overflow-hidden rounded-2xl border border-border">
        <DitherVeil
          src={src}
          pattern={pattern}
          pixelSize={pixelSize}
          inkColor={active.ink}
          paperColor={active.paper}
          revealRadius={radius}
          softness={softness}
          linger={linger}
          alt="Interactive dither veil — drag to reveal the underlying image"
          className="h-[420px] sm:h-[520px]"
        />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Tune the veil</CardTitle>
          <CardDescription>Every control re-diffuses live. Same props as the hero.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-5">
            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Diffusion</span>
              <div role="tablist" aria-label="Dither pattern" className="grid grid-cols-3 gap-1 rounded-lg border border-border bg-muted/50 p-1">
                {PATTERNS.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    role="tab"
                    aria-selected={pattern === p.id}
                    onClick={() => setPattern(p.id)}
                    className={cn(
                      "cursor-pointer rounded-md px-2 py-2 text-xs font-medium transition-colors",
                      pattern === p.id ? "bg-accent text-on-accent" : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Duotone</span>
              <div className="grid grid-cols-2 gap-2">
                {DUOTONES.map((d, i) => (
                  <button
                    key={d.label}
                    type="button"
                    aria-pressed={duo === i}
                    onClick={() => setDuo(i)}
                    className={cn(
                      "flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-2 text-left text-xs transition-colors",
                      duo === i ? "border-accent" : "border-border hover:border-muted-foreground",
                    )}
                  >
                    <span
                      aria-hidden
                      className="size-5 shrink-0 rounded-full border border-border"
                      style={{ background: `linear-gradient(135deg, ${d.ink} 50%, ${d.paper} 50%)` }}
                    />
                    {d.label}
                  </button>
                ))}
              </div>
            </div>
            <Slider label="Pixel size" value={pixelSize} min={1} max={12} step={1} format={(v) => `${v}px`} onChange={setPixelSize} />
            <Slider label="Reveal radius" value={radius} min={40} max={420} step={10} format={(v) => `${v}px`} onChange={setRadius} />
            <Slider label="Softness" value={softness} min={0} max={1} step={0.05} format={(v) => v.toFixed(2)} onChange={setSoftness} />
            <Slider label="Linger" value={linger} min={0} max={5} step={0.2} format={(v) => `${v.toFixed(1)}s`} onChange={setLinger} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
