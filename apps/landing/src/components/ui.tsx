import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { clsx } from "clsx";

export const cn = (...parts: Array<string | false | null | undefined>) => clsx(...parts);

/* Button — variant-driven, shadcn-style API */
type ButtonVariant = "primary" | "outline" | "ghost" | "destructive";
type ButtonSize = "sm" | "md" | "lg";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-accent text-on-accent hover:bg-accent-bright",
  outline: "border border-border bg-transparent text-foreground hover:border-accent hover:text-accent-bright",
  ghost: "bg-transparent text-muted-foreground hover:text-foreground",
  destructive: "bg-destructive text-white hover:brightness-110",
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-xs",
  md: "h-10 px-5 text-sm",
  lg: "h-12 px-7 text-base",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export function Button({ variant = "primary", size = "md", className, type = "button", ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        "inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg font-semibold transition-colors duration-200 disabled:cursor-not-allowed disabled:opacity-50",
        buttonVariants[variant],
        buttonSizes[size],
        className,
      )}
      {...rest}
    />
  );
}

/* Badge */
export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "green" | "red" }) {
  return (
    <span
      className={cn(
        // Solid backgrounds: these often sit over the busy hero dither, and
        // anything translucent lets dots collide with glyphs.
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[11px] font-medium tracking-wide",
        tone === "green" && "border-accent/50 bg-[#0c2317] text-accent-bright",
        tone === "red" && "border-destructive/50 bg-[#2a1113] text-destructive",
        tone === "neutral" && "border-border bg-muted text-foreground",
      )}
    >
      {children}
    </span>
  );
}

/* Card — full composition */
export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-2xl border border-border bg-card text-card-foreground", className)}>{children}</div>
  );
}

export function CardHeader({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("flex flex-col gap-1.5 p-6 pb-3", className)}>{children}</div>;
}

export function CardTitle({ children, className }: { children: ReactNode; className?: string }) {
  return <h3 className={cn("text-lg font-semibold leading-snug", className)}>{children}</h3>;
}

export function CardDescription({ children, className }: { children: ReactNode; className?: string }) {
  return <p className={cn("text-sm leading-relaxed text-muted-foreground", className)}>{children}</p>;
}

export function CardContent({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("p-6 pt-3", className)}>{children}</div>;
}

/* Section heading */
export function SectionHeading({
  eyebrow,
  title,
  lede,
}: {
  eyebrow: string;
  title: string;
  lede?: string;
}) {
  return (
    <div className="flex max-w-2xl flex-col gap-3">
      <p className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-accent">{eyebrow}</p>
      <h2 className="text-3xl font-bold leading-tight tracking-tight sm:text-4xl">{title}</h2>
      {lede && <p className="text-base leading-relaxed text-muted-foreground">{lede}</p>}
    </div>
  );
}

/* Scroll reveal wrapper */
export function Reveal({ children, className }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === "undefined") {
      el.classList.add("is-visible");
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            e.target.classList.add("is-visible");
            io.unobserve(e.target);
          }
        }
      },
      { threshold: 0.12 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return (
    <div ref={ref} className={cn("reveal", className)}>
      {children}
    </div>
  );
}

/* Accessible accordion */
export function Accordion({ items }: { items: Array<{ q: string; a: string }> }) {
  const [open, setOpen] = useState<number | null>(0);
  return (
    <div className="flex flex-col gap-3">
      {items.map((item, i) => {
        const expanded = open === i;
        return (
          <div key={item.q} className="overflow-hidden rounded-xl border border-border bg-card">
            <button
              type="button"
              aria-expanded={expanded}
              aria-controls={`faq-panel-${i}`}
              id={`faq-button-${i}`}
              onClick={() => setOpen(expanded ? null : i)}
              className="flex w-full cursor-pointer items-center justify-between gap-4 p-5 text-left font-medium transition-colors hover:text-accent-bright"
            >
              <span>{item.q}</span>
              <span
                aria-hidden
                className={cn(
                  "font-mono text-accent transition-transform duration-200",
                  expanded ? "rotate-45" : "rotate-0",
                )}
              >
                +
              </span>
            </button>
            {expanded && (
              <p id={`faq-panel-${i}`} role="region" aria-labelledby={`faq-button-${i}`} className="px-5 pb-5 text-sm leading-relaxed text-muted-foreground">
                {item.a}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* Copy-to-clipboard button */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      aria-label={`${label} to clipboard`}
      onClick={() => {
        const finish = () => {
          setDone(true);
          window.setTimeout(() => setDone(false), 1600);
        };
        if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(finish).catch(finish);
        else finish();
      }}
      className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 font-mono text-[11px] text-muted-foreground transition-colors hover:border-accent hover:text-accent-bright"
    >
      {done ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
      {done ? "Copied" : label}
    </button>
  );
}

/* Stat */
export function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-2xl font-semibold text-foreground sm:text-3xl">{value}</span>
      <span className="text-xs uppercase tracking-[0.15em] text-muted-foreground">{label}</span>
    </div>
  );
}
