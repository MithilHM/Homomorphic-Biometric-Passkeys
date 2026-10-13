import { useEffect, useState } from "react";
import { Activity, PlugZap, TriangleAlert } from "lucide-react";
import { Badge, Card, CardContent, CardDescription, CardHeader, CardTitle, CopyButton } from "./ui";

// Same-origin by default: in dev the Vite proxy forwards /v1 to the gateway,
// so there is no cross-origin request at all. Set VITE_GATEWAY_URL only when
// the site is hosted apart from the gateway (that origin must then be added
// to the gateway's ALLOWED_ORIGINS).
const GATEWAY = (import.meta.env.VITE_GATEWAY_URL as string | undefined) ?? "";
const url = (p: string) => `${GATEWAY}${p}`;

interface Health {
  committeeAddress?: string;
  [k: string]: unknown;
}

interface GatewayConfig {
  chainId?: number;
  entryPoint?: string;
  fhe?: { engine?: string; ringDimension?: number; scaleBits?: number; embeddingDimension?: number };
  [k: string]: unknown;
}

type Status = { state: "loading" } | { state: "live"; health: Health; config: GatewayConfig } | { state: "offline"; message: string };

async function fetchJson<T>(path: string, timeoutMs: number): Promise<T> {
  const ctrl = new AbortController();
  const timer = window.setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url(path), { signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as T;
  } finally {
    window.clearTimeout(timer);
  }
}

const COMMANDS = [
  { label: "Install", cmd: "npm install" },
  { label: "Start", cmd: "npm run dev" },
  { label: "Try a demo", cmd: "npm run demo" },
];

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border/60 py-2.5 last:border-0">
      <span className="shrink-0 text-xs uppercase tracking-[0.12em] text-muted-foreground">{k}</span>
      <span className="break-all text-right font-mono text-xs text-foreground">{v}</span>
    </div>
  );
}

export default function StackStatus() {
  const [status, setStatus] = useState<Status>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    // Independent probes in parallel; either may fail without hiding the other.
    Promise.allSettled([fetchJson<Health>("/v1/health", 8000), fetchJson<GatewayConfig>("/v1/config", 8000)]).then(
      ([health, config]) => {
        if (cancelled) return;
        if (health.status === "fulfilled" && config.status === "fulfilled") {
          setStatus({ state: "live", health: health.value, config: config.value });
        } else {
          setStatus({
            state: "offline",
            message: "Wallet service is not running here yet. Start it on your machine with npm run dev, then reload.",
          });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <CardTitle>Wallet service</CardTitle>
            {status.state === "live" ? (
              <Badge tone="green">
                <span className="size-1.5 rounded-full bg-accent animate-pulse-dot" aria-hidden /> Running
              </Badge>
            ) : status.state === "loading" ? (
              <Badge>Checking…</Badge>
            ) : (
              <Badge tone="red">
                <TriangleAlert size={12} aria-hidden /> Not running
              </Badge>
            )}
          </div>
          <CardDescription>
            Checked live from your browser just now. Your face data is never part of this check.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {status.state === "loading" && (
            <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
              <Activity size={15} aria-hidden className="animate-pulse" /> Checking the wallet service…
            </p>
          )}
          {status.state === "offline" && (
            <p className="flex items-start gap-2 py-6 text-sm leading-relaxed text-muted-foreground">
              <PlugZap size={15} aria-hidden className="mt-0.5 shrink-0" /> {status.message}
            </p>
          )}
          {status.state === "live" && (
            <div>
              <Row k="Face check" v="Private — encrypted before it leaves your device" />
              <Row k="Unlock key" v="Your device passkey — only you hold it" />
              <Row k="Safety delay" v="48 hours on account recovery" />
              <Row
                k="Security committee"
                v={status.health.committeeAddress ? `Active (${status.health.committeeAddress.slice(0, 10)}…)` : "Active"}
              />
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Run it on your machine</CardTitle>
          <CardDescription>No account, no signup. Node 20 or newer.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3">
            {COMMANDS.map((c) => (
              <div key={c.label} className="flex items-center justify-between gap-3 rounded-lg border border-border bg-abyss px-3.5 py-2.5">
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">{c.label}</span>
                  <code className="code-scroll truncate font-mono text-xs text-accent-bright">{c.cmd}</code>
                </div>
                <CopyButton text={c.cmd} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
