import { useEffect, useState } from "react";
import { Activity, PlugZap, TriangleAlert } from "lucide-react";
import { Badge, Card, CardContent, CardDescription, CardHeader, CardTitle, CopyButton } from "./ui";

const GATEWAY = import.meta.env.VITE_GATEWAY_URL ?? "http://localhost:5000";

interface Health {
  committeeAddress?: string;
  [k: string]: unknown;
}

interface GatewayConfig {
  chainId?: number;
  entryPoint?: string;
  fhe?: { engine?: string; ringDimension?: number; scaleBits?: number; embeddingDimension?: number };
  webauthn?: { requireUserVerification?: boolean };
  [k: string]: unknown;
}

type Status = { state: "loading" } | { state: "live"; health: Health; config: GatewayConfig } | { state: "offline"; message: string };

async function fetchJson<T>(url: string, timeoutMs: number): Promise<T> {
  const ctrl = new AbortController();
  const timer = window.setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as T;
  } finally {
    window.clearTimeout(timer);
  }
}

const COMMANDS = [
  { label: "Install", cmd: "npm install" },
  { label: "Serve stack", cmd: "npm run dev     # coprocessor :5001, gateway :5000" },
  { label: "Tests", cmd: "npm test            # 177 tests" },
  { label: "Demo", cmd: "npm run demo        # 7 end-to-end scenarios" },
];

function Row({ k, v, mono = true }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border/60 py-2.5 last:border-0">
      <span className="shrink-0 text-xs uppercase tracking-[0.12em] text-muted-foreground">{k}</span>
      <span className={mono ? "break-all text-right font-mono text-xs text-foreground" : "text-right text-xs text-foreground"}>
        {v}
      </span>
    </div>
  );
}

export default function StackStatus() {
  const [status, setStatus] = useState<Status>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    // Independent fetches in parallel; either may fail without hiding the other.
    Promise.allSettled([fetchJson<Health>(`${GATEWAY}/v1/health`, 8000), fetchJson<GatewayConfig>(`${GATEWAY}/v1/config`, 8000)]).then(
      ([health, config]) => {
        if (cancelled) return;
        if (health.status === "fulfilled" && config.status === "fulfilled") {
          setStatus({ state: "live", health: health.value, config: config.value });
        } else {
          const reason =
            health.status === "rejected"
              ? health.reason instanceof Error
                ? health.reason.message
                : "unreachable"
              : "unreachable";
          setStatus({ state: "offline", message: `Gateway ${GATEWAY} ${reason} — start it with npm run dev.` });
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
            <CardTitle>Live stack status</CardTitle>
            {status.state === "live" ? (
              <Badge tone="green">
                <span className="size-1.5 rounded-full bg-accent animate-pulse-dot" aria-hidden /> Live
              </Badge>
            ) : status.state === "loading" ? (
              <Badge>Probing…</Badge>
            ) : (
              <Badge tone="red">
                <TriangleAlert size={12} aria-hidden /> Offline
              </Badge>
            )}
          </div>
          <CardDescription>
            Probed from your browser at <span className="font-mono">{GATEWAY}</span>. Nothing biometric ever leaves this page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {status.state === "loading" && (
            <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
              <Activity size={15} aria-hidden className="animate-pulse" /> Contacting gateway…
            </p>
          )}
          {status.state === "offline" && (
            <p className="flex items-start gap-2 py-6 text-sm leading-relaxed text-muted-foreground">
              <PlugZap size={15} aria-hidden className="mt-0.5 shrink-0" /> {status.message}
            </p>
          )}
          {status.state === "live" && (
            <div>
              <Row k="Committee" v={String(status.health.committeeAddress ?? "—")} />
              <Row k="Chain" v={String(status.config.chainId ?? "—")} />
              <Row k="EntryPoint" v={String(status.config.entryPoint ?? "—")} />
              <Row
                k="FHE engine"
                v={`${status.config.fhe?.engine ?? "—"} · N=${status.config.fhe?.ringDimension ?? "—"} · 2^${status.config.fhe?.scaleBits ?? "—"} · dim ${status.config.fhe?.embeddingDimension ?? "—"}`}
              />
              <Row k="Passkey UV" v={status.config.webauthn?.requireUserVerification ? "required" : "—"} />
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Run it yourself</CardTitle>
          <CardDescription>Node ≥ 20.11. No seed phrases, no hosted key custodian.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3">
            {COMMANDS.map((c) => (
              <div key={c.label} className="flex items-center justify-between gap-3 rounded-lg border border-border bg-abyss px-3.5 py-2.5">
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted-foreground">{c.label}</span>
                  <code className="code-scroll truncate font-mono text-xs text-accent-bright">{c.cmd}</code>
                </div>
                <CopyButton text={c.cmd.split("#")[0]!.trim()} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
