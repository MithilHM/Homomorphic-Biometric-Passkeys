import {
  ArrowRight,
  ArrowUpRight,
  Camera,
  Code2,
  Cpu,
  EyeOff,
  FileText,
  Fingerprint,
  KeyRound,
  Lock,
  ScanFace,
  ShieldAlert,
  ShieldCheck,
  Users,
  Vault,
  XCircle,
} from "lucide-react";
import DitherVeil from "./DitherVeil";
import { Accordion, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Reveal, SectionHeading, Stat } from "./ui";

export const HERO_SRC =
  "https://images.unsplash.com/photo-1737071371043-761e02b1ef95?q=80&w=1400&auto=format&fit=crop";

const REPO = "https://github.com/MithilHM/Homomorphic-Biometric-Passkeys";
const doc = (p: string) => `${REPO}/blob/main/${p}`;

/* ---------------- nav ---------------- */

const NAV = [
  { href: "#how", label: "How it works" },
  { href: "#honesty", label: "Honesty" },
  { href: "#playground", label: "Playground" },
  { href: "#stack", label: "Live stack" },
  { href: "#faq", label: "FAQ" },
];

export function Nav() {
  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-5">
        <a href="#top" className="flex items-center gap-2.5" aria-label="Homomorphic Biometric Passkeys home">
          <span className="flex size-8 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <ScanFace size={19} aria-hidden />
          </span>
          <span className="font-mono text-sm font-semibold tracking-tight">
            homobio<span className="text-accent">/</span>passkeys
          </span>
        </a>
        <nav aria-label="Primary" className="hidden items-center gap-6 text-sm text-muted-foreground md:flex">
          {NAV.map((n) => (
            <a key={n.href} href={n.href} className="transition-colors hover:text-foreground">
              {n.label}
            </a>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <a
            href={REPO}
            target="_blank"
            rel="noreferrer"
            className="inline-flex h-9 cursor-pointer items-center gap-2 rounded-lg border border-border px-3.5 text-sm text-muted-foreground transition-colors hover:border-accent hover:text-foreground"
          >
            <Code2 size={15} aria-hidden /> <span className="hidden sm:inline">Source</span>
          </a>
          <a
            href="#stack"
            className="inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-lg bg-accent px-3.5 text-sm font-semibold text-on-accent transition-colors hover:bg-accent-bright"
          >
            Try it <ArrowRight size={15} aria-hidden />
          </a>
        </div>
      </div>
    </header>
  );
}

/* ---------------- hero ---------------- */

export function Hero() {
  return (
    <section id="top" className="relative">
      <DitherVeil
        src={HERO_SRC}
        pattern="floyd"
        pixelSize={2}
        inkColor="#e9e4d6"
        paperColor="#14101a"
        revealRadius={220}
        softness={0.6}
        linger={1}
        alt="Dithered portrait — move your pointer to reveal it, like a biometric match revealing one bit"
        className="h-[94svh] min-h-[620px]"
      />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-background/70 via-transparent to-background" aria-hidden />
      <div className="absolute inset-0 mx-auto flex max-w-6xl flex-col justify-end px-5 pb-16">
        <div className="pointer-events-auto flex max-w-3xl flex-col gap-5">
          <div className="flex flex-wrap gap-2">
            <Badge tone="green">ERC-4337 v0.7</Badge>
            <Badge tone="green">FHE threshold 3-of-3</Badge>
            <Badge tone="neutral">WebAuthn passkeys</Badge>
            <Badge tone="neutral">Monad · chain 143</Badge>
          </div>
          <h1 className="text-4xl font-bold leading-[1.05] tracking-tight sm:text-6xl">
            Your face unlocks your wallet.
            <span className="text-accent-bright"> Nobody sees your face.</span>
          </h1>
          <p className="max-w-xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            Seedless smart accounts where a WebAuthn passkey holds cryptographic authority and a homomorphic
            face-match gates every transaction. The server multiplies ciphertexts — and learns exactly one bit.
          </p>
          <div className="flex flex-wrap gap-3">
            <Button size="lg" onClick={() => document.querySelector("#stack")?.scrollIntoView({ behavior: "smooth" })}>
              Run the live stack <ArrowRight size={17} aria-hidden />
            </Button>
            <Button size="lg" variant="outline" onClick={() => window.open(doc("docs/protocol-spec.md"), "_blank", "noopener")}>
              Read the protocol spec
            </Button>
          </div>
          <p className="font-mono text-xs text-muted-foreground">Move your pointer — the veil reveals like a match decision.</p>
        </div>
      </div>
    </section>
  );
}

/* ---------------- stats ---------------- */

export function Stats() {
  return (
    <section aria-label="Project statistics" className="border-b border-border/60">
      <div className="mx-auto grid max-w-6xl grid-cols-2 gap-8 px-5 py-12 sm:grid-cols-4">
        <Reveal><Stat value="177" label="Tests passing" /></Reveal>
        <Reveal><Stat value="N=1024" label="RLWE ring, depth-1" /></Reveal>
        <Reveal><Stat value="3-of-3" label="Decryption committee" /></Reveal>
        <Reveal><Stat value="<15s" label="Perceived auth time" /></Reveal>
      </div>
    </section>
  );
}

/* ---------------- how it works ---------------- */

const STEPS = [
  { icon: Camera, title: "Capture on-device", body: "Camera frames are detected, liveness-checked and embedded locally. Pixels never leave the device." },
  { icon: Fingerprint, title: "Encrypt the vector", body: "The 128-d embedding is L2-normalised, quantised at 2^18 and encrypted under the FHE public key." },
  { icon: Cpu, title: "Multiply ciphertexts", body: "The coprocessor multiplies enrolled × live ciphertexts. One ring multiply evaluates the whole cosine similarity." },
  { icon: Vault, title: "Threshold decrypt", body: "Three share-holders jointly recover one scalar. Any subset sees uniform randomness — nothing usable." },
  { icon: KeyRound, title: "Attest, don't prove", body: "The committee signs an EIP-191 attestation: decision bit plus commitments. No image, no embedding, no distance." },
  { icon: Lock, title: "Validate + execute", body: "BiometricSmartAccount checks bindings, consumes the session in validation, and EntryPoint executes on Monad." },
];

export function HowItWorks() {
  return (
    <section id="how" className="mx-auto max-w-6xl scroll-mt-20 px-5 py-20">
      <Reveal>
        <SectionHeading
          eyebrow="Pipeline"
          title="Seven steps, zero plaintext off-device"
          lede="Passkey equals authority; biometric match equals authorization condition. Neither factor alone can spend."
        />
      </Reveal>
      <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {STEPS.map((s, i) => (
          <li key={s.title}>
            <Reveal>
              <Card className="h-full transition-colors hover:border-accent/50">
                <CardHeader>
                  <span className="flex size-9 items-center justify-center rounded-lg bg-accent/12 text-accent">
                    <s.icon size={18} aria-hidden />
                  </span>
                  <p className="font-mono text-xs text-muted-foreground">0{i + 1}</p>
                  <CardTitle>{s.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription>{s.body}</CardDescription>
                </CardContent>
              </Card>
            </Reveal>
          </li>
        ))}
      </ol>
    </section>
  );
}

/* ---------------- honesty ---------------- */

const HONEST = [
  { icon: XCircle, title: "Not ZK-proven", body: "Threshold decryption plus signed attestation. We do not claim the homomorphic arithmetic is zero-knowledge verified." },
  { icon: XCircle, title: "Not CKKS by default", body: "A real leveled RLWE scheme over Z_q[X]/(X^1024+1), depth 1, no bootstrapping. OpenFHE CKKS is an optional path." },
  { icon: ShieldAlert, title: "Not production-hardened", body: "Partial decryptions are not MAC-checked yet; thresholds are provisional; liveness is active-only. All tracked openly." },
  { icon: EyeOff, title: "Not passive liveness", body: "Randomised motion challenges — turn, blink, approach. A still photo fails; a serious deepfake needs the production path." },
];

export function Honesty() {
  return (
    <section id="honesty" className="border-y border-border/60 bg-abyss/60">
      <div className="mx-auto max-w-6xl px-5 py-20">
        <Reveal>
          <SectionHeading
            eyebrow="Stated up front"
            title="What this is not"
            lede="The places this kind of project usually overclaims — documented before the first demo frame."
          />
        </Reveal>
        <div className="mt-10 grid gap-4 sm:grid-cols-2">
          {HONEST.map((h) => (
            <Reveal key={h.title}>
              <Card>
                <CardHeader>
                  <span className="flex size-9 items-center justify-center rounded-lg bg-destructive/12 text-destructive">
                    <h.icon size={18} aria-hidden />
                  </span>
                  <CardTitle>{h.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription>{h.body}</CardDescription>
                </CardContent>
              </Card>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------- tiers ---------------- */

const TIERS = [
  { name: "Convenience", threshold: "0.62", desc: "Low-value flows, session keys allowed. Face plus passkey, short lifetimes.", icon: ShieldCheck },
  { name: "Standard", threshold: "0.70", desc: "The default. Active liveness required, strict expiry, scoped delegation.", icon: Users },
  { name: "High security", threshold: "0.80", desc: "Fresh scan every time, hardware-backed passkey preferred, no session keys.", icon: Vault },
];

export function Tiers() {
  return (
    <section aria-label="Policy tiers" className="mx-auto max-w-6xl px-5 py-20">
      <Reveal>
        <SectionHeading
          eyebrow="Policy engine"
          title="One passkey, many keys"
          lede="Comparisons landing inside the noise band return indeterminate — a recapture, never a coin flip. Thresholds are provisional until measured on real data."
        />
      </Reveal>
      <div className="mt-10 grid gap-4 md:grid-cols-3">
        {TIERS.map((t) => (
          <Reveal key={t.name}>
            <Card className="h-full">
              <CardHeader>
                <span className="flex size-9 items-center justify-center rounded-lg bg-accent/12 text-accent">
                  <t.icon size={18} aria-hidden />
                </span>
                <CardTitle>{t.name}</CardTitle>
                <CardDescription>
                  cosine threshold <span className="font-mono text-accent-bright">{t.threshold}</span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CardDescription>{t.desc}</CardDescription>
              </CardContent>
            </Card>
          </Reveal>
        ))}
      </div>
    </section>
  );
}

/* ---------------- docs ---------------- */

const DOCS = [
  { title: "Protocol spec", desc: "Normative byte-level encoding of every structure. TS and Solidity are two implementations of this document.", href: doc("docs/protocol-spec.md") },
  { title: "Architecture", desc: "Services, data flow, trust boundaries. What each component sees — and what it must never see.", href: doc("docs/architecture.md") },
  { title: "Threat model", desc: "Attacks, mitigations, and what is explicitly not solved. Read before deploying anything.", href: doc("docs/threat-model.md") },
  { title: "Crypto parameters", desc: "Why N=1024, q, scale 2^18, dim 128 — every number benchmarked, none copied from an example.", href: doc("docs/crypto-parameters.md") },
];

export function Docs() {
  return (
    <section aria-label="Documentation" className="border-t border-border/60">
      <div className="mx-auto max-w-6xl px-5 py-20">
        <Reveal>
          <SectionHeading eyebrow="Read the construction" title="Docs, not vibes" />
        </Reveal>
        <div className="mt-10 grid gap-4 sm:grid-cols-2">
          {DOCS.map((d) => (
            <Reveal key={d.title}>
              <a
                href={d.href}
                target="_blank"
                rel="noreferrer"
                className="group flex h-full items-start justify-between gap-4 rounded-2xl border border-border bg-card p-6 transition-colors hover:border-accent/50"
              >
                <span className="flex flex-col gap-2">
                  <span className="flex items-center gap-2 font-semibold">
                    <FileText size={16} aria-hidden className="text-accent" /> {d.title}
                  </span>
                  <span className="text-sm leading-relaxed text-muted-foreground">{d.desc}</span>
                </span>
                <ArrowUpRight size={17} aria-hidden className="mt-1 shrink-0 text-muted-foreground transition-colors group-hover:text-accent-bright" />
              </a>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---------------- faq ---------------- */

const FAQS = [
  { q: "Is my face stored on-chain?", a: "No. Only a keccak commitment of the ciphertext template touches the chain. Ciphertexts live in coprocessor storage; frames and embeddings never leave your device." },
  { q: "Is the face match zero-knowledge proven?", a: "No — and we say so plainly. The decision path is 3-of-3 threshold decryption plus an EIP-191 attestation. A fully ZK-verified FHE pipeline is a research milestone, not a shipped claim." },
  { q: "What happens near the threshold?", a: "The comparison lands in an indeterminate band sized by the measured engine error (2^-9). The server returns HTTP 422 and you capture a fresh sample. Borderline never becomes a coin flip." },
  { q: "What if I lose my device?", a: "Recovery is delay-gated (48h floor, 30-day cap): it can only lock the account, never spend. The owner cancels anytime with a validated operation; finalization registers the new key on-chain." },
  { q: "Which chain, and do I need gas?", a: "Monad (chain ID 143) via ERC-4337 v0.7 EntryPoint 0x5FF1…2789. A sponsorship paymaster covers gas for eligible accounts; the relayer runs in dry-run until a bundler is configured." },
  { q: "Can one passkey cover many keys?", a: "Yes. The same authorization path mints scoped session keys (SessionKeyRegistry), registers backup devices, and drives timelocked recovery — one passkey, many delegations." },
];

export function Faq() {
  return (
    <section id="faq" className="mx-auto max-w-3xl scroll-mt-20 px-5 py-20">
      <Reveal>
        <SectionHeading eyebrow="FAQ" title="Asked like an auditor" />
      </Reveal>
      <Reveal className="mt-10">
        <Accordion items={FAQS} />
      </Reveal>
    </section>
  );
}

/* ---------------- footer ---------------- */

export function Footer() {
  return (
    <footer className="border-t border-border/60">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-5 py-10 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
        <p className="flex items-center gap-2">
          <ScanFace size={15} aria-hidden className="text-accent" />
          Homomorphic Biometric Passkeys · MIT · Monad testnet
        </p>
        <p className="flex items-center gap-4">
          <a href={doc("docs/threat-model.md")} target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">
            Threat model
          </a>
          <a href={REPO} target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">
            Source
          </a>
        </p>
      </div>
    </footer>
  );
}
