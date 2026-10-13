import {
  ArrowRight,
  ArrowUpRight,
  Camera,
  Code2,
  EyeOff,
  FileText,
  Fingerprint,
  KeyRound,
  Lock,
  ScanFace,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Users,
  Vault,
  XCircle,
} from "lucide-react";
import DitherVeil from "./DitherVeil";
import { AuroraText, BorderBeam, ShimmerButton, ShinyText } from "./magic";
import { Accordion, Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Reveal, SectionHeading, Stat } from "./ui";

export const HERO_SRC =
  "https://images.unsplash.com/photo-1737071371043-761e02b1ef95?q=80&w=1400&auto=format&fit=crop";

const REPO = "https://github.com/MithilHM/Homomorphic-Biometric-Passkeys";
const doc = (p: string) => `${REPO}/blob/main/${p}`;

/* ---------------- nav ---------------- */

const NAV = [
  { href: "#how", label: "How it works" },
  { href: "#start", label: "Get started" },
  { href: "#honesty", label: "Honest limits" },
  { href: "#stack", label: "Live status" },
  { href: "#faq", label: "FAQ" },
];

export function Nav() {
  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-5">
        <a href="#top" className="group flex items-center gap-2.5" aria-label="Face wallet home">
          <span className="relative flex size-8 items-center justify-center overflow-hidden rounded-lg bg-accent/15 text-accent transition-shadow group-hover:shadow-[0_0_20px_rgb(34_197_94/0.4)]">
            <ScanFace size={19} aria-hidden />
          </span>
          <span className="font-mono text-sm font-semibold tracking-tight">
            face<span className="text-accent">/</span>wallet
            <span className="ml-2 hidden rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 align-middle font-mono text-[10px] font-medium text-accent-bright sm:inline">
              ● live on Monad
            </span>
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
            className="inline-flex h-9 cursor-pointer items-center gap-2 rounded-lg border border-border px-3.5 text-sm text-muted-foreground transition-all hover:-translate-y-px hover:border-accent hover:text-foreground"
          >
            <Code2 size={15} aria-hidden /> <span className="hidden sm:inline">Source</span>
          </a>
          <a
            href="#start"
            className="btn-shine inline-flex h-9 cursor-pointer items-center gap-1.5 rounded-lg bg-accent px-3.5 text-sm font-semibold text-on-accent transition-all hover:-translate-y-px hover:bg-accent-bright hover:shadow-[0_8px_30px_rgb(34_197_94/0.4)]"
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
        alt="Portrait dissolving into pixels — move your pointer to reveal it"
        className="h-[94svh] min-h-[620px]"
      />
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-background/85 via-background/25 to-background" aria-hidden />
      <div className="pointer-events-none absolute inset-y-0 left-0 w-full bg-gradient-to-r from-background/70 via-transparent to-transparent sm:w-3/4" aria-hidden />
      <div className="absolute inset-0 mx-auto flex max-w-6xl flex-col justify-end px-5 pb-16">
        <div className="pointer-events-auto flex max-w-3xl flex-col gap-5 [text-shadow:0_2px_28px_rgb(0_0_0/0.85),0_1px_4px_rgb(0_0_0/0.9)]">
          <div className="flex flex-wrap gap-2 [text-shadow:none]">
            <Badge tone="green">No seed phrases</Badge>
            <Badge tone="green">Face unlock</Badge>
            <Badge tone="neutral">CKKS homomorphic match</Badge>
            <Badge tone="neutral">ERC-4337 · Monad 143</Badge>
          </div>
          <h1 className="text-4xl font-bold leading-[1.05] tracking-tight sm:text-6xl">
            Your face unlocks your wallet.
            <br />
            <AuroraText colors={["#4ade80", "#38bdf8", "#836ef9", "#4ade80"]} speed={0.9}>
              Nobody sees your face.
            </AuroraText>
          </h1>
          <p className="max-w-xl text-base leading-relaxed text-slate-200 sm:text-lg">
            A crypto wallet that opens with a look instead of a written-down secret. Your face is checked on
            your own device, and the service that verifies you never receives anything it could recognize.
          </p>
          <div className="flex flex-wrap items-center gap-3 [text-shadow:none]">
            <ShimmerButton onClick={() => document.querySelector("#start")?.scrollIntoView({ behavior: "smooth" })}>
              Create your wallet <ArrowRight size={17} aria-hidden />
            </ShimmerButton>
            <Button size="lg" variant="outline" className="bg-background/50 backdrop-blur-sm" onClick={() => window.open(doc("docs/architecture.md"), "_blank", "noopener")}>
              How it works
            </Button>
          </div>
          <p className="font-mono text-[11px] tracking-wide text-slate-400 [text-shadow:none]">
            <ShinyText>Move your pointer — the veil lifts where you look. Your pixels never leave this page.</ShinyText>
          </p>
        </div>
      </div>
    </section>
  );
}

/* ---------------- stats ---------------- */

export function Stats() {
  return (
    <section aria-label="At a glance" className="border-b border-border/60">
      <div className="mx-auto grid max-w-6xl grid-cols-2 gap-8 px-5 py-12 sm:grid-cols-4">
        <Reveal><Stat value="0" label="Seed phrases to write down" ticker /></Reveal>
        <Reveal><Stat value="1" label="Look to unlock" ticker /></Reveal>
        <Reveal><Stat value="0" label="Face data shared with servers" ticker /></Reveal>
        <Reveal><Stat value="48h" label="Safety delay on recovery" /></Reveal>
      </div>
    </section>
  );
}

/* ---------------- how it works ---------------- */

const STEPS = [
  { icon: Camera, title: "Look at your device", body: "Your camera checks it is really you, right there, right now — a photo held up to the lens fails." },
  { icon: Smartphone, title: "Your device does the math", body: "Your phone turns the glance into a scrambled code locally. The picture itself is thrown away instantly." },
  { icon: Fingerprint, title: "Only the scramble travels", body: "What leaves your device cannot be turned back into your face — not by us, not by anyone intercepting it." },
  { icon: KeyRound, title: "Your device key approves", body: "The same tap that unlocks your phone signs the exact payment you reviewed. Nothing else can be swapped in." },
  { icon: Lock, title: "One yes, one payment", body: "Each approval works exactly once, for exactly the payment you saw. Replays and tampered payments are rejected." },
  { icon: Vault, title: "Lost phone? You are covered", body: "Recovery needs your backup key plus a 48-hour waiting period where you can cancel. It can lock, never steal." },
];

export function HowItWorks() {
  return (
    <section id="how" className="mx-auto max-w-6xl scroll-mt-20 px-5 py-20">
      <Reveal>
        <SectionHeading
          eyebrow="How it works"
          title="A look replaces the secret notebook"
          lede="Two things must agree before money moves: your face, and your device key. Either one alone can do nothing."
        />
      </Reveal>
      <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {STEPS.map((s, i) => (
          <li key={s.title}>
            <Reveal>
              <Card className={`h-full ${i === 0 ? "relative overflow-hidden border-accent/40" : ""}`}>
                {i === 0 && <BorderBeam size={100} duration={5} colorFrom="#4ade80" colorTo="#38bdf8" />}
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

/* ---------------- onboarding preview (marketing → app handoff) ---------------- */

const ONBOARD_STEPS = [
  { n: "01", icon: KeyRound, title: "Create a passkey", body: "One tap makes your device key. No seed phrase is ever shown, written, or stored anywhere." },
  { n: "02", icon: ScanFace, title: "Enroll your face — encrypted", body: "Seven glances become one encrypted template on your device. Plaintext never leaves it." },
  { n: "03", icon: KeyRound, title: "Look to spend", body: "Every payment needs face + passkey + exact recipient, together. Replays die on contact." },
];

export function OnboardingPreview() {
  return (
    <section id="start" className="mx-auto max-w-6xl scroll-mt-20 px-5 py-20">
      <Reveal>
        <SectionHeading
          eyebrow="Onboarding · 90 seconds"
          title="From nothing to a face-locked wallet"
          lede="Three steps, in order, with nothing to write down. This is exactly what the wallet app walks you through."
        />
      </Reveal>
      <div className="mt-10 grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <ol className="grid gap-4 sm:grid-cols-3 lg:grid-cols-1">
          {ONBOARD_STEPS.map((s, i) => (
            <li key={s.n}>
              <Reveal>
                <Card className={`relative h-full overflow-hidden ${i === 0 ? "border-accent/40" : ""}`}>
                  {i === 0 && <BorderBeam size={90} duration={5.5} colorFrom="#4ade80" colorTo="#836ef9" />}
                  <CardHeader>
                    <span className="flex items-center gap-3">
                      <span className="flex size-9 items-center justify-center rounded-lg bg-accent/12 font-mono text-sm font-semibold text-accent">
                        {s.n}
                      </span>
                      <span className="flex size-9 items-center justify-center rounded-lg bg-muted text-foreground">
                        <s.icon size={18} aria-hidden />
                      </span>
                    </span>
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
        <Reveal>
          <div className="relative flex h-full flex-col justify-between gap-6 overflow-hidden rounded-2xl border border-accent/30 bg-gradient-to-b from-accent/10 via-card to-card p-8">
            <BorderBeam size={140} duration={7} colorFrom="#4ade80" colorTo="#38bdf8" borderWidth={1.5} />
            <div className="flex flex-col gap-3">
              <p className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-accent">Your privacy, up front</p>
              <p className="text-2xl font-bold leading-tight tracking-tight">
                Camera frames never leave your device.{" "}
                <AuroraText colors={["#4ade80", "#38bdf8", "#836ef9", "#4ade80"]} speed={0.8}>
                  Ever.
                </AuroraText>
              </p>
              <ul className="mt-2 flex flex-col gap-2.5 text-sm leading-relaxed text-muted-foreground">
                {[
                  "Frames are discarded after each capture",
                  "Vectors are encrypted before upload",
                  "Backend compares ciphertext only",
                  "Passkey — not face — is the spending key",
                ].map((t) => (
                  <li key={t} className="flex items-start gap-2.5">
                    <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-accent/40 bg-accent/10 text-[11px] font-bold text-accent-bright">
                      ✓
                    </span>
                    {t}
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex flex-col gap-3">
              <ShimmerButton onClick={() => document.querySelector("#stack")?.scrollIntoView({ behavior: "smooth" })}>
                Open the live wallet <ArrowRight size={17} aria-hidden />
              </ShimmerButton>
              <p className="text-center font-mono text-[11px] text-muted-foreground">
                Runs locally · Monad testnet 143 · open source
              </p>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* ---------------- honesty ---------------- */

const HONEST = [
  { icon: XCircle, title: "We cannot see your face", body: "This cuts both ways: if something goes wrong on your device, we have no copy to help with. Your backup key is your safety net — set it up." },
  { icon: ShieldAlert, title: "New tech, open limits", body: "The face check is getting stronger every release. Today it asks you to move and blink; dedicated spoofing gear is a known open item." },
  { icon: EyeOff, title: "Close calls get a redo, not a guess", body: "If the check lands in the grey zone, it asks for one more glance instead of flipping a coin. Slightly slower, much safer." },
  { icon: Users, title: "Recovery takes two days", body: "That delay is the security. If a recovery you did not start appears, you have 48 hours to cancel it from a device you still own." },
];

export function Honesty() {
  return (
    <section id="honesty" className="border-y border-border/60 bg-abyss/60">
      <div className="mx-auto max-w-6xl px-5 py-20">
        <Reveal>
          <SectionHeading
            eyebrow="Stated up front"
            title="Honest limits"
            lede="A wallet that holds money should tell you what it cannot do — before you trust it."
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
  { name: "Everyday", threshold: "Relaxed", desc: "Coffee money. A quick glance approves small payments; apps you trust can act within limits you set.", icon: ShieldCheck },
  { name: "Standard", threshold: "Balanced", desc: "The default. Every payment needs a fresh glance plus your device key, with tight expiry.", icon: Users },
  { name: "Maximum", threshold: "Strict", desc: "Life savings mode. Fresh glance, strongest device key, no shortcuts, no delegated apps.", icon: Vault },
];

export function Tiers() {
  return (
    <section aria-label="Protection levels" className="mx-auto max-w-6xl px-5 py-20">
      <Reveal>
        <SectionHeading
          eyebrow="Your rules"
          title="Dial strictness up or down"
          lede="Small daily payments stay effortless; big moves demand everything. You choose per wallet."
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
                  strictness <span className="font-mono text-accent-bright">{t.threshold}</span>
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
  { title: "Protocol spec", desc: "The exact byte-level rules both the app and the contracts implement.", href: doc("docs/protocol-spec.md") },
  { title: "Architecture", desc: "Which part sees what — and what no part is ever allowed to see.", href: doc("docs/architecture.md") },
  { title: "Threat model", desc: "What is defended, what is open, and what must hold before production.", href: doc("docs/threat-model.md") },
  { title: "Crypto parameters", desc: "Every number benchmarked on real runs. Nothing copied from an example.", href: doc("docs/crypto-parameters.md") },
];

export function Docs() {
  return (
    <section aria-label="For developers" className="border-t border-border/60">
      <div className="mx-auto max-w-6xl px-5 py-20">
        <Reveal>
          <SectionHeading eyebrow="For developers" title="Verify, don't trust us" lede="Everything above is backed by code and documents you can audit." />
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
  { q: "Where is my face stored?", a: "Nowhere except your device, and only for the second it takes to check. There is no photo album of users on any server — there is nothing to leak." },
  { q: "What if someone steals the scrambled code?", a: "It cannot be turned back into your face, and alone it unlocks nothing. Spending also needs your device key approving that exact payment." },
  { q: "What if my look is borderline — bad light, new glasses?", a: "The wallet asks for one more glance instead of guessing. If your appearance changed for good, re-enroll in settings." },
  { q: "What if I lose my phone?", a: "Start recovery with your backup key. Nothing moves for 48 hours, and you can cancel from any device you still own. After the wait, your new key takes over." },
  { q: "Can apps use my wallet without asking each time?", a: "Only inside limits you set in advance — which apps, how much, until when. Anything outside pops up for a fresh glance." },
  { q: "Do I need to buy crypto for fees?", a: "No. New wallets are sponsored, so your first transactions cost you nothing." },
];

export function Faq() {
  return (
    <section id="faq" className="mx-auto max-w-3xl scroll-mt-20 px-5 py-20">
      <Reveal>
        <SectionHeading eyebrow="FAQ" title="Asked like a customer" />
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
          Face wallet · open source (MIT)
        </p>
        <p className="flex items-center gap-4">
          <a href={doc("docs/threat-model.md")} target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">
            Limits
          </a>
          <a href={REPO} target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">
            Source
          </a>
        </p>
      </div>
    </footer>
  );
}
