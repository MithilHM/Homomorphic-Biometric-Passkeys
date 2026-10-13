import { Suspense, lazy } from "react";
import { Nav, Hero, Stats, HowItWorks, OnboardingPreview, Honesty, Tiers, Docs, Faq, Footer } from "./components/Sections";
import { SectionHeading, Reveal } from "./components/ui";

// Below-fold section split out of the initial chunk.
const StackStatus = lazy(() => import("./components/StackStatus"));

function SectionFallback({ label }: { label: string }) {
  return (
    <div className="rounded-2xl border border-border bg-card p-10 text-center text-sm text-muted-foreground" role="status">
      Loading {label}…
    </div>
  );
}

export default function App() {
  return (
    <div className="min-h-screen bg-background font-sans text-foreground">
      <a
        href="#how"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-accent focus:px-4 focus:py-2 focus:text-on-accent"
      >
        Skip to content
      </a>
      <Nav />
      <main>
        <Hero />
        <Stats />
        <HowItWorks />
        <OnboardingPreview />
        <Honesty />
        <div className="border-y border-border/60 bg-abyss/60">
          <section id="stack" className="mx-auto max-w-6xl scroll-mt-20 px-5 py-20">
            <Reveal>
              <SectionHeading
                eyebrow="Functional"
                title="Talk to a live stack"
                lede="This page probes the gateway you run locally — committee, FHE parameters, EntryPoint — and hands you the commands."
              />
            </Reveal>
            <Reveal className="mt-10">
              <Suspense fallback={<SectionFallback label="stack status" />}>
                <StackStatus />
              </Suspense>
            </Reveal>
          </section>
        </div>
        <Tiers />
        <Docs />
        <Faq />
      </main>
      <Footer />
    </div>
  );
}
