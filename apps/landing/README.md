# @homobio/landing

Marketing + docs landing page for Homomorphic Biometric Passkeys. React Bits
style hero built around `DitherVeil`, plus a tunable playground and a live
gateway-status widget.

**Separate from `apps/web` on purpose:** the shipped wallet client stays
dependency-free (threat model T-7). This site carries React/Tailwind and never
touches key material, biometrics, or the auth path.

## Develop

```bash
npm run dev --workspace=@homobio/landing   # :5173, proxies /v1 to the gateway
npm run typecheck --workspace=@homobio/landing
npm run build --workspace=@homobio/landing # static dist/
```

Set `VITE_GATEWAY_URL` to point the status widget elsewhere (default
`http://localhost:5000`, same-origin `/v1` proxy in dev).

## DitherVeil

```tsx
import DitherVeil from "./DitherVeil";

<div style={{ width: "100%", height: "600px", position: "relative" }}>
  <DitherVeil
    src="https://images.unsplash.com/photo-1737071371043-761e02b1ef95?q=80&w=1400&auto=format&fit=crop"
    pattern="floyd"
    pixelSize={2}
    inkColor="#e9e4d6"
    paperColor="#14101a"
    revealRadius={200}
    softness={0.6}
    linger={1}
  />
</div>
```

- `pattern`: `floyd` (error diffusion) | `bayer` (ordered 4x4) | `none` (threshold).
- Diffusion runs once per source/look; per-frame cost is a few `drawImage`
  calls. The loop pauses offscreen and when the tab hides, and disables the
  trail under `prefers-reduced-motion`.
- CORS-blocked images fall back to a procedural duotone field — never blank.
