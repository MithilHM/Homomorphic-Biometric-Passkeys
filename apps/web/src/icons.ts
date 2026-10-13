/**
 * Inline SVG icon set for the wallet client.
 *
 * The marketing site uses Lucide React; this client ships zero third-party
 * runtime code (supply-chain decision), so the same stroke-icon language is
 * hand-rolled here as static strings. Rendered via the `html` VNode prop,
 * which is only ever fed from these constants — never from network data.
 *
 * All icons: 24x24 viewBox, 2px round stroke, `currentColor`.
 */

const wrap = (inner: string): string =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ` +
  `stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${inner}</svg>`;

export const ICONS = {
  scan: wrap(
    `<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>` +
      `<path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>` +
      `<circle cx="9" cy="10" r="0.5" fill="currentColor"/>` +
      `<circle cx="15" cy="10" r="0.5" fill="currentColor"/>` +
      `<path d="M9 15.5c1.5 1 4.5 1 6 0"/>`,
  ),
  fingerprint: wrap(
    `<path d="M12 11a1 1 0 0 1 1 1c0 2.5-.5 5-1.5 7"/>` +
      `<path d="M12 8a4 4 0 0 1 4 4c0 3-.7 5.6-2 8"/>` +
      `<path d="M12 8a4 4 0 0 0-4 4c0 1.5-.1 3-.4 4.4"/>` +
      `<path d="M12 5a7 7 0 0 1 7 7c0 2.5-.4 4.8-1.2 7"/>` +
      `<path d="M12 5a7 7 0 0 0-7 7c0 1.2.1 2.3.3 3.4"/>`,
  ),
  cpu: wrap(
    `<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="10" y="10" width="4" height="4"/>` +
      `<path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>`,
  ),
  key: wrap(
    `<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9"/><path d="M17 6l2.5 2.5"/><path d="M14.5 8.5L17 11"/>`,
  ),
  shieldCheck: wrap(
    `<path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/>`,
  ),
  camera: wrap(
    `<path d="M4 8h3l2-2.5h6L17 8h3a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/>` +
      `<circle cx="12" cy="13.5" r="3.5"/>`,
  ),
  bolt: wrap(`<path d="M13 2L4 14h6l-1 8 9-12h-6z"/>`),
  lock: wrap(
    `<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>`,
  ),
  wallet: wrap(
    `<path d="M3 7a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>` +
      `<path d="M16 13.5h.01"/><path d="M3 9h18"/>`,
  ),
  activity: wrap(`<path d="M3 12h4l3 8 4-16 3 8h4"/>`),
  layers: wrap(
    `<path d="M12 2l9 5-9 5-9-5z"/><path d="M3 12l9 5 9-5"/><path d="M3 17l9 5 9-5"/>`,
  ),
  eyeOff: wrap(
    `<path d="M3 3l18 18"/><path d="M10.6 5.1A9.8 9.8 0 0 1 12 5c7 0 10 7 10 7a17 17 0 0 1-2.9 3.6"/>` +
      `<path d="M6.6 6.6A16.4 16.4 0 0 0 2 12s3 7 10 7c1.4 0 2.7-.3 3.9-.8"/>` +
      `<path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>`,
  ),
} as const;

export type IconName = keyof typeof ICONS;
