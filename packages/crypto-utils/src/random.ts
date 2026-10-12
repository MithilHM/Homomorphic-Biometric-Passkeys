/** Constant-time comparison + CSPRNG helpers. */

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function randomBytes(length = 32): Uint8Array {
  const out = new Uint8Array(length);
  const c = globalThis.crypto;
  if (!c?.getRandomValues) throw new Error("No CSPRNG available in this runtime");
  c.getRandomValues(out);
  return out;
}

export function randomId(byteLength = 16): string {
  const bytes = randomBytes(byteLength);
  // RFC 4122 v4 layout.
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
