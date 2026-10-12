/** Hex / base64url / big-endian byte helpers shared across the protocol. */

const HEX = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 15];
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string must have even length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

export function isHex(value: unknown, byteLength?: number): value is string {
  if (typeof value !== "string") return false;
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  if (byteLength !== undefined && clean.length !== byteLength * 2) return false;
  return /^[0-9a-fA-F]*$/.test(clean);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  if (typeof btoa === "function") return btoa(binary);
  return Buffer.from(bytes).toString("base64");
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/-/g, "+").replace(/_/g, "/");
  if (typeof atob === "function") {
    const binary = atob(clean);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(clean, "base64"));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  return base64ToBytes(b64url);
}

/** Big-endian uint of `byteLength` bytes. */
export function uintToBytes(value: bigint | number, byteLength: number): Uint8Array {
  let v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n) throw new Error("uintToBytes does not accept negative values");
  const out = new Uint8Array(byteLength);
  for (let i = byteLength - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`value does not fit in ${byteLength} bytes`);
  return out;
}

export function bytesToUint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

export function concat(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** Length-prefixed (u16 big-endian) concatenation — the canonical field framing. */
export function lengthPrefixed(...chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += 2 + c.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  for (const c of chunks) {
    view.setUint16(off, c.length, false);
    out.set(c, off + 2);
    off += 2 + c.length;
  }
  return out;
}

/** ASCII string as bytes. */
export function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 0x7f) throw new Error("ascii() received a non-ASCII character");
    out[i] = c;
  }
  return out;
}
