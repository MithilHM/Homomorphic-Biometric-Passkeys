/** CSPRNG-backed samplers for the RLWE scheme. */

/**
 * Buffered CSPRNG. `crypto.getRandomValues` is comparatively expensive per call,
 * and rejection sampling needs many draws, so we keep a refillable pool.
 */
class RandomPool {
  private buffer = new Uint8Array(0);
  private cursor = 0;

  take(length: number): Uint8Array {
    if (this.cursor + length > this.buffer.length) {
      const size = Math.max(8192, length * 8);
      this.buffer = new Uint8Array(size);
      globalThis.crypto.getRandomValues(this.buffer);
      this.cursor = 0;
    }
    const slice = this.buffer.subarray(this.cursor, this.cursor + length);
    this.cursor += length;
    return slice;
  }
}

const pool = new RandomPool();

function randomBytes(length: number): Uint8Array {
  return pool.take(length);
}

const byteToBigInt = (b: Uint8Array, offset: number, len: number): bigint => {
  let v = 0n;
  for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(b[offset + i]);
  return v;
};

/** Uniform in [0, q) by rejection sampling — unbiased, no modulo bias. */
export function sampleUniform(n: number, q: bigint): bigint[] {
  const byteLength = Math.ceil(q.toString(2).length / 8);
  const out = new Array<bigint>(n);
  for (let i = 0; i < n; i++) {
    for (;;) {
      const v = byteToBigInt(randomBytes(byteLength), 0, byteLength);
      if (v < q) {
        out[i] = v;
        break;
      }
    }
  }
  return out;
}

/** Ternary coefficients in {-1, 0, 1} with equal probability. */
export function sampleTernary(n: number): bigint[] {
  const out = new Array<bigint>(n);
  for (let i = 0; i < n; i++) {
    const r = randomBytes(1)[0] % 3;
    out[i] = r === 0 ? 0n : r === 1 ? 1n : -1n;
  }
  return out;
}

export type Poly = bigint[];

export function addPoly(a: Poly, b: Poly, q: bigint): Poly {
  const out = new Array<bigint>(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] + b[i]) % q;
  return out;
}

export function subPoly(a: Poly, b: Poly, q: bigint): Poly {
  const out = new Array<bigint>(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] - b[i] + q) % q;
  return out;
}

export function scalePoly(a: Poly, s: bigint, q: bigint): Poly {
  const k = ((s % q) + q) % q;
  const out = new Array<bigint>(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] * k) % q;
  return out;
}
