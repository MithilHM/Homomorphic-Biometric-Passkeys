/**
 * Polynomials in R = Z_q[X] / (X^N + 1), stored as N coefficients in [0, q).
 */

import { ntt, primitiveRootOfUnity } from "./field.js";

export class RingContext {
  readonly n: number;
  readonly q: bigint;
  /** Primitive 2N-th root of unity used for the cyclic embedding. */
  readonly psi: bigint;

  private psiCache = new Map<number, bigint>();

  constructor(n: number, q: bigint) {
    if ((n & (n - 1)) !== 0) throw new Error("ring dimension must be a power of two");
    if ((q - 1n) % BigInt(2 * n) !== 0n) {
      throw new Error("modulus must satisfy q = 1 (mod 2N) for the NTT embedding");
    }
    this.n = n;
    this.q = q;
    this.psi = primitiveRootOfUnity(q, 2 * n);
  }

  zero(): bigint[] {
    return new Array<bigint>(this.n).fill(0n);
  }

  fromSigned(values: ArrayLike<number | bigint>): bigint[] {
    const out = this.zero();
    for (let i = 0; i < values.length && i < this.n; i++) {
      let v = typeof values[i] === "bigint" ? (values[i] as bigint) : BigInt(Math.trunc(values[i] as number));
      v %= this.q;
      if (v < 0n) v += this.q;
      out[i] = v;
    }
    return out;
  }

  add(a: bigint[], b: bigint[]): bigint[] {
    const out = this.zero();
    for (let i = 0; i < this.n; i++) out[i] = (a[i] + b[i]) % this.q;
    return out;
  }

  /** Add with an explicit modulus, for assembling multi-term products. */
  add3(a: bigint[], b: bigint[], mod: bigint): bigint[] {
    const out = this.zero();
    for (let i = 0; i < this.n; i++) out[i] = (a[i] + b[i]) % mod;
    return out;
  }

  sub(a: bigint[], b: bigint[]): bigint[] {
    const out = this.zero();
    for (let i = 0; i < this.n; i++) out[i] = (a[i] - b[i] + this.q) % this.q;
    return out;
  }

  neg(a: bigint[]): bigint[] {
    const out = this.zero();
    for (let i = 0; i < this.n; i++) out[i] = a[i] === 0n ? 0n : this.q - a[i];
    return out;
  }

  scale(a: bigint[], s: bigint): bigint[] {
    const out = this.zero();
    const k = ((s % this.q) + this.q) % this.q;
    for (let i = 0; i < this.n; i++) out[i] = (a[i] * k) % this.q;
    return out;
  }

  /** Multiply by X^k (a cyclic rotation of the coefficients). */
  rotate(a: bigint[], k: number): bigint[] {
    const out = this.zero();
    const n = this.n;
    const steps = ((k % (2 * n)) + 2 * n) % (2 * n);
    for (let i = 0; i < n; i++) {
      const j = (i + steps) % n;
      const target = i + steps >= n ? (this.q - a[i]) % this.q : a[i];
      out[j] = target;
    }
    return out;
  }

  /**
   * Multiplication in R.
   *
   * Implemented as a length-2N cyclic convolution with zero padding, then the
   * fold  result[i] = d[i] - d[i + N]  that turns X^N = -1 into X^N = 1.
   *
   * Inputs are reduced into [0, q) first: ternary secrets carry -1n entries
   * and JS `%` keeps the sign, which would violate the file's own invariant.
   */
  mul(a: bigint[], b: bigint[]): bigint[] {
    const size = this.n * 2;
    const fa = new Array<bigint>(size).fill(0n);
    const fb = new Array<bigint>(size).fill(0n);
    for (let i = 0; i < this.n; i++) {
      fa[i] = norm(a[i], this.q);
      fb[i] = norm(b[i], this.q);
    }
    const psi2 = this.rootOfOrder(size);
    ntt(fa, psi2, this.q, false);
    ntt(fb, psi2, this.q, false);
    for (let i = 0; i < size; i++) fa[i] = (fa[i] * fb[i]) % this.q;
    ntt(fa, psi2, this.q, true);
    const out = this.zero();
    for (let i = 0; i < this.n; i++) {
      out[i] = (fa[i] - fa[i + this.n] + this.q) % this.q;
    }
    return out;
  }

  /**
   * Outer product of two lists of polynomials: `out[i][j] = a[i] * b[j]`.
   *
   * The NTT transform of every operand is computed once, so a ciphertext
   * multiplication costs 6 ring multiplications for the price of ~3.
   */
  mulOuter(a: bigint[][], b: bigint[][]): bigint[][][] {
    if (a.length === 0 || b.length === 0) return [];
    const size = this.n * 2;
    const psi2 = this.rootOfOrder(size);

    const toNtt = (poly: bigint[]) => {
      const buf = new Array<bigint>(size).fill(0n);
      for (let i = 0; i < this.n && i < poly.length; i++) buf[i] = norm(poly[i], this.q);
      ntt(buf, psi2, this.q, false);
      return buf;
    };

    const fa = a.map(toNtt);
    const fb = b.map(toNtt);

    const pointwiseInv = (bufA: bigint[], bufB: bigint[]) => {
      const buf = new Array<bigint>(size).fill(0n);
      for (let k = 0; k < size; k++) buf[k] = (bufA[k] * bufB[k]) % this.q;
      ntt(buf, psi2, this.q, true);
      const res = this.zero();
      for (let i = 0; i < this.n; i++) res[i] = (buf[i] - buf[i + this.n] + this.q) % this.q;
      return res;
    };

    return fa.map((bufA) => fb.map((bufB) => pointwiseInv(bufA, bufB)));
  }

  /** Centered integer representative of a field element. */
  toSigned(value: bigint): bigint {
    const half = this.q >> 1n;
    const v = norm(value, this.q);
    return v > half ? v - this.q : v;
  }

  private rootOfOrder(order: number): bigint {
    const cached = this.psiCache.get(order);
    if (cached) return cached;
    if (order === 2 * this.n) {
      this.psiCache.set(order, this.psi);
      return this.psi;
    }
    // psi has order 2N; the 2N-th root is exactly what the padded convolution
    // needs, so no other order is ever requested.
    throw new Error(`unsupported NTT order ${order}`);
  }
}

/** Reduce into [0, q): JS `%` keeps the sign of negative dividends. */
function norm(value: bigint, q: bigint): bigint {
  const v = value % q;
  return v < 0n ? v + q : v;
}
