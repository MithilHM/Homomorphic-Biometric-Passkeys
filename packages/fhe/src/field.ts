/**
 * Prime-field arithmetic and NTT over Z_q with q = 1 (mod 2N).
 *
 * Homomorphic multiplication happens in the negacyclic ring
 * R = Z_q[X] / (X^N + 1). We evaluate it as a cyclic convolution of length 2N
 * (zero padded) followed by the standard fold  c[i] = d[i] - d[i + N], which is
 * far easier to get right than a hand-rolled negacyclic Cooley-Tukey.
 */

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  if (b < 0n) b += mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

export function modInv(a: bigint, mod: bigint): bigint {
  const gcd = extGcd(a, mod);
  if (gcd.g !== 1n) throw new Error("value is not invertible modulo q");
  return ((gcd.x % mod) + mod) % mod;
}

function extGcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return { g: oldR, x: oldS, y: oldT };
}

const SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

export function isProbablePrime(n: bigint, rounds = 24): boolean {
  if (n < 2n) return false;
  for (const p of SMALL_PRIMES) {
    if (n === BigInt(p)) return true;
    if (n % BigInt(p) === 0n) return false;
  }
  const d = n - 1n;
  let r = 0n;
  let dd = d;
  while (dd % 2n === 0n) {
    dd >>= 1n;
    r++;
  }
  for (let i = 0; i < rounds; i++) {
    // Deterministic witness derivation keeps key generation reproducible.
    const a = 2n + BigInt(i) * 2n + 1n;
    let x = modPow(a % n, dd, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let j = 1n; j < r; j++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

/** Smallest prime >= 2^(bits-1) that is congruent to 1 (mod multiple). */
export function findPrime(bits: number, multiple: number): bigint {
  // `multiple` is even (a power of two) for every parameter set we use, so the
  // walk must start from an odd number or every candidate is trivially even.
  const base = (1n << BigInt(bits - 1)) + 1n;
  const step = BigInt(multiple);
  for (let k = 0n; k < 2_000_000n; k++) {
    const candidate = base + k * step;
    if (isProbablePrime(candidate)) return candidate;
  }
  throw new Error(`no prime found with ${bits} bits and q = 1 (mod ${multiple})`);
}

/** A primitive 2N-th root of unity modulo q (exists because 2N | q - 1). */
export function primitiveRootOfUnity(q: bigint, order: number): bigint {
  let g = 2n;
  while (!isProbablePrime(g)) g++;
  while (true) {
    const psi = modPow(g, (q - 1n) / BigInt(order), q);
    // psi must have exact order `order`.
    if (modPow(psi, BigInt(order / 2), q) === q - 1n) return psi;
    g++;
  }
}

/**
 * In-place iterative radix-2 NTT.
 *
 * `root` must be a primitive `values.length`-th root of unity modulo `mod`;
 * each stage then uses `root^(n/len)`, which is a primitive `len`-th root.
 *
 * (Note the stage exponent is `n / len`, NOT `(mod - 1) / len`. The latter only
 * happens to agree when `root = g^((mod-1)/n)` for a generator g; using it with
 * an arbitrary primitive n-th root silently yields roots of the wrong order for
 * most n, and the failure looks like random noise rather than an error.)
 */
export function ntt(values: bigint[], root: bigint, mod: bigint, inverse: boolean): void {
  const n = values.length;
  if ((n & (n - 1)) !== 0) throw new Error("NTT length must be a power of two");

  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      const tmp = values[i];
      values[i] = values[j];
      values[j] = tmp;
    }
  }

  for (let len = 2; len <= n; len <<= 1) {
    let wlen = modPow(root, BigInt(n / len), mod);
    if (inverse) wlen = modInv(wlen, mod);
    const half = len >> 1;
    for (let i = 0; i < n; i += len) {
      let w = 1n;
      for (let j = 0; j < half; j++) {
        const u = values[i + j];
        const v = (values[i + j + half] * w) % mod;
        values[i + j] = (u + v) % mod;
        values[i + j + half] = (u - v + mod) % mod;
        w = (w * wlen) % mod;
      }
    }
  }

  if (inverse) {
    const nInv = modInv(BigInt(n), mod);
    for (let i = 0; i < n; i++) values[i] = (values[i] * nInv) % mod;
  }
}
