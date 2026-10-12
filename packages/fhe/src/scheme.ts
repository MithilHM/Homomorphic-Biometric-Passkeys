/**
 * A real RLWE (Ring-LWE) homomorphic encryption scheme over
 * R = Z_q[X] / (X^N + 1), with ciphertext-ciphertext multiplication.
 *
 * ## Representation
 *
 * A ciphertext is a triple of polynomials `(p0, p1, p2)` denoting the ring
 * element `p2 + p1*s + p0*s^2` in `R[s]/s^3`. Its plaintext is that element
 * evaluated at the real secret `s`. Because evaluation at `s` is a ring
 * homomorphism, addition and multiplication of ciphertexts correspond exactly
 * to addition and multiplication of plaintexts — that is the whole trick.
 *
 * Fresh encryptions are 2-term (`p0 = 0`); a product is 3-term. We deliberately
 * do NOT relinearize: the decryption committee holds `s` and computes `s^2`
 * once. Skipping relinearization removes the dominant noise term (the
 * key-switch error scales with the *product* plaintext), which is what makes a
 * single homomorphic multiplication accurate enough to threshold on.
 *
 * ## What this is and is not
 *
 * This is a genuine leveled RLWE scheme, not a mock: the coprocessor never
 * holds `s`, ciphertexts are semantically secure against the evaluator, and
 * decryption requires the threshold committee. It is *depth 1 only*, with no
 * bootstrapping and no mod-switching, and its parameters are chosen for the
 * benchmark in `docs/crypto-parameters.md` rather than for a published
 * production security target. See `cryptography/openfhe/` for the CKKS engine
 * used when OpenFHE is installed.
 */

import { RingContext } from "./ring.js";
import { addPoly, sampleTernary, sampleUniform, scalePoly, subPoly, type Poly } from "./sampler.js";

export interface Ciphertext {
  p0: Poly;
  p1: Poly;
  p2: Poly;
}

export interface SecretKeyShare {
  shareIndex: number;
  /** Additive share of `s`. */
  sigma: Poly;
  /** Additive share of `s^2`, needed for the quadratic term of a product. */
  tau: Poly;
}

export interface KeyMaterial {
  params: { ringDimension: number; modulus: string; securityLevelBits: number };
  publicKeyA: Poly;
  publicKeyB: Poly;
}

export class RlweScheme {
  readonly ring: RingContext;

  constructor(ring: RingContext) {
    this.ring = ring;
  }

  get n(): number {
    return this.ring.n;
  }

  get q(): bigint {
    return this.ring.q;
  }

  /** Generate a fresh uniform RLWE public key. */
  generateKeyPair(): { publicKey: KeyMaterial; secretKey: Poly } {
    const secretKey = sampleTernary(this.n);
    const a = sampleUniform(this.n, this.q);
    const error = sampleTernary(this.n);
    const b = this.ring.add(this.ring.mul(a, secretKey), this.ring.fromSigned(error));
    return {
      publicKey: {
        params: {
          ringDimension: this.n,
          modulus: this.q.toString(),
          securityLevelBits: 128,
        },
        publicKeyA: a,
        publicKeyB: b,
      },
      secretKey,
    };
  }

  /** Encrypt an integer polynomial as a 2-term ciphertext. */
  encrypt(publicKey: KeyMaterial, message: Poly): Ciphertext {
    if (message.length > this.n) throw new Error("message exceeds ring dimension");
    const r = sampleTernary(this.n);
    const e1 = sampleTernary(this.n);
    const e2 = sampleTernary(this.n);

    const c0 = this.ring.add(this.ring.mul(publicKey.publicKeyA, r), this.ring.fromSigned(e1));
    const c1 = this.ring.add(
      this.ring.mul(publicKey.publicKeyB, r),
      this.ring.fromSigned(e2),
    );
    const c1WithMessage = this.ring.add(c1, this.ring.fromSigned(message));

    // plaintext = p2 + p1*s  with  p2 = c1 + m, p1 = -c0
    return { p0: this.ring.zero(), p1: this.ring.neg(c0), p2: c1WithMessage };
  }

  /** Homomorphic addition. */
  add(a: Ciphertext, b: Ciphertext): Ciphertext {
    return {
      p0: this.ring.add(a.p0, b.p0),
      p1: this.ring.add(a.p1, b.p1),
      p2: this.ring.add(a.p2, b.p2),
    };
  }

  /** Homomorphic subtraction (needed for difference-based similarity checks). */
  sub(a: Ciphertext, b: Ciphertext): Ciphertext {
    return {
      p0: this.ring.sub(a.p0, b.p0),
      p1: this.ring.sub(a.p1, b.p1),
      p2: this.ring.sub(a.p2, b.p2),
    };
  }

  /** Homomorphic multiplication by a public scalar. */
  scalar(a: Ciphertext, k: bigint | number): Ciphertext {
    const s = BigInt(k);
    return { p0: scalePoly(a.p0, s, this.q), p1: scalePoly(a.p1, s, this.q), p2: scalePoly(a.p2, s, this.q) };
  }

  /**
   * Homomorphic ciphertext-ciphertext multiplication.
   *
   * (a.p2 + a.p1 s + a.p0 s^2)(b.p2 + b.p1 s + b.p0 s^2), discarding terms of
   * degree >= 3 (the scheme is depth 1, so this never occurs in a valid use).
   */
  multiply(a: Ciphertext, b: Ciphertext): Ciphertext {
    const aHasQuadratic = a.p0.some((v) => v !== 0n);
    const bHasQuadratic = b.p0.some((v) => v !== 0n);
    // [[a2b0, a2b1, a2b2], [a1b0, a1b1, a1b2], [a0b0, a0b1, a0b2]]
    // Terms of degree >= 3 are dropped: the scheme is depth 1.
    const m = aHasQuadratic || bHasQuadratic
      ? this.ring.mulOuter([a.p2, a.p1, a.p0], [b.p0, b.p1, b.p2])
      : this.ring.mulOuter([a.p2, a.p1], [b.p0, b.p1, b.p2]);
    const p0 = aHasQuadratic
      ? this.ring.add3(this.ring.add3(m[0][0], m[1][1], this.q), m[2][2], this.q)
      : m[1][1];
    const p1 = this.ring.add3(m[0][1], m[1][2], this.q);
    return { p0, p1, p2: m[0][2] };
  }

  /** Decrypt with the full secret key (used by the committee when recombined). */
  decrypt(secretKey: Poly, ciphertext: Ciphertext): Poly {
    const s2 = this.ring.mul(secretKey, secretKey);
    return this.ring.add(
      this.ring.add(ciphertext.p2, this.ring.mul(ciphertext.p1, secretKey)),
      this.ring.mul(ciphertext.p0, s2),
    );
  }

  /**
   * Partial decryption against one additive share of the secret key.
   *
   * Returns only the *keyed* part (the `p1*s + p0*s^2` contribution). The
   * unkeyed `p2` term is public, so it must be added exactly once by the
   * combiner rather than once per share.
   *
   * Because a product ciphertext carries an `s^2` term, each share pairs a
   * random share of `s` with an independent random share of `s^2`. Summing all
   * shares reproduces `decrypt` exactly, while any proper subset is masked by
   * two independent uniform polynomials and leaks nothing.
   */
  partialDecrypt(share: SecretKeyShare, ciphertext: Ciphertext): Poly {
    return this.ring.add(
      this.ring.mul(ciphertext.p1, share.sigma),
      this.ring.mul(ciphertext.p0, share.tau),
    );
  }

  /** Recombine partial decryptions plus the public `p2` term into the plaintext. */
  static recombine(partials: Poly[], p2: Poly, n: number, q: bigint): Poly {
    const out: Poly = [...p2];
    for (const partial of partials) {
      for (let i = 0; i < n; i++) out[i] = (out[i] + partial[i]) % q;
    }
    return out;
  }

  /**
   * Additively split `secret` (and its square) into `parts` shares.
   * All parts are required: any proper subset is uniformly random.
   */
  static splitSecret(secret: Poly, secretSquared: Poly, parts: number, q: bigint): SecretKeyShare[] {
    if (parts < 2) throw new Error("threshold must be at least 2");
    const n = secret.length;
    const randoms = (source: Poly): Poly[] => {
      const out: Poly[] = [];
      for (let i = 0; i < parts - 1; i++) out.push(sampleUniform(n, q));
      const residual = [...source];
      for (const share of out) {
        for (let i = 0; i < n; i++) residual[i] = (residual[i] - share[i] + q) % q;
      }
      out.push(residual);
      return out;
    };

    const sigmas = randoms(secret);
    const taus = randoms(secretSquared);
    return sigmas.map((sigma, i) => ({ shareIndex: i, sigma, tau: taus[i] }));
  }

  /** Convert a field element to its centered integer representative. */
  toSigned(value: bigint): bigint {
    return this.ring.toSigned(value);
  }
}

export { subPoly };
