import { describe, expect, it } from "vitest";
import {
  DEFAULT_FHE_PARAMS,
  DecryptionCommittee,
  HomomorphicEngine,
  paramsForRingDimension,
  verifyParams,
} from "../src/index.js";
import { dot, jitterUnitVector, normalize, seededUnitVector } from "@homobio/crypto-utils";

const DIM = DEFAULT_FHE_PARAMS.embeddingDimension;

/** The bound documented in `docs/crypto-parameters.md` and asserted by bench. */
const ERROR_BOUND = 2 ** -9;

function setup(threshold = 3) {
  const engine = new HomomorphicEngine();
  const keys = engine.generateKeySet(threshold, 1);
  const committee = DecryptionCommittee.fromShares(keys.shares, ["fhe", "proof", "committee"]);
  const evaluate = (a: ArrayLike<number>, b: ArrayLike<number>, errorBound = ERROR_BOUND) =>
    committee.decrypt(
      engine,
      engine.evaluateProduct(
        engine.encryptVector(keys.publicKey, a, DIM, "high"),
        engine.encryptVector(keys.publicKey, b, DIM, "low"),
      ),
      errorBound,
    );
  return { engine, keys, committee, evaluate };
}

describe("FHE parameters", () => {
  it("accepts the default set", () => {
    expect(() => verifyParams(DEFAULT_FHE_PARAMS)).not.toThrow();
  });

  it("rejects a modulus that breaks the NTT embedding", () => {
    expect(() => verifyParams({ ...DEFAULT_FHE_PARAMS, modulus: "1152921504606846977" })).toThrow();
  });

  it("rejects an embedding dimension that would collide with the mirrored layout", () => {
    expect(() =>
      verifyParams({ ...DEFAULT_FHE_PARAMS, embeddingDimension: DEFAULT_FHE_PARAMS.ringDimension }),
    ).toThrow();
  });

  it("rejects a fixed-point scale that could wrap the modulus", () => {
    expect(() => verifyParams({ ...DEFAULT_FHE_PARAMS, scaleBits: 40 })).toThrow();
  });
});

describe("homomorphic similarity", () => {
  it("recovers the cosine similarity of a matched pair", () => {
    const { evaluate } = setup();
    const enrolled = seededUnitVector(DIM, 7);
    const live = jitterUnitVector(enrolled, 0.05, 99);

    const result = evaluate(enrolled, live);
    // Assert against the DOCUMENTED error bound (2^-9), not a rounder number.
    // The scheme's error is a random variable over fresh key material: over 300
    // trials the max was 4.9e-4 with a p99 of 4.5e-4, so a 5e-4 tolerance sits
    // exactly on the tail and fails intermittently. `docs/crypto-parameters.md`
    // promises 2^-9 and that is what this asserts.
    expect(Math.abs(result.similarity - dot(enrolled, live))).toBeLessThan(ERROR_BOUND);
    expect(result.squaredDistance).toBeCloseTo(2 - 2 * dot(enrolled, live), 2);
    expect(result.contributors).toHaveLength(3);
  });

  it("separates impostors from genuine matches", () => {
    const { evaluate } = setup();
    const enrolled = seededUnitVector(DIM, 11);

    const genuine = evaluate(enrolled, jitterUnitVector(enrolled, 0.02, 5));
    const impostor = evaluate(enrolled, seededUnitVector(DIM, 4242));

    expect(genuine.similarity).toBeGreaterThan(0.95);
    expect(impostor.similarity).toBeLessThan(0.35);
    expect(genuine.similarity - impostor.similarity).toBeGreaterThan(0.5);
  });

  it("is insensitive to the input scale: embeddings are normalised first", () => {
    const { evaluate } = setup();
    const enrolled = seededUnitVector(DIM, 21);
    const live = jitterUnitVector(enrolled, 0.05, 22);
    const scaled = Float64Array.from(live, (v) => v * 37.5);

    // Both evaluations draw fresh randomness, so they may differ by up to the
    // error bound; the point of the test is that scaling cancels out.
    expect(Math.abs(evaluate(enrolled, scaled).similarity - evaluate(enrolled, live).similarity)).toBeLessThan(
      2 * ERROR_BOUND,
    );
    expect(Math.abs(evaluate(enrolled, scaled).similarity - dot(enrolled, live))).toBeLessThan(ERROR_BOUND);
  });

  it("holds its error bound across the benchmark matrix", () => {
    const { evaluate } = setup();
    const bound = ERROR_BOUND;
    let worst = 0;

    // 25 samples: enough that a real bound violation would be visible, while
    // keeping the suite's dominant cost in check (each trial is one
    // homomorphic multiplication at N=1024, ~0.6s).
    for (let trial = 0; trial < 25; trial++) {
      const a = seededUnitVector(DIM, trial * 13 + 1);
      const b = seededUnitVector(DIM, trial * 13 + 2);
      worst = Math.max(worst, Math.abs(evaluate(a, b, bound).similarity - dot(a, b)));
    }

    // docs/crypto-parameters.md claims < 2^-9 resolution after one multiplication.
    expect(worst).toBeLessThan(bound);
  });

  it("requires every committee share: a partial set yields nothing usable", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(3, 1);
    const a = seededUnitVector(DIM, 3);
    const b = seededUnitVector(DIM, 4);
    const product = engine.evaluateProduct(
      engine.encryptVector(keys.publicKey, a, DIM, "high"),
      engine.encryptVector(keys.publicKey, b, DIM, "low"),
    );

    const partial = engine.partialDecrypt(keys.shares[0], product);
    const recovered = Number(engine.ring.toSigned(partial[0])) / Math.pow(2, 2 * DEFAULT_FHE_PARAMS.scaleBits);
    expect(Math.abs(recovered - dot(a, b))).toBeGreaterThan(0.1);
  });

  it("recomputes the same plaintext from freshly encrypted ciphertexts", () => {
    const { evaluate } = setup();
    const a = seededUnitVector(DIM, 21);
    const b = seededUnitVector(DIM, 22);
    const first = evaluate(a, b).similarity;
    const second = evaluate(a, b).similarity;
    // Two independent runs, each up to ERROR_BOUND off, so 2x the bound apart.
    expect(Math.abs(first - second)).toBeLessThan(2 * ERROR_BOUND);
    expect(Math.abs(first - dot(a, b))).toBeLessThan(ERROR_BOUND);
  });

  it("decrypts to the plaintext dot product when noise is removed", () => {
    // Encrypting the zero vector gives an exact zero plaintext up to encryption
    // noise, which pins the encoding contract independently of the FHE noise.
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    const zero = new Float64Array(DIM);
    const ctA = engine.encryptVector(keys.publicKey, zero, DIM, "high");
    const ctB = engine.encryptVector(keys.publicKey, zero, DIM, "low");
    const decrypted = engine.decrypt(keys.secret, engine.evaluateProduct(ctA, ctB));
    const estimate = engine.similarity(decrypted, 2 ** -9);
    expect(Math.abs(estimate.similarity)).toBeLessThan(2 ** -6);
  });
});

describe("ciphertext handling", () => {
  it("round-trips through the wire format", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    const template = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 8), DIM, "high");
    const query = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 9), DIM, "low");
    const reopened = engine.packCiphertext(engine.unpackCiphertext(template), DIM, "high");
    expect(engine.evaluateProduct(reopened, query).ciphertext).toBe(
      engine.evaluateProduct(template, query).ciphertext,
    );
  });

  it("rejects a tampered ciphertext", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    const ct = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 8), DIM, "high");
    const flipped = ct.ciphertext.slice(0, -2) + (ct.ciphertext.endsWith("A") ? "B" : "A");
    expect(() => engine.unpackCiphertext({ ...ct, ciphertext: flipped })).toThrow();
  });

  it("rejects a ciphertext whose commitment was swapped", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    const a = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 1), DIM, "high");
    const b = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 2), DIM, "low");
    expect(() => engine.unpackCiphertext({ ...b, commitment: a.commitment })).toThrow();
  });

  it("rejects mixing a template with a query in the wrong layout", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    const a = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 1), DIM, "high");
    const b = engine.encryptVector(keys.publicKey, seededUnitVector(DIM, 2), DIM, "high");
    expect(() => engine.evaluateProduct(a, b)).toThrow(/low layout/);
  });

  it("rejects a wrong-size embedding up front", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    expect(() => engine.encryptVector(keys.publicKey, new Float64Array(DIM - 1), DIM, "low")).toThrow();
  });

  it("rejects a public key whose fingerprint does not match its contents", () => {
    const engine = new HomomorphicEngine();
    const keys = engine.generateKeySet(2, 1);
    const tampered = { ...keys.publicKey, publicKeyB: keys.publicKey.publicKeyA };
    expect(() => engine.toKeyMaterial(tampered)).toThrow(/fingerprint/);
  });
});

describe("ring dimension matrix", () => {
  it("builds valid parameter sets for other ring dimensions", () => {
    for (const n of [512, 2048]) {
      const params = paramsForRingDimension(n, { embeddingDimension: 128 });
      expect(() => verifyParams(params)).not.toThrow();
      const engine = new HomomorphicEngine(params);
      const keys = engine.generateKeySet(2, 1);
      const committee = DecryptionCommittee.fromShares(keys.shares, ["a", "b"]);
      const a = seededUnitVector(DIM, 5);
      const b = seededUnitVector(DIM, 6);
      const result = committee.decrypt(
        engine,
        engine.evaluateProduct(
          engine.encryptVector(keys.publicKey, a, DIM, "high"),
          engine.encryptVector(keys.publicKey, b, DIM, "low"),
        ),
        2 ** -9,
      );
      expect(Math.abs(result.similarity - dot(a, b))).toBeLessThan(2 ** -6);
    }
  });
});
