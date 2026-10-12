/**
 * FHE parameter benchmark (PRD section 11).
 *
 * Sweeps ring dimension x fixed-point scale x embedding size and records the
 * numbers the PRD requires: latency, ciphertext size, numerical error and the
 * false-accept / false-reject behaviour at the resulting precision.
 *
 * Run with: npm run bench
 */

import {
  DecryptionCommittee,
  HomomorphicEngine,
  paramsForRingDimension,
  verifyParams,
} from "@homobio/fhe";
import { dot, jitterUnitVector, normalize, seededUnitVector } from "@homobio/crypto-utils";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

interface Row {
  ringDimension: number;
  scaleBits: number;
  dimension: number;
  threshold: number;
  encryptMs: number;
  evaluateMs: number;
  decryptMs: number;
  ciphertextBytes: number;
  productBytes: number;
  maxError: number;
  falseAccept: number;
  falseReject: number;
}

const TRIALS = 24;
const IMPOSTOR_TRIALS = 24;
const THRESHOLD = 0.7;

async function run(): Promise<void> {
  console.log("FHE parameter benchmark");
  console.log("=======================");
  console.log(`trials: ${TRIALS} genuine, ${IMPOSTOR_TRIALS} impostor per configuration\n`);
  console.log(
    "ringDim  scale  dim   thr   enc(ms)  eval(ms)  dec(ms)  ct(B)  prod(B)  maxErr     FA     FR",
  );

  const rows: Row[] = [];

  for (const ringDimension of [1024, 2048, 4096]) {
    for (const scaleBits of [16, 18, 20]) {
      const dimension = 128;
      const params = paramsForRingDimension(ringDimension, { scaleBits, embeddingDimension: dimension });
      try {
        verifyParams(params);
      } catch {
        console.log(`skip ${ringDimension}/${scaleBits}: ${"invalid parameters"}`);
        continue;
      }

      const engine = new HomomorphicEngine(params);
      const keys = engine.generateKeySet(2, 1);
      const committee = DecryptionCommittee.fromShares(keys.shares, ["a", "b"]);

      let maxError = 0;
      let falseAccept = 0;
      let falseReject = 0;
      let encryptMs = 0;
      let evaluateMs = 0;
      let decryptMs = 0;
      let ciphertextBytes = 0;
      let productBytes = 0;

      for (let trial = 0; trial < TRIALS + IMPOSTOR_TRIALS; trial++) {
        const genuine = trial < TRIALS;
        const enrolled = seededUnitVector(dimension, trial * 17 + 1);
        const live = genuine
          ? jitterUnitVector(enrolled, 0.03 + (trial % 5) * 0.01, trial * 31 + 3)
          : seededUnitVector(dimension, 500_000 + trial * 13);

        const t0 = performance.now();
        const template = engine.encryptVector(keys.publicKey, enrolled, dimension, "high");
        const query = engine.encryptVector(keys.publicKey, live, dimension, "low");
        const t1 = performance.now();
        const product = engine.evaluateProduct(template, query);
        const t2 = performance.now();
        const result = committee.decrypt(engine, product, 2 ** -9);
        const t3 = performance.now();

        const expected = dot(normalize(enrolled), normalize(live));
        const error = Math.abs(result.similarity - expected);
        maxError = Math.max(maxError, error);

        const decided = result.similarity >= THRESHOLD;
        if (genuine && !decided) falseReject++;
        if (!genuine && decided) falseAccept++;

        if (trial === 0) {
          encryptMs = t1 - t0;
          evaluateMs = t2 - t1;
          decryptMs = t3 - t2;
          ciphertextBytes = template.byteLength;
          productBytes = product.byteLength;
        } else {
          encryptMs += t1 - t0;
          evaluateMs += t2 - t1;
          decryptMs += t3 - t2;
        }
      }

      const total = TRIALS + IMPOSTOR_TRIALS;
      const row: Row = {
        ringDimension,
        scaleBits,
        dimension,
        threshold: THRESHOLD,
        encryptMs: encryptMs / total,
        evaluateMs: evaluateMs / total,
        decryptMs: decryptMs / total,
        ciphertextBytes,
        productBytes,
        maxError,
        falseAccept: falseAccept / IMPOSTOR_TRIALS,
        falseReject: falseReject / TRIALS,
      };
      rows.push(row);

      console.log(
        `${String(ringDimension).padStart(7)}  ${String(scaleBits).padStart(5)}  ${String(dimension).padStart(3)}  ` +
          `${THRESHOLD.toFixed(2)}  ${row.encryptMs.toFixed(1).padStart(7)}  ${row.evaluateMs.toFixed(1).padStart(8)}  ` +
          `${row.decryptMs.toFixed(1).padStart(7)}  ${String(ciphertextBytes).padStart(5)}  ${String(productBytes).padStart(7)}  ` +
          `${maxError.toExponential(2).padStart(9)}  ${(row.falseAccept * 100).toFixed(1).padStart(5)}%  ${(row.falseReject * 100).toFixed(1).padStart(5)}%`,
      );
    }
  }

  const outputDir = path.resolve(process.cwd(), "docs/benchmarks");
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(path.join(outputDir, "fhe-parameters.json"), JSON.stringify(rows, null, 2));

  const best = rows
    .filter((r) => r.falseAccept === 0 && r.falseReject === 0)
    .sort((a, b) => a.maxError - b.maxError)[0];
  console.log("\nresults written to docs/benchmarks/fhe-parameters.json");
  if (best) {
    console.log(
      `recommended (by measured accuracy): ring ${best.ringDimension}, scale 2^${best.scaleBits}, ` +
        `max error ${best.maxError.toExponential(2)}`,
    );
  }
}

await run();
