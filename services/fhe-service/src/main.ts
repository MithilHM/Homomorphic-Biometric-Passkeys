/**
 * FHE coprocessor process entry point.
 *
 * Runs as a separate process with its own service token, so the API gateway can
 * only reach it over an authenticated local channel. It holds exactly one of
 * the three decryption shares.
 */

import path from "node:path";
import { JsonStore, type StoredRecord } from "@homobio/store";
import { createLogger } from "@homobio/http-kit";
import { FheCoprocessor, createCoprocessorApp, type TemplateRecord } from "./coprocessor.js";

const DATA_DIR = process.env.HOMOBIO_DATA_DIR ?? path.resolve(process.cwd(), ".data");
const PORT = Number(process.env.FHE_PORT ?? 5001);
const SERVICE_TOKEN = process.env.FHE_SERVICE_TOKEN ?? "dev-fhe-token";
const CHAIN_ID = Number(process.env.CHAIN_ID ?? 143);
const ERROR_BOUND = Number(process.env.FHE_ERROR_BOUND ?? 2 ** -9);

const logger = createLogger("fhe-service");
const templates = new JsonStore<TemplateRecord & StoredRecord>({
  directory: path.join(DATA_DIR, "fhe"),
  fileName: "templates.json",
});

const coprocessor = new FheCoprocessor(
  { port: PORT, dataDir: DATA_DIR, serviceToken: SERVICE_TOKEN, errorBound: ERROR_BOUND, chainId: CHAIN_ID },
  templates,
);

const publicKeyPath = path.join(DATA_DIR, "fhe", "public-key.json");
const localSharePath = path.join(DATA_DIR, "fhe", "share-0.json");

let bootstrapped = false;
try {
  if (process.env.FHE_REUSE_KEYS === "true") {
    coprocessor.load(publicKeyPath, localSharePath);
    bootstrapped = true;
    logger.info("reusing existing FHE key set");
  }
} catch {
  bootstrapped = false;
}

if (!bootstrapped) {
  const { publicKey } = coprocessor.bootstrap({
    proof: path.join(DATA_DIR, "committee", "share-1-proof.json"),
    custody: path.join(DATA_DIR, "committee", "share-2-custody.json"),
  });
  // Persist the public bundle plus this process's own share so a restart can
  // resume without regenerating keys (templates are encrypted under them).
  const fs = await import("node:fs");
  fs.mkdirSync(path.join(DATA_DIR, "fhe"), { recursive: true });
  fs.writeFileSync(publicKeyPath, JSON.stringify(publicKey, null, 2), "utf-8");
}

const app = createCoprocessorApp(coprocessor, {
  port: PORT,
  dataDir: DATA_DIR,
  serviceToken: SERVICE_TOKEN,
  errorBound: ERROR_BOUND,
  chainId: CHAIN_ID,
});

const port = await app.listen();
logger.info("FHE coprocessor ready", { port, chainId: CHAIN_ID, errorBound: ERROR_BOUND });

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void (async () => {
      await templates.settled();
      await app.close();
      process.exit(0);
    })();
  });
}
