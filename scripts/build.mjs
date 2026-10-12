// Bundles the web client and the services with esbuild.
// Usage: node scripts/build.mjs [web|services|all]

import { build } from "esbuild";
import { existsSync, mkdirSync, cpSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const target = process.argv[2] ?? "all";

async function buildWeb() {
  const outDir = path.join(root, "apps/web/dist");
  mkdirSync(outDir, { recursive: true });

  await build({
    entryPoints: [path.join(root, "apps/web/src/main.ts")],
    bundle: true,
    format: "esm",
    target: ["es2022"],
    platform: "browser",
    outfile: path.join(outDir, "app.js"),
    sourcemap: true,
    minify: true,
    legalComments: "none",
    logLevel: "info",
  });

  cpSync(path.join(root, "apps/web/public"), outDir, { recursive: true });
  console.log(`web client -> ${path.relative(root, outDir)}`);
}

async function buildServices() {
  const outDir = path.join(root, "dist/services");
  if (existsSync(outDir)) rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const entries = [
    ["services/api-gateway/src/main.ts", "api-gateway.mjs"],
    ["services/fhe-service/src/main.ts", "fhe-service.mjs"],
  ];

  for (const [entry, outfile] of entries) {
    await build({
      entryPoints: [path.join(root, entry)],
      bundle: true,
      format: "esm",
      platform: "node",
      target: ["node20"],
      outfile: path.join(outDir, outfile),
      sourcemap: true,
      minify: false,
      // esbuild is a BUILD-time tool. `static.ts` imports it lazily so that
      // `npm run dev` can build the web client on first run; bundling it would
      // drag a native binary and ~2MB of loader into the production image.
      // It stays external, and in a container the pre-built bundle means the
      // import never executes — `ensureWebBundle` returns early.
      external: ["esbuild"],
      banner: { js: "import{createRequire as __cr}from'node:module';const require=__cr(import.meta.url);" },
      logLevel: "info",
    });
    console.log(`service ${entry} -> dist/services/${outfile}`);
  }
}

if (target === "web" || target === "all") await buildWeb();
if (target === "services" || target === "all") await buildServices();
