/**
 * Static file serving for the built web client, plus an on-demand bundle build
 * so `npm run dev` works from a clean checkout.
 */

import { createReadStream, existsSync, statSync } from "node:fs";
import path from "node:path";
import type { HttpApp, Logger } from "@homobio/http-kit";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
  ".wasm": "application/wasm",
  ".map": "application/json; charset=utf-8",
};

export async function ensureWebBundle(logger: Logger): Promise<boolean> {
  const outDir = path.resolve(process.cwd(), "apps/web/dist");
  const entry = path.join(outDir, "index.html");
  if (existsSync(entry)) return true;

  logger.info("building the web client bundle (first run)");
  try {
    // esbuild is a devDependency and is external to the service bundle. It is
    // present when running from source, absent in a production image — where
    // the client is pre-built and this branch is never reached. If it is
    // genuinely missing we serve the API only rather than crash-looping.
    const { build } = await import("esbuild");
    await build({
      entryPoints: [path.resolve(process.cwd(), "apps/web/src/main.ts")],
      bundle: true,
      format: "esm",
      target: ["es2022"],
      platform: "browser",
      outfile: path.join(outDir, "app.js"),
      sourcemap: true,
      minify: false,
      logLevel: "warning",
    });

    const { copyFileSync, mkdirSync, readdirSync } = await import("node:fs");
    const publicDir = path.resolve(process.cwd(), "apps/web/public");
    mkdirSync(outDir, { recursive: true });
    if (existsSync(publicDir)) {
      for (const entryName of readdirSync(publicDir)) {
        copyFileSync(path.join(publicDir, entryName), path.join(outDir, entryName));
      }
    }
    logger.info("web client bundle built", { outDir });
    return true;
  } catch (error) {
    logger.error("failed to build the web client; serving the API only", {
      error: String(error),
      hint: "run `npm run build:web` and restart to serve the client",
    });
    return false;
  }
}

export function serveStatic(app: HttpApp, root: string, logger: Logger): void {
  app.get("/", (ctx) => {
    if (!existsSync(path.join(root, "index.html"))) {
      ctx.response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      ctx.response.end(FALLBACK_PAGE);
      return;
    }
    sendFile(ctx.response, path.join(root, "index.html"));
  }, { raw: true });

  app.get("/assets/:name", (ctx) => {
    const file = path.join(root, ctx.params.name);
    if (!file.startsWith(root) || !existsSync(file)) {
      ctx.response.writeHead(404, { "content-type": "text/plain" });
      ctx.response.end("not found");
      return;
    }
    sendFile(ctx.response, file);
  }, { raw: true });

  app.get("/app.js", (ctx) => {
    const file = path.join(root, "app.js");
    if (!existsSync(file)) {
      ctx.response.writeHead(404, { "content-type": "text/plain" });
      ctx.response.end("bundle not built");
      return;
    }
    sendFile(ctx.response, file);
  }, { raw: true });

  logger.info("static client mounted", { root });
}

function sendFile(response: import("node:http").ServerResponse, file: string): void {
  const ext = path.extname(file);
  response.writeHead(200, {
    "content-type": MIME[ext] ?? "application/octet-stream",
    "cache-control": "no-store",
  });
  createReadStream(file).pipe(response);
}

const FALLBACK_PAGE = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Homomorphic Biometric Passkeys</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 3rem auto; max-width: 42rem; line-height: 1.6; }
      code { background: #1118270d; padding: 0.15rem 0.35rem; border-radius: 4px; }
    </style>
  </head>
  <body>
    <h1>API gateway is running</h1>
    <p>The web client bundle was not built. Run <code>npm run build:web</code> and reload.</p>
    <p>API surface: <code>GET /v1/health</code>, <code>GET /v1/config</code>, <code>POST /v1/auth/challenge</code>.</p>
  </body>
</html>`;
