/**
 * CORS boundary for the gateway.
 *
 * Regression test for the landing-page failure: a page served from
 * http://localhost:5173 fetched /v1/health and /v1/config and the browser
 * rejected both responses with "no Access-Control-Allow-Origin header", even
 * though the gateway answered 200. The old http-kit validated `Origin`
 * against the allowlist but never emitted ACAO/Vary and had no OPTIONS
 * preflight handler, so every browser read was blocked.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HttpApp, createLogger } from "../src/index.js";

const GATEWAY_ORIGIN = "http://localhost:5000";
const LANDING_ORIGIN = "http://localhost:5173";
const EVIL_ORIGIN = "http://evil.test";

describe("CORS allowlist", () => {
  let app: HttpApp;
  let base: string;

  beforeAll(async () => {
    // Mirrors services/api-gateway/src/main.ts parsing of comma-separated
    // ALLOWED_ORIGINS into the allowlist passed through to HttpApp.
    const parsed = `${GATEWAY_ORIGIN},${LANDING_ORIGIN}`.split(",").map((s) => s.trim()).filter(Boolean);
    app = new HttpApp({ port: 0, logger: createLogger("cors-test"), allowedOrigins: parsed });
    app.get("/v1/health", () => ({ status: "healthy" }), { raw: true });
    app.get("/v1/config", () => ({ chainId: 143 }), { raw: true });
    const port = await app.listen();
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it("emits ACAO + Vary: Origin for an allowlisted origin on GET", async () => {
    for (const path of ["/v1/health", "/v1/config"]) {
      const res = await fetch(`${base}${path}`, { headers: { Origin: LANDING_ORIGIN } });
      expect(res.status).toBe(200);
      expect(res.headers.get("access-control-allow-origin")).toBe(LANDING_ORIGIN);
      expect(res.headers.get("vary")).toContain("Origin");
    }
  });

  it("echoes the exact requesting origin, never a wildcard or a fixed one", async () => {
    const res = await fetch(`${base}/v1/health`, { headers: { Origin: GATEWAY_ORIGIN } });
    expect(res.headers.get("access-control-allow-origin")).toBe(GATEWAY_ORIGIN);
    expect(res.headers.get("access-control-allow-origin")).not.toBe("*");
  });

  it("rejects a non-allowlisted origin with 403 and no ACAO header", async () => {
    const res = await fetch(`${base}/v1/health`, { headers: { Origin: EVIL_ORIGIN } });
    expect(res.status).toBe(403);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(await res.json()).toMatchObject({ error: "origin_not_allowed" });
  });

  it("answers preflight with 204 + CORS headers for an allowlisted origin", async () => {
    const res = await fetch(`${base}/v1/health`, {
      method: "OPTIONS",
      headers: {
        Origin: LANDING_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(LANDING_ORIGIN);
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")).toContain("content-type");
    expect(res.headers.get("access-control-max-age")).not.toBeNull();
  });

  it("rejects preflight from a non-allowlisted origin with no ACAO header", async () => {
    const res = await fetch(`${base}/v1/health`, {
      method: "OPTIONS",
      headers: { Origin: EVIL_ORIGIN, "Access-Control-Request-Method": "GET" },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("leaves non-browser requests (no Origin) alone: 200, no ACAO", async () => {
    const res = await fetch(`${base}/v1/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("keeps ACAO on error responses to allowlisted origins", async () => {
    const res = await fetch(`${base}/v1/does-not-exist`, { headers: { Origin: LANDING_ORIGIN } });
    expect(res.status).toBe(404);
    expect(res.headers.get("access-control-allow-origin")).toBe(LANDING_ORIGIN);
  });
});
