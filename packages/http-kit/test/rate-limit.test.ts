/**
 * Scoped rate limiters.
 *
 * Regression test: named limiters used to burn a token on EVERY request,
 * regardless of route — 20-odd health checks, config fetches and static files
 * exhausted the `verify` (20/min) and `challenge` (30/min) buckets and users
 * got `rate_limited` without ever issuing that many challenges. A limiter
 * with `paths` must only count requests under those prefixes.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HttpApp, createLogger } from "../src/index.js";

describe("scoped rate limiters", () => {
  let app: HttpApp;
  let base: string;

  beforeAll(async () => {
    app = new HttpApp({ port: 0, logger: createLogger("ratelimit-test"), allowedOrigins: [] });
    app.useRateLimit("challenge", { limit: 2, windowMs: 60_000, paths: ["/v1/auth/challenge"] });
    app.post("/v1/auth/challenge", () => ({ challenge: "x" }), { raw: true });
    app.get("/v1/health", () => ({ status: "healthy" }), { raw: true });
    const port = await app.listen();
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it("does not burn challenge quota on unrelated routes", async () => {
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${base}/v1/health`);
      expect(res.status).toBe(200);
    }
    const res = await fetch(`${base}/v1/auth/challenge`, { method: "POST" });
    expect(res.status).toBe(200);
  });

  it("still limits the scoped route", async () => {
    // One challenge already issued above (limit 2); one more is allowed…
    expect((await fetch(`${base}/v1/auth/challenge`, { method: "POST" })).status).toBe(200);
    // …the third within the window is rejected.
    const limited = await fetch(`${base}/v1/auth/challenge`, { method: "POST" });
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ error: "rate_limited" });
  });
});
