/**
 * Opt-in Content-Security-Policy header (M3.4, gate 4).
 *
 * The wallet bundle is dependency-free and needs no inline scripts, so the
 * default policy is deny-ish with neither `unsafe-inline` nor `unsafe-eval`.
 * Emission is opt-in: services that never serve documents must stay
 * byte-identical unless they configure a policy.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { HttpApp, createLogger, defaultContentSecurityPolicy } from "../src/index.js";

describe("Content-Security-Policy (opt-in)", () => {
  let open: HttpApp;
  let openBase: string;
  let locked: HttpApp;
  let lockedBase: string;

  beforeAll(async () => {
    open = new HttpApp({ port: 0, logger: createLogger("csp-open"), allowedOrigins: ["*"] });
    open.get("/", () => ({ ok: true }), { raw: true });
    open.get("/v1/health", () => ({ status: "healthy" }), { raw: true });
    openBase = `http://127.0.0.1:${await open.listen()}`;

    locked = new HttpApp({
      port: 0,
      logger: createLogger("csp-locked"),
      allowedOrigins: ["*"],
      contentSecurityPolicy: defaultContentSecurityPolicy(),
    });
    locked.get("/", () => ({ ok: true }), { raw: true });
    locked.get("/v1/health", () => ({ status: "healthy" }), { raw: true });
    lockedBase = `http://127.0.0.1:${await locked.listen()}`;
  });

  afterAll(async () => {
    await open.close();
    await locked.close();
  });

  it("emits no CSP header by default", async () => {
    for (const path of ["/", "/v1/health"]) {
      const res = await fetch(`${openBase}${path}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-security-policy")).toBeNull();
    }
  });

  it("emits the configured policy on document, API and error responses", async () => {
    const expected = defaultContentSecurityPolicy();
    for (const path of ["/", "/v1/health", "/v1/does-not-exist"]) {
      const res = await fetch(`${lockedBase}${path}`);
      expect(res.headers.get("content-security-policy")).toBe(expected);
    }
    expect((await fetch(`${lockedBase}/v1/does-not-exist`)).status).toBe(404);
  });

  it("emits the policy on preflight responses", async () => {
    const res = await fetch(`${lockedBase}/v1/health`, { method: "OPTIONS" });
    expect(res.status).toBe(204);
    expect(res.headers.get("content-security-policy")).toBe(defaultContentSecurityPolicy());
  });

  it("emits nothing when explicitly disabled with false", async () => {
    const app = new HttpApp({
      port: 0,
      logger: createLogger("csp-off"),
      allowedOrigins: ["*"],
      contentSecurityPolicy: false,
    });
    app.get("/v1/health", () => ({ status: "healthy" }), { raw: true });
    const base = `http://127.0.0.1:${await app.listen()}`;
    try {
      const res = await fetch(`${base}/v1/health`);
      expect(res.headers.get("content-security-policy")).toBeNull();
    } finally {
      await app.close();
    }
  });

  it("default policy is deny-ish with no inline scripting", () => {
    const policy = defaultContentSecurityPolicy();
    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("script-src 'self'");
    expect(policy).toContain("object-src 'none'");
    expect(policy).toContain("frame-ancestors 'none'");
    expect(policy).not.toContain("unsafe-inline");
    expect(policy).not.toContain("unsafe-eval");
  });
});
