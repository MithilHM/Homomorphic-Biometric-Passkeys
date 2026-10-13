/**
 * Static client serving.
 *
 * Regression tests for the browser's "Refused to apply style" failure: the
 * gateway served `/app.js` but had no route for `/app.css`, so the request
 * fell through to the API 404 handler and came back as `application/json`.
 * Every file the client references must be served with its real MIME type,
 * while anything that is not a client asset must stay unreachable.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { HttpApp, createLogger } from "../../packages/http-kit/src/index.js";
import { serveStatic } from "../api-gateway/src/static.js";

describe("static client routes", () => {
  let app: HttpApp;
  let base: string;
  let dir: string;

  beforeAll(async () => {
    dir = mkdtempSync(path.join(tmpdir(), "homobio-static-"));
    writeFileSync(path.join(dir, "index.html"), "<!doctype html><html></html>");
    writeFileSync(path.join(dir, "app.js"), "console.log(1);");
    writeFileSync(path.join(dir, "app.css"), "body{}");
    writeFileSync(path.join(dir, "app.js.map"), "{}");
    writeFileSync(path.join(dir, "secret.env"), "CUSTODY_UNLOCK_SECRET=x");
    mkdirSync(path.join(dir, "nested"));
    writeFileSync(path.join(dir, "nested", "app.css"), "body{}");

    app = new HttpApp({ port: 0, logger: createLogger("static-test"), allowedOrigins: ["*"] });
    // An API route registered first, mirroring production order: the generic
    // static route must never shadow it.
    app.get("/v1/health", () => ({ status: "healthy" }), { raw: true });
    serveStatic(app, dir, createLogger("static-test"));
    const port = await app.listen();
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await app.close();
  });

  it("serves the stylesheet as CSS, not JSON", async () => {
    const response = await fetch(`${base}/app.css`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/css");
    expect(await response.text()).toBe("body{}");
  });

  it("serves the bundle as JavaScript", async () => {
    const response = await fetch(`${base}/app.js`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/javascript");
  });

  it("serves the index page at /", async () => {
    const response = await fetch(`${base}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
  });

  it("does not shadow API routes registered before it", async () => {
    const response = await fetch(`${base}/v1/health`);
    expect(response.status).toBe(200);
  });

  it("refuses files with non-static extensions", async () => {
    const response = await fetch(`${base}/secret.env`);
    expect(response.status).toBe(404);
  });

  it("refuses extensionless paths", async () => {
    const response = await fetch(`${base}/secret`);
    expect(response.status).toBe(404);
  });

  it("refuses parent traversal", async () => {
    const response = await fetch(`${base}/..%2Fsecret.env`);
    expect(response.status).toBe(404);
  });

  it("returns 404 for a missing asset instead of the API error envelope", async () => {
    const response = await fetch(`${base}/missing.css`);
    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("text/plain");
  });
});
