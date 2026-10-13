/**
 * A tiny HTTP micro-framework over `node:http`.
 *
 * Deliberately dependency-free: every byte that runs in the authentication path
 * is code we can read, audit and pin. It provides exactly what the PRD's gateway
 * requirements need — size limits, origin validation, rate limiting, correlation
 * IDs, schema validation and structured redacted logging — and nothing else.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { timingSafeEqual } from "@homobio/crypto-utils";

export interface RequestContext {
  request: IncomingMessage;
  response: ServerResponse;
  params: Record<string, string>;
  query: URLSearchParams;
  body: unknown;
  requestId: string;
  clientIp: string;
  startedAt: number;
}

export type Handler = (ctx: RequestContext) => Promise<unknown> | unknown;

export interface RouteDefinition {
  method: string;
  path: string;
  handler: Handler;
  /** Maximum accepted request body in bytes. Ciphertext payloads need more. */
  maxBodyBytes?: number;
  /** Skip the JSON body parser (health checks, metrics). */
  raw?: boolean;
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export interface Logger {
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

/**
 * Structured logger with an explicit redaction list.
 *
 * PRD section 36: never log embeddings, images, FHE secret keys, WebAuthn
 * private material or decrypted distances. Redaction is enforced here rather
 * than trusted to each call site.
 */
const FORBIDDEN_KEYS = new Set([
  "embedding",
  "embeddings",
  "embeddingVector",
  "image",
  "imageData",
  "frame",
  "pixels",
  "secretKey",
  "fheSecretKey",
  "privateKey",
  "password",
  "distance",
  "plaintextDistance",
  "similarity",
  "template",
  "authorizationHeader",
  "cookie",
]);

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[deep]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return value.length > 512 ? `${value.slice(0, 512)}…` : value;
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (value instanceof Uint8Array) return `[bytes:${value.length}]`;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_KEYS.has(key)) {
        out[key] = "[redacted]";
        continue;
      }
      out[key] = redact(item, depth + 1);
    }
    return out;
  }
  return "[unsupported]";
}

export function createLogger(service: string): Logger {
  const emit = (level: string) => (message: string, fields: Record<string, unknown> = {}) => {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      service,
      message,
      ...(redact(fields) as Record<string, unknown>),
    });
    if (level === "error") process.stderr.write(`${line}\n`);
    else process.stdout.write(`${line}\n`);
  };
  return {
    info: emit("info"),
    warn: emit("warn"),
    error: emit("error"),
  };
}

export interface RateLimitRule {
  /** Requests allowed per window. */
  limit: number;
  windowMs: number;
  /** Optional key extractor; defaults to client IP. */
  key?: (ctx: RequestContext) => string;
  /** Optional path prefixes this limiter applies to. A limiter without paths
   *  applies to every request; one with paths is only checked (and only burns
   *  quota) when the request path starts with one of them. Without this, a
   *  limiter named "challenge" burns a token on every health check, config
   *  fetch and static file — tripping 429s for users who issued few
   *  challenges. */
  paths?: string[];
}

interface Bucket {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly rule: RateLimitRule) {}

  check(key: string): { allowed: boolean; remaining: number; retryAfterSeconds: number } {
    const now = Date.now();
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + this.rule.windowMs });
      return { allowed: true, remaining: this.rule.limit - 1, retryAfterSeconds: 0 };
    }
    bucket.count += 1;
    if (bucket.count > this.rule.limit) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000),
      };
    }
    return { allowed: true, remaining: this.rule.limit - bucket.count, retryAfterSeconds: 0 };
  }

  /** Drop expired buckets so a long-running process does not leak memory. */
  sweep(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) {
        this.buckets.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

export interface ServerOptions {
  port: number;
  host?: string;
  logger: Logger;
  allowedOrigins: string[];
  globalRateLimit?: RateLimitRule;
  defaultMaxBodyBytes?: number;
  serviceAuthToken?: string;
  onRequest?: (ctx: RequestContext, durationMs: number, status: number) => void;
}

const DEFAULT_MAX_BODY = 256 * 1024;

export class HttpApp {
  private readonly routes: RouteDefinition[] = [];
  private readonly rateLimiters = new Map<string, { limiter: RateLimiter; rule: RateLimitRule }>();
  private server?: Server;

  constructor(private readonly options: ServerOptions) {}

  route(method: string, path: string, handler: Handler, extra: Partial<RouteDefinition> = {}): this {
    this.routes.push({ method: method.toUpperCase(), path, handler, ...extra });
    return this;
  }

  get(path: string, handler: Handler, extra?: Partial<RouteDefinition>): this {
    return this.route("GET", path, handler, extra);
  }

  post(path: string, handler: Handler, extra?: Partial<RouteDefinition>): this {
    return this.route("POST", path, handler, extra);
  }

  delete(path: string, handler: Handler, extra?: Partial<RouteDefinition>): this {
    return this.route("DELETE", path, handler, extra);
  }

  useRateLimit(name: string, rule: RateLimitRule): this {
    this.rateLimiters.set(name, { limiter: new RateLimiter(rule), rule });
    return this;
  }

  async listen(): Promise<number> {
    const { port, host = "0.0.0.0", logger } = this.options;
    this.server = createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve, reject) => {
      this.server?.once("error", reject);
      this.server?.listen(port, host, () => resolve());
    });
    const address = this.server.address();
    const boundPort = typeof address === "object" && address ? address.port : port;
    logger.info(`listening on http://${host}:${boundPort}`);
    return boundPort;
  }

  async close(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const startedAt = Date.now();
    const requestId = String(request.headers["x-request-id"] ?? crypto.randomUUID());
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    const clientIp = request.socket.remoteAddress ?? "unknown";

    response.setHeader("x-request-id", requestId);
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("cache-control", "no-store");

    try {
      this.applyCors(request, response);
      if ((request.method ?? "GET").toUpperCase() === "OPTIONS") {
        this.handlePreflight(request, response);
        return;
      }
      if (this.options.serviceAuthToken) this.checkServiceAuth(request);

      const globalLimit = this.options.globalRateLimit;
      if (globalLimit) {
        const limiter = this.rateLimiter("__global", globalLimit);
        const result = limiter.check(globalLimit.key ? globalLimit.key({} as RequestContext) : clientIp);
        if (!result.allowed) {
          response.setHeader("retry-after", String(result.retryAfterSeconds));
          throw new HttpError(429, "rate_limited", "Too many requests");
        }
      }

      const match = this.match(request.method ?? "GET", url.pathname);
      if (!match) throw new HttpError(404, "not_found", `No route for ${url.pathname}`);

      for (const [name, entry] of this.rateLimiters) {
        if (name === "__global") continue;
        if (entry.rule.paths && !entry.rule.paths.some((prefix) => url.pathname.startsWith(prefix))) continue;
        const result = entry.limiter.check(entry.rule.key?.({ clientIp } as RequestContext) ?? clientIp);
        if (!result.allowed) {
          response.setHeader("retry-after", String(result.retryAfterSeconds));
          throw new HttpError(429, "rate_limited", `Rate limit exceeded for ${name}`);
        }
      }

      const ctx: RequestContext = {
        request,
        response,
        params: match.params,
        query: url.searchParams,
        body: match.route.raw ? undefined : await readJsonBody(request, match.route.maxBodyBytes ?? this.options.defaultMaxBodyBytes ?? DEFAULT_MAX_BODY),
        requestId,
        clientIp,
        startedAt,
      };

      const result = await match.route.handler(ctx);
      // A handler that streams its own response (static files) has already sent
      // headers; writing JSON on top of it would throw.
      if (response.headersSent || response.writableEnded) return;
      sendJson(response, result === undefined ? { ok: true } : (result as Record<string, unknown>), 200);
    } catch (error) {
      const { status, code, message, details } = describeError(error);
      if (status >= 500 && !response.headersSent) {
        this.options.logger.error("request failed", { requestId, path: url.pathname, error: String(error) });
      }
      if (!response.headersSent && !response.writableEnded) {
        sendJson(response, { error: code, message, details }, status);
      }
    } finally {
      const duration = Date.now() - startedAt;
      this.options.onRequest?.(
        { request, response, params: {}, query: url.searchParams, body: undefined, requestId, clientIp, startedAt },
        duration,
        response.statusCode,
      );
    }
  }

  private rateLimiter(name: string, rule: RateLimitRule): RateLimiter {
    let entry = this.rateLimiters.get(name);
    if (!entry) {
      entry = { limiter: new RateLimiter(rule), rule };
      this.rateLimiters.set(name, entry);
    }
    return entry.limiter;
  }

  /**
   * Browser origin boundary (NOT an auth control).
   *
   * Validates the `Origin` header against the allowlist and, when it matches,
   * emits `Access-Control-Allow-Origin` + `Vary: Origin` so the browser lets
   * the page read the response. Requests without an `Origin` header
   * (curl, bundlers, server-to-server) skip CORS entirely. A disallowed
   * origin gets a 403 with NO ACAO header, so the browser keeps blocking it.
   * The `"*"` entry (used by static-asset tests) emits `*` and skips the
   * allowlist check.
   */
  private applyCors(request: IncomingMessage, response: ServerResponse): void {
    const allowed = this.options.allowedOrigins;
    if (allowed.includes("*")) {
      response.setHeader("access-control-allow-origin", "*");
      return;
    }
    const origin = request.headers.origin;
    if (origin === undefined) return; // non-browser client (bundler, CLI)
    if (!allowed.includes(origin)) {
      throw new HttpError(403, "origin_not_allowed", `Origin ${origin} is not allowed`);
    }
    response.setHeader("access-control-allow-origin", origin);
    response.setHeader("vary", "Origin");
  }

  /**
   * Answer a CORS preflight without touching the router: there is no
   * `OPTIONS /v1/...` route and there must not need to be. `applyCors` runs
   * first, so a disallowed origin never reaches this 204.
   */
  private handlePreflight(request: IncomingMessage, response: ServerResponse): void {
    const requestedHeaders = request.headers["access-control-request-headers"];
    response.setHeader("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
    response.setHeader(
      "access-control-allow-headers",
      typeof requestedHeaders === "string" && requestedHeaders.length > 0
        ? requestedHeaders
        : "content-type, authorization, x-request-id",
    );
    response.setHeader("access-control-max-age", "600");
    response.writeHead(204);
    response.end();
  }

  private checkServiceAuth(request: IncomingMessage): void {
    const token = this.options.serviceAuthToken;
    if (!token) return;
    const header = request.headers.authorization ?? "";
    const provided = header.startsWith("Bearer ") ? header.slice(7) : "";
    const a = Buffer.from(provided);
    const b = Buffer.from(token);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new HttpError(401, "unauthorized", "Missing or invalid service token");
    }
  }

  private match(method: string, pathname: string): { route: RouteDefinition; params: Record<string, string> } | undefined {
    let pathMatched = false;
    for (const route of this.routes) {
      const params = matchPath(route.path, pathname);
      if (!params) continue;
      pathMatched = true;
      if (route.method === method) return { route, params };
    }
    if (pathMatched) throw new HttpError(405, "method_not_allowed", `${method} is not allowed here`);
    return undefined;
  }
}

function matchPath(pattern: string, pathname: string): Record<string, string> | undefined {
  const patternParts = pattern.split("/").filter(Boolean);
  const pathParts = pathname.split("/").filter(Boolean);
  if (patternParts.length !== pathParts.length) return undefined;
  const params: Record<string, string> = {};
  for (let i = 0; i < patternParts.length; i++) {
    const expected = patternParts[i];
    const actual = pathParts[i];
    if (expected.startsWith(":")) {
      params[expected.slice(1)] = decodeURIComponent(actual);
      continue;
    }
    if (expected !== actual) return undefined;
  }
  return params;
}

async function readJsonBody(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > maxBytes) {
      throw new HttpError(413, "payload_too_large", `Request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(buffer);
  }
  if (total === 0) return undefined;
  const text = Buffer.concat(chunks).toString("utf-8");
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json", "Request body is not valid JSON");
  }
}

function sendJson(response: ServerResponse, payload: unknown, status: number): void {
  const body = JSON.stringify(payload);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(body);
}

function describeError(error: unknown): { status: number; code: string; message: string; details?: unknown } {
  if (error instanceof HttpError) {
    return { status: error.status, code: error.code, message: error.message, details: error.details };
  }
  return { status: 500, code: "internal_error", message: "Unexpected server error" };
}

/* -------------------------------------------------------------------------- */
/*                             Request validation                              */
/* -------------------------------------------------------------------------- */

export function requireString(body: unknown, field: string, options: { maxLength?: number; pattern?: RegExp } = {}): string {
  const value = readPath(body, field);
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, "invalid_request", `${field} is required and must be a non-empty string`);
  }
  if (options.maxLength && value.length > options.maxLength) {
    throw new HttpError(400, "invalid_request", `${field} exceeds ${options.maxLength} characters`);
  }
  if (options.pattern && !options.pattern.test(value)) {
    throw new HttpError(400, "invalid_request", `${field} has an unexpected format`);
  }
  return value;
}

export function requireNumber(body: unknown, field: string, options: { min?: number; max?: number } = {}): number {
  const value = readPath(body, field);
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new HttpError(400, "invalid_request", `${field} is required and must be a finite number`);
  }
  if (options.min !== undefined && value < options.min) {
    throw new HttpError(400, "invalid_request", `${field} must be >= ${options.min}`);
  }
  if (options.max !== undefined && value > options.max) {
    throw new HttpError(400, "invalid_request", `${field} must be <= ${options.max}`);
  }
  return value;
}

export function optionalString(body: unknown, field: string, options: { maxLength?: number } = {}): string | undefined {
  const value = readPath(body, field);
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw new HttpError(400, "invalid_request", `${field} must be a string`);
  if (options.maxLength && value.length > options.maxLength) {
    throw new HttpError(400, "invalid_request", `${field} exceeds ${options.maxLength} characters`);
  }
  return value;
}

export function requireObject(body: unknown, field: string): Record<string, unknown> {
  const value = readPath(body, field);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new HttpError(400, "invalid_request", `${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function readPath(body: unknown, field: string): unknown {
  if (!field) return body;
  if (field.includes(".")) {
    return field.split(".").reduce<unknown>((acc, part) => {
      if (typeof acc !== "object" || acc === null) return undefined;
      return (acc as Record<string, unknown>)[part];
    }, body);
  }
  if (typeof body !== "object" || body === null) return undefined;
  return (body as Record<string, unknown>)[field];
}

export const HEX_32 = /^0x[0-9a-fA-F]{64}$/;
export const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
export const BASE64URL = /^[A-Za-z0-9_-]+$/;
