/**
 * Browser compatibility of `@homobio/userop`.
 *
 * Regression test for the blank-page failure (`Uncaught ReferenceError:
 * process is not defined`): the chain-config constants read `process.env` at
 * module top level, and this package is bundled into the browser client, where
 * `process` does not exist. Module evaluation threw before the app rendered.
 *
 * The test bundles the package for the browser and evaluates it in a `vm`
 * sandbox that has no `process` and no `Buffer` — only the globals a real
 * browser provides. If anyone reintroduces a bare Node global at module scope,
 * evaluation throws and this fails.
 */

import { describe, expect, it } from "vitest";
import { runInNewContext } from "node:vm";
import path from "node:path";
import { buildSync } from "esbuild";

// packages/userop/test/ -> repo root is three levels up.
const root = path.resolve(__dirname, "../../..");

interface BrowserUserOp {
  MONAD_TESTNET: { rpcUrl: string; entryPoint: string };
  MONAD_MAINNET: { rpcUrl: string; entryPoint: string };
  readEnv: (name: string) => string | undefined;
}

function loadInBrowserSandbox(): BrowserUserOp {
  const result = buildSync({
    entryPoints: [path.join(root, "packages/userop/src/index.ts")],
    bundle: true,
    format: "cjs",
    platform: "browser",
    write: false,
    logLevel: "silent",
    alias: {
      "@homobio/crypto-utils": path.join(root, "packages/crypto-utils/src/index.ts"),
    },
  });
  const code = result.outputFiles[0].text;
  // Deliberately browser-shaped: TextEncoder/atob exist in browsers, while
  // `process` and `Buffer` do not. Anything the bundle touches outside this
  // list throws a ReferenceError, which is exactly the failure under test.
  const module = { exports: {} as Record<string, unknown> };
  const sandbox = {
    module,
    exports: module.exports,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    URL,
    URLSearchParams,
  };
  runInNewContext(code, sandbox, { filename: "userop.browser.cjs" });
  return module.exports as unknown as BrowserUserOp;
}

describe("userop loads without Node globals", () => {
  it("evaluates with no `process` and no `Buffer` in scope", () => {
    expect(() => loadInBrowserSandbox()).not.toThrow();
  });

  it("falls back to the documented chain defaults", () => {
    const browser = loadInBrowserSandbox();
    expect(browser.MONAD_TESTNET.rpcUrl).toBe("https://testnet-rpc.monad.xyz");
    expect(browser.MONAD_TESTNET.entryPoint).toBe("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
    expect(browser.MONAD_MAINNET.rpcUrl).toBe("https://rpc.monad.xyz");
  });

  it("readEnv yields undefined for unset variables instead of throwing", () => {
    const browser = loadInBrowserSandbox();
    expect(browser.readEnv("HOMOBIO_DEFINITELY_UNSET_VARIABLE")).toBeUndefined();
  });
});
