import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(fileURLToPath(import.meta.url));
const r = (p: string) => path.resolve(root, p);

export default defineConfig({
  resolve: {
    alias: {
      "@homobio/crypto-utils": r("packages/crypto-utils/src/index.ts"),
      "@homobio/protocol-types": r("packages/protocol-types/src/index.ts"),
      "@homobio/fhe": r("packages/fhe/src/index.ts"),
      "@homobio/webauthn": r("packages/webauthn/src/index.ts"),
      "@homobio/biometric-client": r("packages/biometric-client/src/index.ts"),
      "@homobio/userop": r("packages/userop/src/index.ts"),
      "@homobio/http-kit": r("packages/http-kit/src/index.ts"),
      "@homobio/store": r("packages/store/src/index.ts"),
      // Subpath before the bare specifier: Vite aliases are prefix matches.
      "@homobio/sdk/envelope": r("packages/sdk/src/envelope.ts"),
      "@homobio/sdk": r("packages/sdk/src/index.ts"),
    },
  },
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "services/**/test/**/*.test.ts",
      "apps/*/test/**/*.test.ts",
      "contracts/test/**/*.test.ts",
      "cryptography/vectors/test/**/*.test.ts",
    ],
    exclude: ["**/node_modules/**", "**/dist/**"],
    environment: "node",
    testTimeout: 120_000,
    hookTimeout: 120_000,
    pool: "threads",
  },
});
