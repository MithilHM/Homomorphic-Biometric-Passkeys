// Compiles every contract with solc and writes ABI + bytecode artifacts.
// Run with: node scripts/compile-contracts.mjs

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, rmSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const contractsDir = path.join(root, "contracts");
const outDir = path.join(contractsDir, "artifacts");

function collect(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      // `lib` holds forge-std (Foundry-only), `test` holds *.t.sol which
      // import it. Both are compiled by `forge test` in CI, not here.
      if (entry === "artifacts" || entry === "lib" || entry === "node_modules" || entry === "test") continue;
      files.push(...collect(full));
    } else if (entry.endsWith(".sol") && !entry.endsWith(".t.sol")) {
      files.push(full);
    }
  }
  return files;
}

const sources = {};
for (const file of collect(contractsDir)) {
  sources[path.relative(root, file).replace(/\\/g, "/")] = { content: readFileSync(file, "utf8") };
}

if (Object.keys(sources).length === 0) {
  console.error("no .sol sources found");
  process.exit(1);
}

const solc = require("solc");

const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    // The account's envelope decoder touches many locals; the IR pipeline is the
    // supported way to compile it without hand-tuning the stack.
    viaIR: true,
    evmVersion: "paris",
    outputSelection: {
      "*": {
        "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object", "metadata"],
      },
    },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));

const errors = (output.errors ?? []).filter((e) => e.severity === "error");
const warnings = (output.errors ?? []).filter((e) => e.severity !== "error");

if (existsSync(outDir)) rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const artifacts = {};
for (const [file, contracts] of Object.entries(output.contracts ?? {})) {
  for (const [name, contract] of Object.entries(contracts)) {
    // Interfaces and abstract contracts have no deployable bytecode.
    const bytecode = contract.evm?.bytecode?.object ?? "";
    const deployed = contract.evm?.deployedBytecode?.object ?? "";
    if (!bytecode && !deployed) continue;
    const key = `${file}:${name}`;
    artifacts[key] = {
      abi: contract.abi,
      bytecode: `0x${bytecode}`,
      deployedBytecode: `0x${deployed}`,
    };
  }
}

writeFileSync(path.join(outDir, "contracts.json"), JSON.stringify(artifacts, null, 2));

for (const warning of warnings) {
  console.warn(`warning: ${warning.formattedMessage?.trim() ?? warning.message}`);
}

if (errors.length > 0) {
  for (const error of errors) {
    console.error(error.formattedMessage ?? error.message);
  }
  process.exit(1);
}

const names = Object.keys(artifacts).sort();
console.log(`compiled ${names.length} contracts`);
for (const name of names) {
  const size = (artifacts[name].deployedBytecode.length - 2) / 2;
  console.log(`  ${name.padEnd(62)} ${String(size).padStart(6)} bytes`);
}
