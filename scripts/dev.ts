/**
 * Development launcher.
 *
 * Starts the FHE coprocessor first (the gateway refuses to start without it),
 * then the API gateway, and shuts both down together. The gateway builds and
 * serves the web client on first run.
 */

import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const tsx = path.join(root, "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");

const children: ChildProcess[] = [];

function run(name: string, entry: string, env: Record<string, string> = {}) {
  const child = spawn(tsx, [entry], {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
    shell: process.platform === "win32",
  });
  const prefix = `[${name}] `;
  child.stdout.on("data", (chunk) => process.stdout.write(prefixLines(prefix, chunk)));
  child.stderr.on("data", (chunk) => process.stderr.write(prefixLines(prefix, chunk)));
  child.on("exit", (code) => {
    console.log(`${prefix}exited with code ${code}`);
    shutdown(code ?? 0);
  });
  children.push(child);
  return child;
}

function prefixLines(prefix: string, chunk: Buffer): string {
  return String(chunk)
    .split("\n")
    .map((line) => (line.length > 0 ? `${prefix}${line}\n` : ""))
    .join("");
}

function shutdown(code: number): void {
  for (const child of children) {
    if (!child.killed) child.kill();
  }
  process.exit(code);
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => shutdown(0));
}

console.log("starting the FHE coprocessor…");
run("fhe", path.join(root, "services/fhe-service/src/main.ts"));

setTimeout(() => {
  console.log("starting the API gateway…");
  run("gateway", path.join(root, "services/api-gateway/src/main.ts"));
}, 1500);
