/**
 * Conformance of the Python CKKS engine against the TypeScript RLWE engine.
 *
 * The Python module has no runtime dependency on OpenFHE, so its decision
 * procedure and parameter validation are testable here. What CANNOT be tested
 * without OpenFHE installed is the arithmetic — and the module refuses to run
 * rather than faking it, which is exactly what these tests assert.
 *
 * Run: npx vitest run cryptography/vectors/test
 */

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { DEFAULT_FHE_PARAMS, decide } from "@homobio/fhe";

const root = path.resolve(__dirname, "../../..");
const modulePath = path.join(root, "cryptography/openfhe/ckks_encryptor.py");

/** Run a snippet inside the Python module and return its JSON output. */
function python<T>(body: string): T {
  const script = `
import json, sys
sys.path.insert(0, ${JSON.stringify(path.dirname(modulePath))})
import ckks_encryptor as c

${body}
`;
  const out = execFileSync("python", ["-c", script], { cwd: root, encoding: "utf-8" });
  return JSON.parse(out.trim().split("\n").pop() as string) as T;
}

describe("the OpenFHE module exists and is importable", () => {
  it("is present on disk", () => {
    expect(existsSync(modulePath)).toBe(true);
  });

  it("imports without OpenFHE installed", () => {
    const result = python<{ ok: boolean }>("print(json.dumps({'ok': hasattr(c, 'CkksEngine')}))");
    expect(result.ok).toBe(true);
  });
});

describe("it refuses to fake a comparison", () => {
  /**
   * The previous implementation fell back to pickling the plaintext embedding
   * and returning a hardcoded distance of 0.5. Every attestation signed over
   * such a decision would have been a lie. This pins the replacement.
   */
  it("reports unavailability rather than simulating", () => {
    const result = python<{ available: boolean; reason: string | null }>(
      "print(json.dumps({'available': c.is_available(), 'reason': c.CkksEngine().describe()['unavailableReason']}))",
    );
    expect(typeof result.available).toBe("boolean");
    // In CI OpenFHE is absent, so this must be False and explained.
    if (!result.available) {
      expect(result.reason).toBeTruthy();
    }
  });

  it("raises rather than returning a number when it cannot encrypt", () => {
    const result = python<{ raised: boolean; message: string }>(`
engine = c.CkksEngine()
try:
    engine.encrypt([0.1] * 128)
    raised = False
    message = ''
except c.OpenFHEUnavailable as exc:
    raised = True
    message = str(exc)
except Exception as exc:
    raised = True
    message = type(exc).__name__
print(json.dumps({'raised': raised, 'message': message}))
`);
    expect(result.raised).toBe(true);
    // The message must explain the refusal, not pretend to have succeeded.
    expect(result.message).toMatch(/not installed|no mock/i);
  });

  it("does not contain a plaintext-embedding fallback", () => {
    // A source-level assertion: the old implementation serialised the
    // embedding into a dict literally keyed "embedding" and returned a
    // hardcoded distance. Nothing may reintroduce that.
    const source = readFileSync(modulePath, "utf-8");
    // Strip the module docstring, which legitimately *discusses* the old
    // behaviour; only executable code is under test here.
    const code = source.replace(/^"""[\s\S]*?"""/, "");
    expect(code).not.toMatch(/\bpickle\b/);
    expect(code).not.toMatch(/["']mock["']\s*:/);
    expect(code).not.toMatch(/["']embedding["']\s*:/);
    expect(code).not.toMatch(/["']distance["']\s*:\s*0?\.\d/);
  });
});

describe("its parameters match the RLWE engine's profile", () => {
  it("uses the same embedding dimension", () => {
    const result = python<{ dimension: number }>(
      "print(json.dumps({'dimension': c.DEFAULT_PARAMETERS.embedding_dimension}))",
    );
    expect(result.dimension).toBe(DEFAULT_FHE_PARAMS.embeddingDimension);
  });

  it("uses the same documented error bound", () => {
    const result = python<{ bound: number }>(
      "print(json.dumps({'bound': c.DEFAULT_PARAMETERS.error_bound}))",
    );
    expect(result.bound).toBeCloseTo(2 ** -9, 12);
  });

  it("claims 128-bit security", () => {
    const result = python<{ bits: number }>(
      "print(json.dumps({'bits': c.CkksEngine().describe()['securityLevelBits']}))",
    );
    expect(result.bits).toBe(128);
  });

  it("reduces a power-of-two batch size with log2(dim) rotations", () => {
    const result = python<{ batch: number; steps: number[] }>(`
p = c.DEFAULT_PARAMETERS
print(json.dumps({'batch': p.batch_size, 'steps': p.rotation_steps}))
`);
    expect(result.batch).toBe(8192 / 2);
    // 128 slots need 7 rotate-and-add steps.
    expect(result.steps).toEqual([1, 2, 4, 8, 16, 32, 64]);
  });
});

describe("its decision procedure is identical to the TypeScript engine", () => {
  const cases: Array<[number, number, number, string]> = [
    [0.95, 0.7, 2 ** -9, "accept"],
    [0.702, 0.7, 2 ** -9, "accept"],
    [0.3, 0.7, 2 ** -9, "reject"],
    [0.698, 0.7, 2 ** -9, "reject"],
    [0.7, 0.7, 2 ** -9, "indeterminate"],
    [0.699, 0.7, 2 ** -9, "indeterminate"],
    [0.701, 0.7, 2 ** -9, "indeterminate"],
  ];

  it("agrees on every case, including the whole noise band", () => {
    const result = python<{ zones: string[] }>(`
cases = ${JSON.stringify(cases)}
zones = [c.decide(s, t, m).zone for s, t, m, _ in cases]
print(json.dumps({'zones': zones}))
`);
    expect(result.zones).toEqual(cases.map(([, , , zone]) => zone));
  });

  it("agrees with the TS engine directly", () => {
    const result = python<{ zones: string[] }>(`
cases = ${JSON.stringify(cases)}
zones = [c.decide(s, t, m).zone for s, t, m, _ in cases]
print(json.dumps({'zones': zones}))
`);
    const tsZones = cases.map(([s, t, m]) => decide(s, t, m).zone);
    expect(result.zones).toEqual(tsZones);
  });

  it("never collapses the band into a boolean", () => {
    const result = python<{ decisions: boolean[] }>(`
cases = ${JSON.stringify(cases)}
decisions = [c.decide(s, t, m).decision for s, t, m, _ in cases]
print(json.dumps({'decisions': decisions}))
`);
    // Only the `accept` cases may be true; `indeterminate` must be false but
    // must ALSO not be silently reported as a reject.
    expect(result.decisions).toEqual(cases.map(([, , , zone]) => zone === "accept"));
  });
});

interface RotationStepsByDimension {
  d128: number[];
  d512: number[];
  d1024: number[];
}

describe("its plaintext helpers agree with the TS engine", () => {
  it("computes the same rotation steps", () => {
    const result = python<RotationStepsByDimension>(`
print(json.dumps({
    'd128': c.rotation_steps_for(128),
    'd512': c.rotation_steps_for(512),
    'd1024': c.rotation_steps_for(1024),
}))
`);
    expect(result.d128).toEqual([1, 2, 4, 8, 16, 32, 64]);
    expect(result.d512).toEqual([1, 2, 4, 8, 16, 32, 64, 128, 256]);
    expect(result.d1024).toEqual([1, 2, 4, 8, 16, 32, 64, 128, 256, 512]);
  });

  it("computes the same cosine similarity as the TS engine", () => {
    const a = Array.from({ length: 128 }, (_, i) => Math.sin(i) + 1);
    const b = Array.from({ length: 128 }, (_, i) => Math.cos(i) + 1);
    const result = python<{ value: number }>(`
import math
a = ${JSON.stringify(a)}
b = ${JSON.stringify(b)}
print(json.dumps({'value': c.cosine(a, b)}))
`);
    const dot = a.reduce((sum: number, x: number, i: number) => sum + x * (b[i] as number), 0);
    const expected = dot / (Math.hypot(...a) * Math.hypot(...b));
    expect(result.value).toBeCloseTo(expected, 10);
  });

  it("rejects a zero vector rather than dividing by zero", () => {
    const result = python<{ raised: boolean }>(`
try:
    c.normalise([0.0] * 128)
    raised = False
except ValueError:
    raised = True
print(json.dumps({'raised': raised}))
`);
    expect(result.raised).toBe(true);
  });
});

describe("its parameter validation", () => {
  it("rejects a ring dimension that is not a power of two", () => {
    const result = python<{ raised: boolean }>(`
try:
    c.CkksParameters(ring_dimension=1000)
    raised = False
except ValueError:
    raised = True
print(json.dumps({'raised': raised}))
`);
    expect(result.raised).toBe(true);
  });

  it("rejects an embedding that cannot fit in the ring", () => {
    const result = python<{ raised: boolean }>(`
try:
    c.CkksParameters(ring_dimension=128, embedding_dimension=1024)
    raised = False
except ValueError:
    raised = True
print(json.dumps({'raised': raised}))
`);
    expect(result.raised).toBe(true);
  });

  it("rejects a non-positive error bound", () => {
    const result = python<{ raised: boolean }>(`
try:
    c.CkksParameters(error_bound=0.0)
    raised = False
except ValueError:
    raised = True
print(json.dumps({'raised': raised}))
`);
    expect(result.raised).toBe(true);
  });

  it("rejects a threshold outside (0, 1)", () => {
    const result = python<{ raised: boolean }>(`
raised = False
for bad in (0.0, 1.0, 1.5, -0.1):
    try:
        c.CkksParameters(threshold=bad)
    except ValueError:
        continue
    raised = False
    break
else:
    raised = True
print(json.dumps({'raised': raised}))
`);
    expect(result.raised).toBe(true);
  });
});
