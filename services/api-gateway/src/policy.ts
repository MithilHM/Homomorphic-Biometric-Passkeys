/**
 * Policy engine (PRD section 20).
 *
 * Policies are versioned documents, not magic numbers. A challenge is bound to
 * `keccak256(canonicalJson(policy))`, so changing a threshold or a limit
 * invalidates every outstanding challenge that was issued under the old
 * revision — no stale authorization can outlive a policy change.
 */

import { canonicalJson, keccak256Hex } from "@homobio/crypto-utils";
import { policyHashHex, type BiometricPolicy } from "@homobio/protocol-types";

export const DEFAULT_POLICIES: BiometricPolicy[] = [
  {
    policyId: "policy-convenience-v1",
    version: 1,
    tier: "convenience",
    biometricRequired: true,
    passkeyRequired: true,
    livenessRequired: true,
    // Calibrated per model version; see docs/crypto-parameters.md.
    cosineThreshold: 0.62,
    noiseMargin: 2 ** -8,
    maxTransactionValueWei: "1000000000000000000",
    sessionEnabled: true,
    sessionDurationSeconds: 3600,
    recoveryDelaySeconds: 172_800,
    maxAttempts: 5,
    lockoutSeconds: 900,
  },
  {
    policyId: "policy-standard-v1",
    version: 1,
    tier: "standard",
    biometricRequired: true,
    passkeyRequired: true,
    livenessRequired: true,
    cosineThreshold: 0.7,
    noiseMargin: 2 ** -8,
    maxTransactionValueWei: "100000000000000000000",
    sessionEnabled: true,
    sessionDurationSeconds: 900,
    recoveryDelaySeconds: 172_800,
    maxAttempts: 3,
    lockoutSeconds: 900,
  },
  {
    policyId: "policy-high-security-v1",
    version: 1,
    tier: "high-security",
    biometricRequired: true,
    passkeyRequired: true,
    livenessRequired: true,
    cosineThreshold: 0.8,
    noiseMargin: 2 ** -9,
    maxTransactionValueWei: "0",
    sessionEnabled: false,
    sessionDurationSeconds: 0,
    recoveryDelaySeconds: 604_800,
    maxAttempts: 2,
    lockoutSeconds: 3600,
  },
];

export class PolicyRegistry {
  private readonly policies = new Map<string, BiometricPolicy>();

  constructor(initial: BiometricPolicy[] = DEFAULT_POLICIES) {
    for (const policy of initial) this.policies.set(policy.policyId, policy);
  }

  get(policyId: string): BiometricPolicy {
    const policy = this.policies.get(policyId);
    if (!policy) throw new Error(`unknown policy ${policyId}`);
    return policy;
  }

  list(): BiometricPolicy[] {
    return [...this.policies.values()].sort((a, b) => a.policyId.localeCompare(b.policyId));
  }

  hash(policyId: string): string {
    return policyHashHex(this.get(policyId));
  }

  /** Publish a new revision. The previous revision stays addressable. */
  publish(policy: BiometricPolicy): BiometricPolicy {
    const previous = this.policies.get(policy.policyId);
    const next = { ...policy, version: (previous?.version ?? 0) + 1 };
    this.policies.set(next.policyId, next);
    return next;
  }

  /**
   * Decide whether a policy accepts a similarity estimate.
   *
   * The engine's own error bound is folded in: if the estimate sits inside
   * `[threshold - margin, threshold + margin]` we return `indeterminate` and
   * the caller must capture again. Guessing at the boundary would quietly turn
   * a noisy comparison into a coin flip (PRD section 12).
   */
  evaluate(
    policy: BiometricPolicy,
    similarity: number,
    engineErrorBound: number,
  ): { zone: "accept" | "reject" | "indeterminate"; margin: number } {
    const margin = Math.max(policy.noiseMargin, engineErrorBound);
    if (similarity >= policy.cosineThreshold + margin) return { zone: "accept", margin };
    if (similarity <= policy.cosineThreshold - margin) return { zone: "reject", margin };
    return { zone: "indeterminate", margin };
  }

  describe(policyId: string): Record<string, unknown> {
    const policy = this.get(policyId);
    return {
      ...policy,
      policyHash: policyHashHex(policy),
      canonical: canonicalJson(policy),
    };
  }
}
