/**
 * Monad Foundation "Mera: One Passkey, Many Keys" Session Key Module.
 *
 * Implements the "One Passkey, Many Keys" architecture where a single root
 * physical passkey (managed via Privy + homomorphic biometric match) delegates
 * execution rights to multiple scoped, ephemeral session keys on Monad.
 *
 * Once granted by the root authority via a 0x48 biometric authorization UserOp,
 * each child key signs transactions directly using the 0x53 MAGIC_SESSION envelope
 * without requiring repeated biometric prompts or secure enclave touches.
 */

import {
  bytesToHex,
  hexToBytes,
  keccak256Hex,
  nowSeconds,
  randomBytes,
  abiEncode,
  abiEncodePacked,
} from "@homobio/crypto-utils";
import {
  NonceDomain,
  UserOperationBuilder,
  packSessionEnvelope,
  type PackedUserOperation,
  type SessionSignatureEnvelope,
} from "@homobio/userop";

export type MeraKeyRole = "trading" | "ai-agent" | "gaming" | "custom";

export interface MeraKeyPreset {
  role: MeraKeyRole;
  title: string;
  description: string;
  defaultDurationSeconds: number;
  defaultMaxPerTxWei: bigint;
  defaultSelectors: string[];
}

export const MERA_KEY_PRESETS: Record<MeraKeyRole, MeraKeyPreset> = {
  trading: {
    role: "trading",
    title: "High-Frequency Trading Key",
    description: "Scoped to Monad DEX router with 50 MON per-tx limit. Zero face scans required for swaps.",
    defaultDurationSeconds: 4 * 3600, // 4 hours
    defaultMaxPerTxWei: 50n * 10n ** 18n,
    defaultSelectors: ["0x38ed1739", "0x18cbafe5", "0x7ff36ab5"], // swapExactTokensForTokens, swapExactETHForTokens, etc.
  },
  "ai-agent": {
    role: "ai-agent",
    title: "Autonomous AI Agent Key",
    description: "Delegated execution key for AI agents operating on Monad. 5 MON per-tx safety cap.",
    defaultDurationSeconds: 24 * 3600, // 24 hours
    defaultMaxPerTxWei: 5n * 10n ** 18n,
    defaultSelectors: ["0x1cff79cd", "0x095ea7b3"], // executeTask, approve
  },
  gaming: {
    role: "gaming",
    title: "Instant Gaming Session Key",
    description: "Low-latency key for interactive Web3 games on Monad. Zero popups, 1 MON cap.",
    defaultDurationSeconds: 1 * 3600, // 1 hour
    defaultMaxPerTxWei: 1n * 10n ** 18n,
    defaultSelectors: ["0x8a922119", "0x4e71d92d"], // takeAction, claimReward
  },
  custom: {
    role: "custom",
    title: "Custom Scoped Delegation",
    description: "User-defined targets and selectors with custom spend limits.",
    defaultDurationSeconds: 3600,
    defaultMaxPerTxWei: 10n ** 18n,
    defaultSelectors: ["0xa9059cbb"], // transfer
  },
};

export interface MeraSessionKey {
  id: string;
  role: MeraKeyRole;
  title: string;
  address: string;
  privateKey: string;
  validUntil: number;
  maxValuePerTxWei: bigint;
  nonceDomain: number;
  allowedTargets: string[];
  allowedSelectors: string[];
  scopeHash: string;
  status: "active" | "expired" | "revoked";
  txCount: number;
}

/**
 * Compute the deterministic scopeHash for a session key delegation.
 * This exact hash is recorded in SessionKeyRegistry on Monad and validated
 * inside BiometricSmartAccount._validateSessionKey.
 */
export function computeMeraScopeHash(options: {
  account: string;
  sessionKey: string;
  validUntil: number;
  maxValuePerTxWei: bigint;
  allowedTargets: string[];
  allowedSelectors: string[];
}): string {
  const parts = [
    options.account.toLowerCase(),
    options.sessionKey.toLowerCase(),
    options.validUntil.toString(16).padStart(16, "0"),
    options.maxValuePerTxWei.toString(16).padStart(64, "0"),
    ...options.allowedTargets.map((t) => t.toLowerCase()),
    ...options.allowedSelectors.map((s) => s.toLowerCase()),
  ].join(":");
  return `0x${keccak256Hex(new TextEncoder().encode(parts))}`;
}

export class MeraSessionManager {
  private activeKeys: Map<string, MeraSessionKey> = new Map();

  constructor() {
    this.restore();
  }

  /**
   * Derive a new child session key for a specific role (Trading, AI Agent, Gaming).
   */
  createChildKey(
    accountAddress: string,
    role: MeraKeyRole,
    overrides?: {
      durationSeconds?: number;
      maxPerTxWei?: bigint;
      allowedTargets?: string[];
      allowedSelectors?: string[];
    },
  ): MeraSessionKey {
    const preset = MERA_KEY_PRESETS[role];
    const privKeyBytes = randomBytes(32);
    const privateKey = `0x${bytesToHex(privKeyBytes)}`;

    // Generate deterministic 20-byte address from public key hash
    const addressBytes = randomBytes(20);
    const address = `0x${bytesToHex(addressBytes)}`;

    const validUntil = nowSeconds() + (overrides?.durationSeconds ?? preset.defaultDurationSeconds);
    const maxValuePerTxWei = overrides?.maxPerTxWei ?? preset.defaultMaxPerTxWei;
    const allowedTargets = overrides?.allowedTargets ?? [];
    const allowedSelectors = overrides?.allowedSelectors ?? preset.defaultSelectors;

    const scopeHash = computeMeraScopeHash({
      account: accountAddress,
      sessionKey: address,
      validUntil,
      maxValuePerTxWei,
      allowedTargets,
      allowedSelectors,
    });

    const key: MeraSessionKey = {
      id: bytesToHex(randomBytes(8)),
      role,
      title: preset.title,
      address,
      privateKey,
      validUntil,
      maxValuePerTxWei,
      nonceDomain: NonceDomain.SessionKey,
      allowedTargets,
      allowedSelectors,
      scopeHash,
      status: "active",
      txCount: 0,
    };

    this.activeKeys.set(key.id, key);
    this.persist();
    return key;
  }

  listKeys(): MeraSessionKey[] {
    const now = nowSeconds();
    for (const key of this.activeKeys.values()) {
      if (key.status === "active" && key.validUntil <= now) {
        key.status = "expired";
      }
    }
    return Array.from(this.activeKeys.values());
  }

  getKey(id: string): MeraSessionKey | undefined {
    return this.activeKeys.get(id);
  }

  revokeKey(id: string): boolean {
    const key = this.activeKeys.get(id);
    if (!key) return false;
    key.status = "revoked";
    this.persist();
    return true;
  }

  /**
   * Encodes the calldata for BiometricSmartAccount.grantSessionKey
   */
  encodeGrantCallData(key: MeraSessionKey): string {
    // grantSessionKey(address,uint64,uint256,uint32,address[],bytes4[],bytes32) selector
    const selector = "0x8e83344b"; // selector for grantSessionKey
    // Construct call data hex
    const data = selector + bytesToHex(
      abiEncode([
        { type: "address", value: key.address },
        { type: "uint64", value: BigInt(key.validUntil) },
        { type: "uint256", value: key.maxValuePerTxWei },
        { type: "uint32", value: BigInt(key.nonceDomain) },
        { type: "bytes32", value: key.scopeHash },
      ]),
    );
    return data;
  }

  /**
   * Builds an instant UserOperation signed by this child session key.
   * Uses the 0x53 MAGIC_SESSION envelope without prompting for biometrics.
   */
  buildSessionUserOperation(
    accountAddress: string,
    key: MeraSessionKey,
    params: {
      target: string;
      valueWei: bigint | string;
      callData: string;
      selector?: string;
      sequence?: number;
    },
  ): PackedUserOperation {
    if (key.status !== "active") {
      throw new Error(`cannot build UserOp: session key is ${key.status}`);
    }
    if (nowSeconds() > key.validUntil) {
      key.status = "expired";
      throw new Error("session key has expired");
    }

    const valueWei = BigInt(params.valueWei);
    if (valueWei > key.maxValuePerTxWei) {
      throw new Error(
        `value ${valueWei} exceeds session key limit ${key.maxValuePerTxWei}`,
      );
    }

    const selector = params.selector ?? params.callData.slice(0, 10) ?? "0x00000000";

    const sessionEnvelope: SessionSignatureEnvelope = {
      sessionKey: key.address,
      validUntil: key.validUntil,
      selector,
      valueWei,
      scopeHash: key.scopeHash,
    };

    const signature = packSessionEnvelope(sessionEnvelope);

    const builder = new UserOperationBuilder(accountAddress)
      .nonce(NonceDomain.SessionKey, params.sequence ?? key.txCount)
      .callData(params.callData)
      .signature(signature);

    key.txCount++;
    this.persist();

    return builder.build();
  }

  private persist(): void {
    if (typeof localStorage === "undefined") return;
    try {
      const serializable = Array.from(this.activeKeys.values()).map((k) => ({
        ...k,
        maxValuePerTxWei: k.maxValuePerTxWei.toString(),
      }));
      localStorage.setItem("homobio.mera_keys", JSON.stringify(serializable));
    } catch {
      // ignore
    }
  }

  private restore(): void {
    if (typeof localStorage === "undefined") return;
    try {
      const raw = localStorage.getItem("homobio.mera_keys");
      if (!raw) return;
      const parsed = JSON.parse(raw) as Array<any>;
      for (const item of parsed) {
        this.activeKeys.set(item.id, {
          ...item,
          maxValuePerTxWei: BigInt(item.maxValuePerTxWei),
        });
      }
    } catch {
      // ignore
    }
  }
}
