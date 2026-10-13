import { describe, expect, it } from "vitest";
import {
  MeraSessionManager,
  computeMeraScopeHash,
  MERA_KEY_PRESETS,
  type MeraKeyRole,
} from "../src/index.js";
import { unpackSessionEnvelope } from "@homobio/userop";

describe("Monad Mera: One Passkey, Many Keys", () => {
  const account = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  it("provides templates for Trading, AI Agent, and Gaming keys", () => {
    expect(MERA_KEY_PRESETS.trading.role).toBe("trading");
    expect(MERA_KEY_PRESETS["ai-agent"].role).toBe("ai-agent");
    expect(MERA_KEY_PRESETS.gaming.role).toBe("gaming");
    expect(MERA_KEY_PRESETS.trading.defaultMaxPerTxWei).toBeGreaterThan(0n);
  });

  it("derives deterministic scope hashes", () => {
    const hash1 = computeMeraScopeHash({
      account,
      sessionKey: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      validUntil: 1800000000,
      maxValuePerTxWei: 10n ** 18n,
      allowedTargets: ["0xcccccccccccccccccccccccccccccccccccccccc"],
      allowedSelectors: ["0xa9059cbb"],
    });

    const hash2 = computeMeraScopeHash({
      account,
      sessionKey: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      validUntil: 1800000000,
      maxValuePerTxWei: 10n ** 18n,
      allowedTargets: ["0xcccccccccccccccccccccccccccccccccccccccc"],
      allowedSelectors: ["0xa9059cbb"],
    });

    expect(hash1).toBe(hash2);
    expect(hash1.startsWith("0x")).toBe(true);
    expect(hash1.length).toBe(66);
  });

  it("creates multiple child session keys from a single root account", () => {
    const manager = new MeraSessionManager();

    const tradingKey = manager.createChildKey(account, "trading");
    const aiKey = manager.createChildKey(account, "ai-agent");
    const gamingKey = manager.createChildKey(account, "gaming");

    expect(tradingKey.id).not.toBe(aiKey.id);
    expect(tradingKey.address).not.toBe(gamingKey.address);
    expect(tradingKey.status).toBe("active");
    expect(tradingKey.title).toContain("Trading");
    expect(aiKey.title).toContain("AI Agent");
    expect(gamingKey.title).toContain("Gaming");

    const allKeys = manager.listKeys();
    expect(allKeys.length).toBeGreaterThanOrEqual(3);
  });

  it("encodes grantSessionKey callData for on-chain registration on Monad", () => {
    const manager = new MeraSessionManager();
    const key = manager.createChildKey(account, "trading");
    const callData = manager.encodeGrantCallData(key);

    expect(callData.startsWith("0x8e83344b")).toBe(true); // grantSessionKey selector
    expect(callData.length).toBeGreaterThan(100);
  });

  it("builds and signs instant UserOperations with the 0x53 MAGIC_SESSION envelope without biometric prompts", () => {
    const manager = new MeraSessionManager();
    const key = manager.createChildKey(account, "gaming");

    const userOp = manager.buildSessionUserOperation(account, key, {
      target: "0x1234567890123456789012345678901234567890",
      valueWei: 1000n,
      callData: "0x8a9221190000000000000000000000000000000000000000000000000000000000000001",
    });

    expect(userOp.sender.toLowerCase()).toBe(account.toLowerCase());
    expect(userOp.signature.startsWith("0x53")).toBe(true); // MAGIC_SESSION_ENVELOPE

    // Unpack and verify envelope fields
    const unpacked = unpackSessionEnvelope(userOp.signature);
    expect(unpacked.sessionKey.toLowerCase()).toBe(key.address.toLowerCase());
    expect(unpacked.validUntil).toBe(key.validUntil);
    expect(unpacked.scopeHash.toLowerCase()).toBe(key.scopeHash.toLowerCase());
    expect(unpacked.valueWei).toBe(1000n);

    // Verify key execution counter incremented
    expect(key.txCount).toBe(1);
  });

  it("enforces session spend limits", () => {
    const manager = new MeraSessionManager();
    const key = manager.createChildKey(account, "gaming", {
      maxPerTxWei: 500n,
    });

    expect(() =>
      manager.buildSessionUserOperation(account, key, {
        target: "0x1234567890123456789012345678901234567890",
        valueWei: 1000n, // exceeds 500n limit
        callData: "0x12345678",
      }),
    ).toThrow(/exceeds session key limit/);
  });

  it("revokes child keys", () => {
    const manager = new MeraSessionManager();
    const key = manager.createChildKey(account, "trading");
    expect(key.status).toBe("active");

    const revoked = manager.revokeKey(key.id);
    expect(revoked).toBe(true);
    expect(key.status).toBe("revoked");

    expect(() =>
      manager.buildSessionUserOperation(account, key, {
        target: "0x1234567890123456789012345678901234567890",
        valueWei: 0n,
        callData: "0x12345678",
      }),
    ).toThrow(/session key is revoked/);
  });
});
