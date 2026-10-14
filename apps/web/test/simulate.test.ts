import { describe, expect, it } from "vitest";

import {
  ACCOUNT_EXECUTE_SELECTOR,
  ERC20_APPROVE_SELECTOR,
  ERC20_TRANSFER_SELECTOR,
  decodeUserOperation,
  formatAmount,
  previewUserOperation,
} from "../src/simulate.js";

const TOKEN = "0x1111111111111111111111111111111111111111";
const ALICE = "0x2222222222222222222222222222222222222222";
const SPENDER = "0x3333333333333333333333333333333333333333";
const ONE_TOKEN = 1_000_000_000_000_000_000n;

function addressWord(address: string): string {
  return address.slice(2).toLowerCase().padStart(64, "0");
}

function amountWord(amount: bigint): string {
  return amount.toString(16).padStart(64, "0");
}

function transferCalldata(to: string, amount: bigint): string {
  return `${ERC20_TRANSFER_SELECTOR}${addressWord(to)}${amountWord(amount)}`;
}

function approveCalldata(spender: string, amount: bigint): string {
  return `${ERC20_APPROVE_SELECTOR}${addressWord(spender)}${amountWord(amount)}`;
}

function executeCalldata(target: string, value: bigint, innerHex: string): string {
  const inner = innerHex.startsWith("0x") ? innerHex.slice(2) : innerHex;
  const offset = (96).toString(16).padStart(64, "0");
  const length = (inner.length / 2).toString(16).padStart(64, "0");
  return `${ACCOUNT_EXECUTE_SELECTOR}${addressWord(target)}${amountWord(value)}${offset}${length}${inner}`;
}

describe("simulate decoder", () => {
  it("decodes transfer into token, recipient and amount", () => {
    const decoded = decodeUserOperation({
      token: TOKEN,
      callData: transferCalldata(ALICE, ONE_TOKEN),
      value: 0n,
    });
    expect(decoded).toEqual({
      kind: "erc20-transfer",
      token: TOKEN.toLowerCase(),
      to: ALICE.toLowerCase(),
      amount: ONE_TOKEN,
      value: 0n,
    });
  });

  it("decodes approve into token, spender and amount", () => {
    const decoded = decodeUserOperation({
      token: TOKEN,
      callData: approveCalldata(SPENDER, 250n),
      value: 0n,
    });
    expect(decoded).toEqual({
      kind: "erc20-approve",
      token: TOKEN.toLowerCase(),
      spender: SPENDER.toLowerCase(),
      amount: 250n,
      value: 0n,
    });
  });

  it("accepts uppercase hex and mixed-case addresses", () => {
    const upperCalldata = `0x${transferCalldata(ALICE, 7n).slice(2).toUpperCase()}`;
    const decoded = decodeUserOperation({
      token: `0x${TOKEN.slice(2).toUpperCase()}`,
      callData: upperCalldata,
      value: 0,
    });
    expect(decoded.kind).toBe("erc20-transfer");
    if (decoded.kind === "erc20-transfer") {
      expect(decoded.to).toBe(ALICE.toLowerCase());
      expect(decoded.amount).toBe(7n);
    }
  });

  it("treats the current wallet placeholder selector as unrecognized, never as a transfer", () => {
    // flows.ts builds 0xb9059cbb... (one nibble off transfer). A guessed
    // decode here would show the wrong recipient, so this must stay explicit.
    const bad = `0xb9059cbb${addressWord(ALICE)}`;
    const decoded = decodeUserOperation({ callData: bad, value: 0n });
    expect(decoded.kind).toBe("unrecognized");
    if (decoded.kind === "unrecognized") {
      expect(decoded.selector).toBe("0xb9059cbb");
      expect(decoded.fingerprint).toMatch(/^[0-9a-f]{8}$/);
    }
  });

  it("reports short, non-hex and odd-length calldata as unrecognized without throwing", () => {
    for (const callData of ["0x", "", "0x123", "0x12345", "not hex", "0xzzzz", "0Xa9059cb"]) {
      const decoded = decodeUserOperation({ token: TOKEN, callData, value: 0n });
      expect(decoded.kind).toBe("unrecognized");
    }
  });

  it("rejects transfer calldata with a missing amount word", () => {
    const decoded = decodeUserOperation({
      token: TOKEN,
      callData: `${ERC20_TRANSFER_SELECTOR}${addressWord(ALICE)}`,
      value: 0n,
    });
    expect(decoded.kind).toBe("unrecognized");
  });

  it("rejects transfer calldata with trailing bytes instead of truncating them", () => {
    const decoded = decodeUserOperation({
      token: TOKEN,
      callData: `${transferCalldata(ALICE, 1n)}00`,
      value: 0n,
    });
    expect(decoded.kind).toBe("unrecognized");
  });

  it("rejects an address word with non-zero padding instead of decoding it wrongly", () => {
    const dirty = `000000000000000000000001${ALICE.slice(2).toLowerCase()}`;
    const decoded = decodeUserOperation({
      token: TOKEN,
      callData: `${ERC20_TRANSFER_SELECTOR}${dirty}${amountWord(1n)}`,
      value: 0n,
    });
    expect(decoded.kind).toBe("unrecognized");
  });

  it("reports transfer-shaped calldata without a token contract as unrecognized", () => {
    const decoded = decodeUserOperation({ callData: transferCalldata(ALICE, 1n), value: 0n });
    expect(decoded.kind).toBe("unrecognized");
  });

  it("decodes a plain native send from the value field with empty calldata", () => {
    const decoded = decodeUserOperation({ to: ALICE, callData: "0x", value: "0x8ac7230489e80000" });
    expect(decoded).toEqual({ kind: "native", to: ALICE.toLowerCase(), value: 10n ** 19n });
  });

  it("reports an empty call with zero value as unrecognized (nothing to show)", () => {
    expect(decodeUserOperation({ to: ALICE, callData: "0x", value: 0n }).kind).toBe("unrecognized");
    expect(decodeUserOperation({ callData: "0x", value: 10n }).kind).toBe("unrecognized");
  });

  it("unwraps account execute() and decodes the token call inside", () => {
    const decoded = decodeUserOperation({
      callData: executeCalldata(TOKEN, 0n, transferCalldata(ALICE, ONE_TOKEN)),
      value: 0n,
    });
    expect(decoded).toEqual({
      kind: "erc20-transfer",
      token: TOKEN.toLowerCase(),
      to: ALICE.toLowerCase(),
      amount: ONE_TOKEN,
      value: 0n,
    });
  });

  it("reads the native amount from the execute value field", () => {
    const decoded = decodeUserOperation({
      callData: executeCalldata(ALICE, 10n ** 18n, "0x"),
      value: 0n,
    });
    expect(decoded).toEqual({ kind: "native", to: ALICE.toLowerCase(), value: 10n ** 18n });
  });

  it("reports execute with an unknown inner call as unrecognized", () => {
    const decoded = decodeUserOperation({
      callData: executeCalldata(ALICE, 0n, "0xdeadbeef"),
      value: 0n,
    });
    expect(decoded.kind).toBe("unrecognized");
    if (decoded.kind === "unrecognized") {
      expect(decoded.selector).toBe(ACCOUNT_EXECUTE_SELECTOR);
    }
  });

  it("gives every unrecognized payload a stable 8-hex fingerprint", () => {
    const a = decodeUserOperation({ callData: "0xdeadbeef", value: 0n });
    const b = decodeUserOperation({ callData: "0xdeadbeef", value: 0n });
    const c = decodeUserOperation({ callData: "0xdeadbeee", value: 0n });
    expect(a).toEqual(b);
    if (a.kind === "unrecognized" && c.kind === "unrecognized") {
      expect(a.fingerprint).toMatch(/^[0-9a-f]{8}$/);
      expect(a.fingerprint).not.toBe(c.fingerprint);
    } else {
      throw new Error("expected unrecognized payloads");
    }
  });
});

describe("simulate preview text", () => {
  it("previews a transfer as a Send line with token, amount and recipient", () => {
    const text = previewUserOperation({
      token: TOKEN,
      callData: transferCalldata(ALICE, ONE_TOKEN),
      value: 0n,
    });
    expect(text).toContain("Send 1 of token");
    expect(text).toContain(TOKEN.toLowerCase());
    expect(text).toContain(ALICE.toLowerCase());
  });

  it("previews an approval as an Allow line naming the spender", () => {
    const text = previewUserOperation({
      token: TOKEN,
      callData: approveCalldata(SPENDER, 250n),
      value: 0n,
    });
    expect(text).toContain("Allow");
    expect(text).toContain(SPENDER.toLowerCase());
    expect(text).toContain(TOKEN.toLowerCase());
  });

  it("previews a native send with the MON amount", () => {
    const text = previewUserOperation({ to: ALICE, callData: "0x", value: 10n ** 18n });
    expect(text).toContain("Send 1 MON to");
    expect(text).toContain(ALICE.toLowerCase());
  });

  it("warns explicitly on unrecognized calldata and shows only selector plus fingerprint", () => {
    const text = previewUserOperation({ callData: "0xdeadbeef", value: 0n });
    expect(text).toContain("could not recognize");
    expect(text).toContain("0xdeadbeef");
    expect(text).toContain("Do not approve");
    expect(text).not.toContain("Send");
    expect(text).not.toContain("Allow");
  });
});

describe("formatAmount", () => {
  it("formats whole, fractional, dust and zero amounts", () => {
    expect(formatAmount(ONE_TOKEN)).toBe("1");
    expect(formatAmount(1_500_000_000_000_000_000n)).toBe("1.5");
    expect(formatAmount(1n)).toBe("0.000000000000000001");
    expect(formatAmount(0n)).toBe("0");
  });
});
