import { describe, expect, it } from "vitest";
import { encodeFunctionData, encodeAbiParameters, parseAbi, parseAbiParameters, keccak256 } from "viem";
import {
  DEFAULT_GAS_POLICY,
  NonceDomain,
  UserOperationBuilder,
  buildInitCode,
  decodeNonce,
  encodeNonce,
  fromJSON,
  getUserOpHash,
  hashPackedUserOperation,
  packSessionEnvelope,
  unpackSessionEnvelope,
  SESSION_ENVELOPE_BODY_BYTES,
  type PackedUserOperation,
} from "../src/index.js";
import { abiEncode, bytesToHex, hexToBytes } from "@homobio/crypto-utils";

const ENTRY_POINT = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const SENDER = "0x1234567890AbcdEF1234567890aBcdef12345678";

const op: PackedUserOperation = {
  sender: SENDER,
  nonce: 0n,
  initCode: "0x600160005260206000f3",
  callData: `0x${"ab".repeat(160)}`,
  callGasLimit: 400_000n,
  verificationGasLimit: 900_000n,
  preVerificationGas: 120_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_500_000_000n,
  paymasterAndData: "0x",
  signature: `0x${"cd".repeat(128)}`,
};

describe("userOpHash", () => {
  it("matches viem's reference encoding of PackedUserOperation", () => {
    const reference = encodeAbiParameters(
      parseAbiParameters(
        "address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxPriorityFeePerGas, uint256 maxFeePerGas, bytes paymasterAndData, bytes signature",
      ),
      [
        op.sender,
        op.nonce,
        op.initCode,
        op.callData,
        op.callGasLimit,
        op.verificationGasLimit,
        op.preVerificationGas,
        op.maxPriorityFeePerGas,
        op.maxFeePerGas,
        op.paymasterAndData,
        op.signature,
      ],
    );
    expect(hashPackedUserOperation(op)).toBe(keccak256(reference).slice(2));
  });

  it("matches viem for the outer EntryPoint/chainId wrap", () => {
    const inner = hashPackedUserOperation(op);
    const reference = encodeAbiParameters(
      parseAbiParameters("bytes32 opHash, address entryPoint, uint256 chainId"),
      [`0x${inner}`, ENTRY_POINT, 143],
    );
    expect(getUserOpHash(op, ENTRY_POINT, 143)).toBe(keccak256(reference).slice(2));
  });

  it("changes when any single field changes", () => {
    const base = getUserOpHash(op, ENTRY_POINT, 143);
    const variants: PackedUserOperation[] = [
      { ...op, sender: "0x2234567890AbcdEF1234567890aBcdef12345678" },
      { ...op, nonce: 1n },
      { ...op, callData: "0xdeadbeef" },
      { ...op, callGasLimit: op.callGasLimit + 1n },
      { ...op, maxFeePerGas: op.maxFeePerGas + 1n },
      { ...op, paymasterAndData: "0x1234" },
      { ...op, signature: "0x1234" },
      { ...op, initCode: "0x600260005260206000f3" },
    ];
    for (const variant of variants) {
      expect(getUserOpHash(variant, ENTRY_POINT, 143)).not.toBe(base);
    }
  });

  it("changes with the EntryPoint and with the chain id", () => {
    const base = getUserOpHash(op, ENTRY_POINT, 143);
    expect(getUserOpHash(op, "0x0000000071727De22E5E9d8BAf0edAc6f37da032", 143)).not.toBe(base);
    expect(getUserOpHash(op, ENTRY_POINT, 1)).not.toBe(base);
  });
});

describe("nonce domains", () => {
  it("packs a domain into the high byte", () => {
    expect(encodeNonce(NonceDomain.Wallet, 0)).toBe(0n);
    expect(decodeNonce(encodeNonce(NonceDomain.SessionKey, 7))).toEqual({
      domain: NonceDomain.SessionKey,
      sequence: 7n,
    });
    expect(decodeNonce(encodeNonce(NonceDomain.Recovery, 1)).domain).toBe(NonceDomain.Recovery);
  });

  it("refuses sequences that would overflow into the next domain", () => {
    expect(() => encodeNonce(NonceDomain.Wallet, 2 ** 248)).toThrow();
    expect(() => encodeNonce(NonceDomain.Wallet, 2 ** 256)).toThrow();
  });

  it("keeps domains from colliding", () => {
    const seen = new Set<string>();
    for (const domain of [
      NonceDomain.Wallet,
      NonceDomain.SessionKey,
      NonceDomain.Recovery,
      NonceDomain.DeviceManagement,
      NonceDomain.Paymaster,
    ]) {
      const nonce = encodeNonce(domain, 3);
      expect(seen.has(nonce.toString(16))).toBe(false);
      seen.add(nonce.toString(16));
    }
  });
});

describe("builder", () => {
  it("produces JSON that round-trips", () => {
    const built = new UserOperationBuilder(SENDER)
      .nonce(NonceDomain.Wallet, 5)
      .callData("0x1234")
      .build();
    const json = new UserOperationBuilder(SENDER)
      .nonce(NonceDomain.Wallet, 5)
      .callData("0x1234")
      .toJSON();
    expect(fromJSON(json)).toEqual(built);
  });

  it("rejects an inverted fee policy", () => {
    expect(() =>
      new UserOperationBuilder(SENDER).gas({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n }).build(),
    ).toThrow();
  });

  it("uses verification gas that fits passkey + attestation validation", () => {
    expect(DEFAULT_GAS_POLICY.verificationGasLimit).toBeGreaterThan(500_000n);
  });
});

describe("counterfactual init code", () => {
  it("selects createAccount(address,bytes)", () => {
    const factory = "0x1111111111111111111111111111111111111111";
    const initCode = buildInitCode(factory, "0x");
    expect(initCode.startsWith(factory)).toBe(true);
    const reference = encodeFunctionData({
      abi: parseAbi(["function createAccount(address owner, bytes callData)"]),
      functionName: "createAccount",
      args: ["0x0000000000000000000000000000000000000000", "0x"],
    });
    expect(initCode).toBe(`${factory}${reference.slice(2)}`);
  });
});

describe("session signature envelope", () => {
  const envelope = {
    sessionKey: "0x1234567890AbcdEF1234567890aBcdef12345678",
    validUntil: 1_791_374_000,
    selector: "0xa9059cbb",
    valueWei: "1000000000000000000",
    scopeHash: `0x${"22".repeat(32)}`,
  };

  it("packs fields at the exact offsets _validateSessionKey reads", () => {
    const packed = packSessionEnvelope(envelope);
    // magic | uint16 body length
    expect(packed.slice(0, 4)).toBe("0x53");
    expect(packed.slice(4, 8)).toBe(SESSION_ENVELOPE_BODY_BYTES.toString(16).padStart(4, "0"));
    expect(packed.length).toBe(2 + 2 * (3 + SESSION_ENVELOPE_BODY_BYTES));
    // `body` starts after "0x" (2 chars) + magic (2) + uint16 length (4).
    const body = packed.slice(8);
    const at = (start: number, length: number): string => body.slice(start * 2, (start + length) * 2);
    expect(at(0, 20)).toBe(envelope.sessionKey.slice(2).toLowerCase());
    expect(at(20, 8)).toBe(envelope.validUntil.toString(16).padStart(16, "0"));
    expect(at(28, 4)).toBe("a9059cbb");
    expect(at(32, 32)).toBe(BigInt(envelope.valueWei).toString(16).padStart(64, "0"));
    expect(at(64, 32)).toBe(envelope.scopeHash.slice(2));
  });

  it("round-trips", () => {
    expect(unpackSessionEnvelope(packSessionEnvelope(envelope))).toEqual({
      ...envelope,
      sessionKey: envelope.sessionKey.toLowerCase(),
      valueWei: BigInt(envelope.valueWei),
    });
  });

  it("changes when any field changes", () => {
    const base = packSessionEnvelope(envelope);
    expect(packSessionEnvelope({ ...envelope, sessionKey: "0x9999999999999999999999999999999999999999" })).not.toBe(base);
    expect(packSessionEnvelope({ ...envelope, selector: "0xdeadbeef" })).not.toBe(base);
    expect(packSessionEnvelope({ ...envelope, valueWei: "2" })).not.toBe(base);
    expect(packSessionEnvelope({ ...envelope, scopeHash: `0x${"33".repeat(32)}` })).not.toBe(base);
  });

  it("rejects malformed input instead of silently mis-parsing", () => {
    const packed = packSessionEnvelope(envelope);
    expect(() => unpackSessionEnvelope(packed.slice(0, 60))).toThrow(/truncated/);
    // The account only accepts 0x53 for a session; 0x48 is the authorization envelope.
    expect(() => unpackSessionEnvelope(`0x48${packed.slice(4)}`)).toThrow(/not a session envelope/);
    expect(() => packSessionEnvelope({ ...envelope, selector: "0xa9059c" })).toThrow(/4 bytes/);
    expect(() => packSessionEnvelope({ ...envelope, valueWei: -1 })).toThrow(/uint256/);
  });
});

describe("abi helpers used by the hash", () => {
  it("produces the same bytes as viem for the outer wrap", () => {
    const ours = bytesToHex(
      abiEncode([
        { type: "bytes32", value: `0x${"11".repeat(32)}` },
        { type: "address", value: ENTRY_POINT },
        { type: "uint256", value: 143n },
      ]),
    );
    const reference = encodeAbiParameters(parseAbiParameters("bytes32, address, uint256"), [
      `0x${"11".repeat(32)}`,
      ENTRY_POINT,
      143n,
    ]);
    expect(ours).toBe(reference.slice(2));
  });
});

