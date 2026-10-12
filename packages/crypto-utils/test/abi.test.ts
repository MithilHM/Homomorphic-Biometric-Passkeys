import { describe, expect, it } from "vitest";
import { encodeAbiParameters, parseAbiParameters, keccak256 as viemKeccak } from "viem";
import { abiEncode, abiEncodePacked, abiEncodeHex } from "../src/abi.js";
import { keccak256Hex } from "../src/hashes.js";
import { bytesToHex } from "../src/bytes.js";

const address = "0x00000000000000000000000000000000000000ff";
const bytes32a = `0x${"11".repeat(32)}`;
const bytes32b = `0x${"22".repeat(32)}`;

describe("abi encoder vs viem", () => {
  it("matches for static-only parameter lists", () => {
    const params = [
      { type: "address" as const, value: address },
      { type: "uint256" as const, value: 143n },
      { type: "bool" as const, value: true },
      { type: "bytes32" as const, value: bytes32a },
    ];
    const ref = encodeAbiParameters(
      parseAbiParameters("address, uint256, bool, bytes32"),
      [address, 143n, true, bytes32a],
    );
    expect(abiEncodeHex(params)).toBe(ref.slice(2));
  });

  it("matches for dynamic bytes interleaved with statics", () => {
    const initCode = "0x600160005260206000f3";
    const callData = `0x${"ab".repeat(80)}`;
    const signature = `0x${"cd".repeat(65)}`;
    const params = [
      { type: "address" as const, value: address },
      { type: "uint256" as const, value: 7n },
      { type: "bytes" as const, value: initCode },
      { type: "uint256" as const, value: 100000n },
      { type: "bytes" as const, value: callData },
      { type: "bytes" as const, value: signature },
    ];
    const ref = encodeAbiParameters(
      parseAbiParameters("address, uint256, bytes, uint256, bytes, bytes"),
      [address, 7n, initCode, 100000n, callData, signature],
    );
    expect(abiEncodeHex(params)).toBe(ref.slice(2));
  });

  it("matches for several consecutive dynamic fields", () => {
    const params = [
      { type: "bytes" as const, value: "0x" },
      { type: "bytes" as const, value: "0xdeadbeef" },
      { type: "bytes32" as const, value: bytes32b },
    ];
    const ref = encodeAbiParameters(parseAbiParameters("bytes, bytes, bytes32"), ["0x", "0xdeadbeef", bytes32b]);
    expect(abiEncodeHex(params)).toBe(ref.slice(2));
  });

  it("uses Solidity's minimal-width packed encoding", () => {
    // Solidity `abi.encodePacked(uint8(1), address, bytes4, bool, bytes)`:
    //   1 byte | 20 bytes | 4 bytes | 1 byte | raw
    const ours = bytesToHex(
      abiEncodePacked([
        { type: "uint8", value: 1 },
        { type: "address", value: address },
        { type: "bytes4", value: "0x12345678" },
        { type: "bool", value: false },
        { type: "bytes", value: "0xdeadbeef" },
      ]),
    );
    expect(ours).toBe(
      "01" +
        "00000000000000000000000000000000000000ff" +
        "12345678" +
        "00" +
        "deadbeef",
    );
  });

  it("produces the same digest as viem's keccak for identical bytes", () => {
    const bytes = abiEncode([{ type: "bytes32", value: bytes32a }]);
    const ref = viemKeccak(bytes);
    expect(keccak256Hex(bytes)).toBe(ref.slice(2));
  });
});
