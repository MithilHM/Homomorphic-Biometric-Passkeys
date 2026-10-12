import { describe, expect, it } from "vitest";
import {
  keccak256Hex,
  sha3_256,
  bytesToHex,
  hexToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  lengthPrefixed,
  uintToBytes,
  bytesToUint,
  domainHashHex,
  canonicalJson,
  timingSafeEqual,
  randomId,
} from "../src/index.js";

describe("keccak256", () => {
  it("matches the canonical empty-string digest", () => {
    expect(keccak256Hex("")).toBe(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    );
  });

  it("matches the canonical 'abc' digest", () => {
    expect(keccak256Hex("abc")).toBe(
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    );
  });

  it("matches known solidity/etherscan digests", () => {
    expect(keccak256Hex("hello")).toBe(
      "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
    );
    expect(keccak256Hex("Transfer(address,address,uint256)")).toBe(
      "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    );
  });

  it("absorbs inputs that span multiple sponge blocks", () => {
    const long = "a".repeat(400);
    const digest = keccak256Hex(long);
    expect(digest).toHaveLength(64);
    expect(digest).not.toBe(keccak256Hex("a".repeat(399)));
  });

  it("is distinct from SHA3-256", () => {
    expect(bytesToHex(sha3_256(""))).not.toBe(keccak256Hex(""));
  });
});

describe("byte helpers", () => {
  it("round-trips hex", () => {
    const bytes = new Uint8Array([0, 1, 127, 128, 255]);
    expect(bytesToHex(bytes)).toBe("00017f80ff");
    expect(hexToBytes("0x00017f80ff")).toEqual(bytes);
  });

  it("round-trips base64url without padding", () => {
    const bytes = new Uint8Array([251, 255, 190, 1, 2]);
    const b64 = bytesToBase64Url(bytes);
    expect(b64).not.toContain("=");
    expect(base64UrlToBytes(b64)).toEqual(bytes);
  });

  it("frames length-prefixed fields unambiguously", () => {
    const framed = lengthPrefixed(new Uint8Array([1]), new Uint8Array([2, 3]));
    expect(hexToBytes("00010100020203".replace(/0x/, ""))).toEqual(framed);
  });

  it("encodes fixed-width unsigned integers", () => {
    expect(bytesToUint(uintToBytes(143n, 8))).toBe(143n);
    expect(() => uintToBytes(2n ** 64n, 8)).toThrow();
  });
});

describe("domain separation", () => {
  it("produces different digests per domain for identical fields", () => {
    const f = new Uint8Array([1, 2, 3]);
    expect(domainHashHex("AUTH", f)).not.toBe(domainHashHex("ENROLL", f));
  });

  it("is order sensitive", () => {
    const a = new Uint8Array([1]);
    const b = new Uint8Array([2]);
    expect(domainHashHex("AUTH", a, b)).not.toBe(domainHashHex("AUTH", b, a));
  });
});

describe("canonical json", () => {
  it("sorts keys so both services agree", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("drops undefined members", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe("randomness", () => {
  it("produces RFC4122 v4 identifiers", () => {
    expect(randomId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("compares in constant time without throwing on length mismatch", () => {
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
});
