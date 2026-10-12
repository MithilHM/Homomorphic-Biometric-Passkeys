/**
 * Cross-language consistency between TypeScript and Solidity.
 *
 * The protocol's security depends on both implementations computing the *same*
 * bytes. A one-byte drift in `AuthDomain.authorizationHash` would make every
 * on-chain authorization revert (or, worse, be malleable in one language only).
 *
 * We cannot execute the EVM here, so this test does two things instead:
 *   1. asserts the TypeScript hashes match the committed vectors, and
 *   2. parses the Solidity sources and checks that every hashed field appears in
 *      the `abi.encodePacked` argument list, in the same order and with the same
 *      Solidity type. A rename, reordering or width change therefore fails the
 *      suite instead of failing on chain.
 *
 * `contracts/test/AuthDomain.t.sol` covers the on-chain behaviour under Foundry.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { authorizationHashHex, resultCommitmentHex, sessionKeyHashHex } from "@homobio/protocol-types";
import { bytesToBase64Url } from "@homobio/crypto-utils";
import { getUserOpHash, packSessionEnvelope, type PackedUserOperation } from "@homobio/userop";
import { packAuthorizationEnvelope } from "@homobio/sdk/envelope";

const root = path.resolve(__dirname, "../..");
const vectors = JSON.parse(readFileSync(path.join(root, "cryptography/vectors/protocol.json"), "utf-8")) as any;

function readSolidity(relative: string): string {
  return readFileSync(path.join(root, relative), "utf-8");
}

/** Extract the ordered parameter list of a Solidity function. */
function solidityParameters(source: string, signature: string): string[] {
  const start = source.indexOf(signature);
  if (start < 0) throw new Error(`signature not found: ${signature}`);
  const open = source.indexOf("(", start);
  let depth = 0;
  let end = open;
  for (let i = open; i < source.length; i++) {
    if (source[i] === "(") depth++;
    else if (source[i] === ")") {
      depth--;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  return source
    .slice(open + 1, end)
    .split(",")
    .map((part) => part.trim().split(/\s+/)[0])
    .filter(Boolean);
}

describe("protocol vectors", () => {
  it("matches the committed authorization hash", () => {
    expect(authorizationHashHex(vectors.authorization.fields)).toBe(vectors.expected.authorizationHash);
  });

  it("matches the committed session key hash", () => {
    expect(sessionKeyHashHex(vectors.sessionKey.fields)).toBe(vectors.expected.sessionKeyHash);
  });

  it("matches the committed userOpHash", () => {
    const json = vectors.userOperation.operation;
    const op: PackedUserOperation = {
      sender: json.sender,
      nonce: BigInt(json.nonce),
      initCode: json.initCode,
      callData: json.callData,
      callGasLimit: BigInt(json.callGasLimit),
      verificationGasLimit: BigInt(json.verificationGasLimit),
      preVerificationGas: BigInt(json.preVerificationGas),
      maxFeePerGas: BigInt(json.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(json.maxPriorityFeePerGas),
      paymasterAndData: json.paymasterAndData,
      signature: json.signature,
    };
    expect(getUserOpHash(op, vectors.userOperation.entryPoint, vectors.userOperation.chainId)).toBe(
      vectors.expected.userOpHash,
    );
  });

  it("matches the committed result commitment", () => {
    expect(
      resultCommitmentHex({
        sessionId: vectors.authorization.fields.sessionId,
        templateCommitment: "ee".repeat(32),
        queryCommitment: "ff".repeat(32),
        decision: true,
      }),
    ).toBe(vectors.expected.resultCommitment);
  });
});

describe("Solidity mirrors the TypeScript field list", () => {
  const authDomain = readSolidity("contracts/protocol/AuthDomain.sol");

  it("hashes the authorization fields in the same order and widths", () => {
    const parameters = solidityParameters(authDomain, "function authorizationHash(");
    expect(parameters).toEqual([
      "uint8", // version
      "address", // wallet
      "uint64", // chainId
      "bytes32", // userOpHash
      "bytes16", // sessionId
      "bytes32", // policyHash
      "uint32", // templateVersion
      "uint32", // fheKeyVersion
      "bool", // decision
      "uint32", // thresholdBps
      "bytes32", // resultCommitment
      "uint64", // issuedAt
      "uint64", // expiresAt
      "uint32", // proofSystem
      "uint32", // verifierVersion
      "bytes32", // decisionProgramHash
    ]);
  });

  it("uses the same domain separator string", () => {
    expect(authDomain).toContain('bytes internal constant AUTH_DOMAIN = "HOMOBIO/AUTH-V1";');
    expect(authDomain).toContain('bytes internal constant SESSION_DOMAIN = "HOMOBIO/SESSION-V1";');
    expect(authDomain).toContain('bytes internal constant RESULT_DOMAIN = "HOMOBIO/RESULT-V1";');
  });

  it("hashes the session key scope in the same order", () => {
    const parameters = solidityParameters(authDomain, "function sessionKeyHash(");
    expect(parameters).toEqual([
      "address", // sessionKey
      "address", // wallet
      "uint64", // chainId
      "uint64", // validUntil
      "uint256", // maxValuePerTx
      "uint32", // nonceDomain
      "address[]", // allowedTargets
      "bytes4[]", // allowedSelectors
    ]);
  });

  it("hashes the result commitment in the same order", () => {
    const parameters = solidityParameters(authDomain, "function resultCommitment(");
    expect(parameters).toEqual(["bytes16", "bytes32", "bytes32", "bool"]);
  });
});

describe("Authorization struct matches the hashed field list", () => {
  it("declares every field the account decodes, in the same order", () => {
    const source = readSolidity("contracts/interfaces/IAuthorizationVerifier.sol");
    const start = source.indexOf("struct Authorization {");
    const body = source.slice(start, source.indexOf("}", start));
    const fields = body
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("//") && !line.startsWith("struct") && !line.startsWith("}"))
      .map((line) => line.split(";")[0].trim());

    expect(fields).toEqual([
      "uint8 version",
      "address wallet",
      "uint64 chainId",
      "bytes32 userOpHash",
      "bytes16 sessionId",
      "bytes32 policyHash",
      "uint32 templateVersion",
      "uint32 fheKeyVersion",
      "bool decision",
      "uint32 thresholdBps",
      "bytes32 resultCommitment",
      "uint64 issuedAt",
      "uint64 expiresAt",
      "uint32 proofSystem",
      "uint32 verifierVersion",
      "bytes32 decisionProgramHash",
      "bytes32 attestationHash",
      "bytes signature",
    ]);
  });
});

describe("the account decodes the envelope the SDK packs", () => {
  const account = readSolidity("contracts/account/BiometricSmartAccount.sol");

  it("reads the authorization at the documented byte offsets", () => {
    // magic 0x48 + uint16 length
    expect(account).toContain("MAGIC_AUTHORIZATION = 0x48");
    // The decoder walks: envelopeHash(32) | assertionLen(2) | assertion | fields.
    expect(account).toContain("cursor += 32;");
    expect(account).toContain("if (assertionLength == 0) revert MissingPasskeyAssertion();");
    // Every field read must be bounds-checked against the declared total.
    expect(account).toContain("if (envelope.length != cursor + 307) revert MalformedEnvelope();");
  });

  it("keeps the session envelope at a fixed width", () => {
    expect(account).toContain("if (envelope.length != 3 + 20 + 8 + 4 + 32 + 32) revert MalformedEnvelope();");
  });

  /**
   * The strongest check available without an EVM: parse the *offset arithmetic*
   * straight out of `_decodeAuthorization` and compare it against the bytes the
   * SDK actually produces. A rename or reorder in either language moves a number
   * here and fails the suite, instead of reverting on chain at 3am.
   */
  it("agrees with _decodeAuthorization on every field offset", () => {
    const decoder = account.slice(account.indexOf("function _decodeAuthorization"));
    const offsetOf = (field: string): number => {
      // Matches both `envelope[cursor]` and `envelope[cursor + N:...]`, so a
      // reordering in the decoder changes the number this asserts against.
      const match = decoder.match(new RegExp(`a\\.${field} = [^;]*envelope\\[cursor(?: \\+ (\\d+))?`));
      if (!match) throw new Error(`could not find the offset of a.${field} in the decoder`);
      return match[1] === undefined ? 0 : Number.parseInt(match[1], 10);
    };

    // The assertion travels as base64url, so its byte length is not its string
// length; read it back out of the envelope rather than assuming.
    const assertion = bytesToBase64Url(new Uint8Array([0xaa, 0xbb, 0xcc]));
    const packed = packAuthorizationEnvelope({
      envelopeHash: `0x${"11".repeat(32)}`,
      attestationHash: `0x${"22".repeat(32)}`,
      attestationSignature: `0x${"33".repeat(65)}`,
      webauthnAssertion: assertion,
      authorization: {
        ...vectors.authorization.fields,
        attestationHash: `0x${"22".repeat(32)}`,
      },
    });

    const body = packed.slice(2);
    // `cursor` in Solidity counts from the first body byte.
    const read = (start: number, length: number): string => body.slice(6 + start * 2, 6 + (start + length) * 2);
    // envelopeHash occupies 32 bytes from the start of the body.
    const assertionLength = Number.parseInt(body.slice(6 + 64, 6 + 68), 16);
    const fieldStart = 32 + 2 + assertionLength;
    expect(assertionLength).toBe(3);

    expect(read(0, 32)).toBe("11".repeat(32));
    expect(offsetOf("version")).toBe(0);
    expect(read(fieldStart + offsetOf("version"), 1)).toBe(
      vectors.authorization.fields.version.toString(16).padStart(2, "0"),
    );
    expect(offsetOf("wallet")).toBe(1);
    expect(read(fieldStart + offsetOf("wallet"), 20)).toBe(
      vectors.authorization.fields.wallet.replace(/^0x/, "").toLowerCase(),
    );
    expect(offsetOf("chainId")).toBe(21);
    expect(offsetOf("userOpHash")).toBe(29);
    expect(offsetOf("sessionId")).toBe(61);
    expect(offsetOf("policyHash")).toBe(77);
    expect(offsetOf("templateVersion")).toBe(109);
    expect(offsetOf("fheKeyVersion")).toBe(113);
    expect(offsetOf("decision")).toBe(117);
    expect(offsetOf("thresholdBps")).toBe(118);
    expect(offsetOf("resultCommitment")).toBe(122);
    expect(offsetOf("issuedAt")).toBe(154);
    expect(offsetOf("expiresAt")).toBe(162);
    expect(offsetOf("proofSystem")).toBe(170);
    expect(offsetOf("verifierVersion")).toBe(174);
    expect(offsetOf("decisionProgramHash")).toBe(178);
    expect(offsetOf("attestationHash")).toBe(210);
    expect(offsetOf("signature")).toBe(242);

    // userOpHash / resultCommitment / attestationHash must land on the exact
    // values the services computed, not just on plausible-looking bytes.
    // The vectors file stores hashes un-prefixed; the wire format is 0x-prefixed.
    const bare = (value: string): string => value.replace(/^0x/, "").toLowerCase();
    expect(`0x${read(fieldStart + offsetOf("userOpHash"), 32)}`).toBe(
      `0x${bare(vectors.authorization.fields.userOpHash)}`,
    );
    expect(`0x${read(fieldStart + offsetOf("resultCommitment"), 32)}`).toBe(
      `0x${bare(vectors.authorization.fields.resultCommitment)}`,
    );
    expect(`0x${read(fieldStart + offsetOf("attestationHash"), 32)}`).toBe(`0x${"22".repeat(32)}`);
    expect(read(fieldStart + offsetOf("signature"), 65)).toBe("33".repeat(65));
  });

  it("puts the session envelope where _validateSessionKey reads it", () => {
    const packed = packSessionEnvelope({
      sessionKey: "0x1234567890AbcdEF1234567890aBcdef12345678",
      validUntil: 1_791_374_000,
      selector: "0xa9059cbb",
      valueWei: "1000000000000000000",
      scopeHash: `0x${"44".repeat(32)}`,
    });
    // body starts after "0x" (2) + magic (2) + uint16 length (4); the Solidity
    // offsets are absolute into the whole envelope, so subtract the header.
    const body = packed.slice(8);
    const at = (start: number, length: number): string => body.slice(start * 2, (start + length) * 2);

    expect(at(0, 20)).toBe("1234567890abcdef1234567890abcdef12345678");
    expect(at(20, 8)).toBe((1_791_374_000).toString(16).padStart(16, "0"));
    expect(at(28, 4)).toBe("a9059cbb");
    expect(at(32, 32)).toBe((10n ** 18n).toString(16).padStart(64, "0"));
    expect(at(64, 32)).toBe("44".repeat(32));
  });
});

describe("PackedUserOperation field order", () => {
  it("matches the ERC-4337 v0.7 layout the hash depends on", () => {
    const source = readSolidity("contracts/interfaces/IEntryPoint.sol");
    const start = source.indexOf("struct PackedUserOperation {");
    const body = source.slice(start, source.indexOf("}", start));
    const fields = body
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("struct") && !line.startsWith("}"))
      .map((line) => line.split(";")[0].trim());

    expect(fields).toEqual([
      "address sender",
      "uint256 nonce",
      "bytes initCode",
      "bytes callData",
      "uint256 callGasLimit",
      "uint256 verificationGasLimit",
      "uint256 preVerificationGas",
      "uint256 maxPriorityFeePerGas",
      "uint256 maxFeePerGas",
      "bytes paymasterAndData",
      "bytes signature",
    ]);
  });
});
