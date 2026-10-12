/**
 * ERC-4337 (v0.7) UserOperation hashing and construction for Monad.
 *
 * The account hash is the single most important binding in the system: the passkey
 * signature and the biometric authorization both commit to it, and the EntryPoint
 * recomputes it from the calldata it receives. If this file and the Solidity
 * disagree by a byte, every operation reverts — so the encoding is cross-checked
 * against viem in `packages/userop/test/userop.test.ts` and against `solc`
 * output in `contracts/test/cross-language.test.ts`.
 */

import { abiEncode, bytesToHex, hexToBytes, keccak256Hex } from "@homobio/crypto-utils";

export interface PackedUserOperation {
  sender: string;
  nonce: bigint;
  initCode: string;
  callData: string;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  paymasterAndData: string;
  signature: string;
}

export interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  entryPoint: string;
  bundlerUrl?: string;
  nativeCurrency: { name: string; symbol: string; decimals: number };
  explorerUrl?: string;
}

/**
 * Networks.
 *
 * `entryPoint` is configuration, not a constant: the deployed EntryPoint address
 * must be confirmed against the exact target network version before use, which
 * is why the API gateway refuses to start without an explicit value in
 * production mode.
 */
export const MONAD_TESTNET: ChainConfig = {
  chainId: 143,
  name: "Monad Testnet",
  rpcUrl: process.env.MONAD_TESTNET_RPC ?? "https://testnet-rpc.monad.xyz",
  entryPoint: process.env.MONAD_ENTRY_POINT ?? "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
};

export const MONAD_MAINNET: ChainConfig = {
  chainId: 1,
  name: "Monad",
  rpcUrl: process.env.MONAD_RPC ?? "https://rpc.monad.xyz",
  entryPoint: process.env.MONAD_ENTRY_POINT ?? "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
};

/** Nonce key layout (PRD section 17.2): the top byte selects the workflow. */
export enum NonceDomain {
  Wallet = 0,
  SessionKey = 1,
  Recovery = 2,
  DeviceManagement = 3,
  Paymaster = 4,
}

const NONCE_DOMAIN_SHIFT = 248n;

export function encodeNonce(domain: NonceDomain, sequence: number | bigint): bigint {
  const seq = BigInt(sequence);
  if (seq < 0n || seq >= 1n << NONCE_DOMAIN_SHIFT) {
    throw new Error("nonce sequence does not fit in the domain's key range");
  }
  return (BigInt(domain) << NONCE_DOMAIN_SHIFT) | seq;
}

export function decodeNonce(nonce: bigint): { domain: NonceDomain; sequence: bigint } {
  return {
    domain: Number((nonce >> NONCE_DOMAIN_SHIFT) & 0xffn) as NonceDomain,
    sequence: nonce & ((1n << NONCE_DOMAIN_SHIFT) - 1n),
  };
}

/** keccak256(abi.encode(packedUserOp)) — EntryPoint's inner step. */
export function hashPackedUserOperation(userOp: PackedUserOperation): string {
  const encoded = abiEncode([
    { type: "address", value: userOp.sender },
    { type: "uint256", value: userOp.nonce },
    { type: "bytes", value: userOp.initCode },
    { type: "bytes", value: userOp.callData },
    { type: "uint256", value: userOp.callGasLimit },
    { type: "uint256", value: userOp.verificationGasLimit },
    { type: "uint256", value: userOp.preVerificationGas },
    { type: "uint256", value: userOp.maxPriorityFeePerGas },
    { type: "uint256", value: userOp.maxFeePerGas },
    { type: "bytes", value: userOp.paymasterAndData },
    { type: "bytes", value: userOp.signature },
  ]);
  return keccak256Hex(encoded);
}

/**
 * The canonical userOpHash:
 *
 *   keccak256(abi.encode(keccak256(abi.encode(userOp)), entryPoint, chainId))
 */
export function getUserOpHash(userOp: PackedUserOperation, entryPoint: string, chainId: number): string {
  const inner = hashPackedUserOperation(userOp);
  return keccak256Hex(
    abiEncode([
      { type: "bytes32", value: `0x${inner}` },
      { type: "address", value: entryPoint },
      { type: "uint256", value: BigInt(chainId) },
    ]),
  );
}

/** Counterfactual deployment payload: `factory.createAccount{value}(initCode)`. */
export function buildInitCode(factory: string, callData: string): string {
  const selector = keccak256Hex("createAccount(address,bytes)").slice(0, 8);
  const encoded = abiEncode([
    { type: "address", value: "0x0000000000000000000000000000000000000000" },
    { type: "bytes", value: callData },
  ]);
  return `${factory}${selector}${bytesToHex(encoded)}`;
}

export interface GasPolicy {
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export const DEFAULT_GAS_POLICY: GasPolicy = {
  callGasLimit: 400_000n,
  // Passkey + attestation + FHE-commitment checks are all inside validation.
  verificationGasLimit: 900_000n,
  preVerificationGas: 120_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_500_000_000n,
};

export class UserOperationBuilder {
  private readonly op: PackedUserOperation;

  constructor(sender: string, defaults: Partial<GasPolicy> = {}) {
    const policy = { ...DEFAULT_GAS_POLICY, ...defaults };
    this.op = {
      sender: sender.toLowerCase(),
      nonce: 0n,
      initCode: "0x",
      callData: "0x",
      callGasLimit: policy.callGasLimit,
      verificationGasLimit: policy.verificationGasLimit,
      preVerificationGas: policy.preVerificationGas,
      maxPriorityFeePerGas: policy.maxPriorityFeePerGas,
      maxFeePerGas: policy.maxFeePerGas,
      paymasterAndData: "0x",
      signature: "0x",
    };
  }

  nonce(domain: NonceDomain, sequence: number | bigint): this {
    this.op.nonce = encodeNonce(domain, sequence);
    return this;
  }

  rawNonce(nonce: bigint): this {
    this.op.nonce = nonce;
    return this;
  }

  callData(callData: string): this {
    this.op.callData = callData;
    return this;
  }

  initCode(initCode: string): this {
    this.op.initCode = initCode;
    return this;
  }

  paymasterAndData(data: string): this {
    this.op.paymasterAndData = data;
    return this;
  }

  gas(policy: Partial<GasPolicy>): this {
    Object.assign(this.op, policy);
    return this;
  }

  signature(signature: string): this {
    this.op.signature = signature;
    return this;
  }

  build(): PackedUserOperation {
    if (this.op.maxFeePerGas < this.op.maxPriorityFeePerGas) {
      throw new Error("maxFeePerGas must be at least maxPriorityFeePerGas");
    }
    return { ...this.op };
  }

  /** JSON representation for the API layer (bigints become hex strings). */
  toJSON(): Record<string, string> {
    const op = this.build();
    return {
      sender: op.sender,
      nonce: `0x${op.nonce.toString(16)}`,
      initCode: op.initCode,
      callData: op.callData,
      callGasLimit: `0x${op.callGasLimit.toString(16)}`,
      verificationGasLimit: `0x${op.verificationGasLimit.toString(16)}`,
      preVerificationGas: `0x${op.preVerificationGas.toString(16)}`,
      maxFeePerGas: `0x${op.maxFeePerGas.toString(16)}`,
      maxPriorityFeePerGas: `0x${op.maxPriorityFeePerGas.toString(16)}`,
      paymasterAndData: op.paymasterAndData,
      signature: op.signature,
    };
  }
}

export function fromJSON(value: Record<string, string>): PackedUserOperation {
  const toBig = (v: string): bigint => {
    if (v === undefined || v === null || v === "") return 0n;
    if (typeof v === "string" && v.startsWith("0x")) return BigInt(v);
    return BigInt(v);
  };
  return {
    sender: String(value.sender).toLowerCase(),
    nonce: toBig(value.nonce),
    initCode: value.initCode || "0x",
    callData: value.callData || "0x",
    callGasLimit: toBig(value.callGasLimit),
    verificationGasLimit: toBig(value.verificationGasLimit),
    preVerificationGas: toBig(value.preVerificationGas),
    maxFeePerGas: toBig(value.maxFeePerGas),
    maxPriorityFeePerGas: toBig(value.maxPriorityFeePerGas),
    paymasterAndData: value.paymasterAndData || "0x",
    signature: value.signature || "0x",
  };
}


/* ---------------------------------------------------------------------------
 * The `userOp.signature` envelopes
 * ---------------------------------------------------------------------------
 *
 * The AUTHORIZATION envelope is packed by `@homobio/sdk`'s
 * `packAuthorizationEnvelope` (`packages/sdk/src/envelope.ts`), which mirrors
 * `BiometricSmartAccount._decodeAuthorization` byte for byte.
 *
 * It deliberately does not live here. This package must not carry a second,
 * parallel definition of a wire format the account decodes index-based: two
 * encoders for magic `0x48` is exactly how a client ends up submitting an
 * envelope the contract cannot parse.
 *
 * The SESSION envelope does belong next to the hash it is validated against.
 */

export const MAGIC_AUTHORIZATION_ENVELOPE = 0x48;
export const MAGIC_SESSION_ENVELOPE = 0x53;

/**
 * Session-key envelope for `userOp.signature`.
 *
 * Layout, all fixed width, exactly as `BiometricSmartAccount._validateSessionKey`
 * reads it (96-byte body):
 *
 *   0x53 | uint16 bodyLength | address key | uint64 validUntil
 *        | bytes4 selector | uint256 value | bytes32 scopeHash
 */
export interface SessionSignatureEnvelope {
  sessionKey: string;
  validUntil: number;
  selector: string;
  valueWei: string | bigint;
  /** Must equal `SessionKeyRegistry.scopeHashes(key)` for the live grant. */
  scopeHash: string;
}

export const SESSION_ENVELOPE_BODY_BYTES = 96;

export function packSessionEnvelope(envelope: SessionSignatureEnvelope): string {
  const selector = hexToBytes(
    envelope.selector.startsWith("0x") ? envelope.selector : `0x${envelope.selector}`,
  );
  if (selector.length !== 4) throw new Error("selector must be 4 bytes");

  const value = BigInt(envelope.valueWei);
  if (value < 0n || value >= 1n << 256n) throw new Error("value does not fit in uint256");
  const validUntil = BigInt(envelope.validUntil);
  if (validUntil < 0n || validUntil >= 1n << 64n) throw new Error("validUntil does not fit in uint64");

  const body =
    bytesToHex(hexToBytes(envelope.sessionKey.toLowerCase())) +
    validUntil.toString(16).padStart(16, "0") +
    bytesToHex(selector) +
    value.toString(16).padStart(64, "0") +
    bytesToHex(hexToBytes(envelope.scopeHash));

  const bodyLength = body.length / 2;
  if (bodyLength !== SESSION_ENVELOPE_BODY_BYTES) {
    throw new Error(`session envelope body is ${bodyLength} bytes, expected ${SESSION_ENVELOPE_BODY_BYTES}`);
  }
  return `0x53${bodyLength.toString(16).padStart(4, "0")}${body}`;
}

/** Inverse of {@link packSessionEnvelope}; used by tests and the operator console. */
export function unpackSessionEnvelope(packed: string): SessionSignatureEnvelope {
  const hex = packed.startsWith("0x") ? packed.slice(2) : packed;
  if (hex.slice(0, 2) !== "53") throw new Error("not a session envelope");
  const bodyLength = Number.parseInt(hex.slice(2, 6), 16);
  if (bodyLength !== SESSION_ENVELOPE_BODY_BYTES) throw new Error("session envelope has the wrong length");
  if (hex.length !== 6 + bodyLength * 2) throw new Error("session envelope is truncated");
  const body = hex.slice(6);
  return {
    sessionKey: `0x${body.slice(0, 40)}`,
    validUntil: Number.parseInt(body.slice(40, 56), 16),
    selector: `0x${body.slice(56, 64)}`,
    valueWei: BigInt(`0x${body.slice(64, 128)}`),
    scopeHash: `0x${body.slice(128, 192)}`,
  };
}
