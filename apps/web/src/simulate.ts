/**
 * Human-readable transaction preview (M3.8, closes T-13).
 *
 * Problem: the wallet review step asked the user to approve blind calldata.
 * This module decodes the calldata before signing so the review screen can
 * show token, amount and recipient in plain language.
 *
 * Scope (deliberately small, dependency-free):
 *   - ERC-20 transfer(address,uint256), selector 0xa9059cbb
 *   - ERC-20 approve(address,uint256),  selector 0x095ea7b3
 *   - Native currency sends, read from the operation's value field
 *   - Account execute(address,uint256,bytes) wrappers (0xb61d27f6), which are
 *     unwrapped first so the token call inside is what gets described
 *
 * Anything else decodes to an explicit `unrecognized` state that carries only
 * the selector and a short fingerprint. The decoder never guesses: malformed
 * lengths, non-zero address padding, trailing bytes and missing context (no
 * token contract, no destination) all decode to `unrecognized`, never to a
 * best-effort parse. All functions are pure — the only UI call is the one
 * `previewUserOperation(...)` line in the authenticate review step.
 */

export const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
export const ERC20_APPROVE_SELECTOR = "0x095ea7b3";
export const ACCOUNT_EXECUTE_SELECTOR = "0xb61d27f6";

/** Native currency symbol shown on preview lines. */
export const NATIVE_SYMBOL = "MON";

/** Assumed token decimals when formatting raw uint256 amounts. */
export const DEFAULT_TOKEN_DECIMALS = 18;

export interface PreviewInput {
  /** Hex calldata of the operation (the account execute wrapper is unwrapped). */
  callData: string;
  /**
   * Token contract for a direct (non-execute-wrapped) ERC-20 call.
   * Required for transfer/approve: without it the decoder reports
   * `unrecognized` instead of guessing which token is involved.
   */
  token?: string;
  /** Destination for a plain native send with empty calldata. */
  to?: string;
  /** Native currency amount in wei (hex string, decimal string, number or bigint). */
  value?: bigint | string | number;
}

export type DecodedOperation =
  | { kind: "erc20-transfer"; token: string; to: string; amount: bigint; value: bigint }
  | { kind: "erc20-approve"; token: string; spender: string; amount: bigint; value: bigint }
  | { kind: "native"; to: string; value: bigint }
  | { kind: "unrecognized"; selector: string; fingerprint: string };

/**
 * Decode an operation into a structured preview model. Pure: no I/O, no
 * hashing beyond a display fingerprint, and never throws on malformed
 * calldata — malformed input yields `unrecognized`.
 */
export function decodeUserOperation(input: PreviewInput): DecodedOperation {
  const value = parseWei(input.value ?? 0n);
  const hex = normalizeHex(input.callData);
  if (hex === null) return { kind: "unrecognized", selector: "none", fingerprint: "none" };
  const bytes = hexToBytesArray(hex);
  if (bytes.length === 0) {
    if (value > 0n && isAddress(input.to)) {
      return { kind: "native", to: input.to.toLowerCase(), value };
    }
    return { kind: "unrecognized", selector: "none", fingerprint: fingerprintBytes(bytes) };
  }
  const selector = selectorOfBytes(bytes);
  if (selector === ACCOUNT_EXECUTE_SELECTOR) return decodeExecute(bytes);
  if (selector === ERC20_TRANSFER_SELECTOR || selector === ERC20_APPROVE_SELECTOR) {
    return decodeDirectErc20(selector, bytes, input.token, value);
  }
  return { kind: "unrecognized", selector, fingerprint: fingerprintBytes(bytes) };
}

/**
 * One-line plain-language preview for the review screen. Recognized calls
 * read as "Send X of token T to 0x..."; anything else reads as an explicit
 * warning that names the selector and fingerprint and shows nothing else.
 */
export function previewUserOperation(input: PreviewInput): string {
  const decoded = decodeUserOperation(input);
  switch (decoded.kind) {
    case "erc20-transfer": {
      const extra =
        decoded.value > 0n ? `, plus ${formatAmount(decoded.value)} ${NATIVE_SYMBOL}` : "";
      return (
        `Send ${formatAmount(decoded.amount)} of token ${decoded.token} ` +
        `to ${decoded.to}${extra}. ` +
        `Only approve this with your passkey and face if you recognize the token and the address.`
      );
    }
    case "erc20-approve": {
      const extra =
        decoded.value > 0n ? `, plus ${formatAmount(decoded.value)} ${NATIVE_SYMBOL}` : "";
      return (
        `Allow ${decoded.spender} to spend up to ${formatAmount(decoded.amount)} ` +
        `of token ${decoded.token}${extra}. ` +
        `This can drain your balance of that token. ` +
        `Only approve this with your passkey and face if you trust the spender.`
      );
    }
    case "native":
      return (
        `Send ${formatAmount(decoded.value)} ${NATIVE_SYMBOL} to ${decoded.to}. ` +
        `Only approve this with your passkey and face if you recognize the address.`
      );
    case "unrecognized":
      return (
        `We could not recognize this transaction ` +
        `(type ${decoded.selector}, fingerprint ${decoded.fingerprint}). ` +
        `No amount or recipient could be read. ` +
        `Do not approve it unless you trust where it came from.`
      );
  }
}

/**
 * Format a raw uint256 amount with 18 decimals: 1000000000000000000 -> "1",
 * 1500000000000000000 -> "1.5", 1 -> "0.000000000000000001", 0 -> "0".
 */
export function formatAmount(amount: bigint, decimals: number = DEFAULT_TOKEN_DECIMALS): string {
  if (amount < 0n) throw new Error("amount must not be negative");
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 77) {
    throw new Error("decimals must be an integer between 0 and 77");
  }
  if (decimals === 0) return amount.toString();
  const base = 10n ** BigInt(decimals);
  const whole = amount / base;
  const frac = amount % base;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${whole.toString()}.${fracStr}`;
}

/* ------------------------------ internals ------------------------------ */

function decodeDirectErc20(
  selector: string,
  bytes: Uint8Array,
  token: string | undefined,
  value: bigint,
): DecodedOperation {
  const unrecognized = (): DecodedOperation => ({
    kind: "unrecognized",
    selector,
    fingerprint: fingerprintBytes(bytes),
  });
  // transfer/approve take exactly two 32-byte words; anything longer or
  // shorter is not a call we understand, so report it, never truncate it.
  if (bytes.length !== 68) return unrecognized();
  const counterparty = parseAddressWord(bytes.subarray(4, 36));
  if (counterparty === null) return unrecognized();
  const amount = parseUint256Word(bytes.subarray(36, 68));
  if (!isAddress(token)) return unrecognized();
  const tokenAddress = token.toLowerCase();
  if (selector === ERC20_TRANSFER_SELECTOR) {
    return { kind: "erc20-transfer", token: tokenAddress, to: counterparty, amount, value };
  }
  return { kind: "erc20-approve", token: tokenAddress, spender: counterparty, amount, value };
}

/**
 * Unwrap account execute(address target, uint256 value, bytes data) and
 * decode the call inside with the target as the token contract. The outer
 * value field is the native amount being sent.
 */
function decodeExecute(bytes: Uint8Array): DecodedOperation {
  const unrecognized = (): DecodedOperation => ({
    kind: "unrecognized",
    selector: ACCOUNT_EXECUTE_SELECTOR,
    fingerprint: fingerprintBytes(bytes),
  });
  // 4-byte selector + 3 head words (target, value, bytes offset).
  if (bytes.length < 100) return unrecognized();
  const target = parseAddressWord(bytes.subarray(4, 36));
  if (target === null) return unrecognized();
  const outerValue = parseUint256Word(bytes.subarray(36, 68));
  const offset = parseUint256Word(bytes.subarray(68, 100));
  // execute has exactly three parameters, so the bytes offset must be 96.
  if (offset !== 96n) return unrecognized();
  const lengthWordAt = 100;
  if (bytes.length < lengthWordAt + 32) return unrecognized();
  const innerLength = parseUint256Word(bytes.subarray(lengthWordAt, lengthWordAt + 32));
  if (innerLength > BigInt(Number.MAX_SAFE_INTEGER)) return unrecognized();
  const len = Number(innerLength);
  const innerStart = lengthWordAt + 32;
  // Exact match only: trailing bytes mean this is not plain execute data.
  if (bytes.length !== innerStart + len) return unrecognized();
  const inner = bytes.subarray(innerStart, innerStart + len);
  if (inner.length === 0) {
    if (outerValue > 0n) return { kind: "native", to: target, value: outerValue };
    return {
      kind: "unrecognized",
      selector: ACCOUNT_EXECUTE_SELECTOR,
      fingerprint: fingerprintBytes(bytes),
    };
  }
  const innerSelector = selectorOfBytes(inner);
  if (innerSelector === ERC20_TRANSFER_SELECTOR || innerSelector === ERC20_APPROVE_SELECTOR) {
    const decoded = decodeDirectErc20(innerSelector, inner, target, outerValue);
    // decodeDirectErc20 only reports unrecognized here when the inner data is
    // malformed; re-tag it as the outer execute type so the review screen
    // shows what the user actually signed, not the inner fragment.
    if (decoded.kind === "unrecognized") return unrecognized();
    return decoded;
  }
  return unrecognized();
}

function selectorOfBytes(bytes: Uint8Array): string {
  if (bytes.length < 4) return "none";
  return `0x${bytesToHex(bytes.subarray(0, 4))}`;
}

/** FNV-1a 32-bit display tag (not cryptographic, only so two unknown payloads can be told apart). */
function fingerprintBytes(bytes: Uint8Array): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i] as number;
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

/** Strict hex parser: returns null (never throws) for non-hex input. */
function normalizeHex(callData: string): string | null {
  if (typeof callData !== "string") return null;
  const trimmed = callData.trim();
  const bare = trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
  if (bare.length === 0) return "";
  if (bare.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(bare)) return null;
  return bare.toLowerCase();
}

function hexToBytesArray(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * Parse a 32-byte ABI word as an address. Returns null when the leading
 * 12 bytes are not zero — that word is not an address, so the call is not
 * decoded rather than decoded wrongly.
 */
function parseAddressWord(word: Uint8Array): string | null {
  if (word.length !== 32) return null;
  for (let i = 0; i < 12; i++) {
    if (word[i] !== 0) return null;
  }
  return `0x${bytesToHex(word.subarray(12, 32))}`;
}

function parseUint256Word(word: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(word)}`);
}

function isAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function parseWei(value: bigint | string | number): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error("value must not be negative");
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("value must be a non-negative safe integer");
    return BigInt(value);
  }
  const trimmed = value.trim();
  if (/^0[xX][0-9a-fA-F]+$/.test(trimmed)) return BigInt(trimmed);
  if (/^[0-9]+$/.test(trimmed)) return BigInt(trimmed);
  throw new Error("value must be a hex string, decimal string, number or bigint");
}
