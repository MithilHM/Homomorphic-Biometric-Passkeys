/**
 * A strict, minimal CBOR (RFC 8949) decoder.
 *
 * WebAuthn attestation objects and COSE keys are CBOR, and we must parse them
 * ourselves rather than trusting a permissive library: an attacker who controls
 * the attestation blob controls the parser's input. This decoder rejects
 * indefinite lengths, non-minimal integer encodings, and trailing garbage.
 */

export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | Map<number | string, CborValue>
  | { [key: string]: CborValue };

export class CborError extends Error {}

class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}

  private need(count: number): void {
    if (this.offset + count > this.bytes.length) throw new CborError("truncated CBOR input");
  }

  u8(): number {
    this.need(1);
    return this.bytes[this.offset++];
  }

  slice(count: number): Uint8Array {
    this.need(count);
    const out = this.bytes.subarray(this.offset, this.offset + count);
    this.offset += count;
    return out;
  }

  argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    const bytes = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (bytes === 0) throw new CborError("reserved CBOR additional information");
    const raw = this.slice(bytes);
    let value = 0n;
    for (const byte of raw) value = (value << 8n) | BigInt(byte);
    return value;
  }
}

function readLength(reader: Reader, additional: number): number {
  if (additional === 31) throw new CborError("indefinite lengths are not accepted");
  const value = reader.argument(additional);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError("CBOR length is too large");
  const length = Number(value);
  if (additional < 24 && length !== additional) throw new CborError("non-minimal CBOR length encoding");
  return length;
}

function decodeValue(reader: Reader, depth: number): CborValue {
  if (depth > 16) throw new CborError("CBOR nesting is too deep");
  const initial = reader.u8();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  switch (major) {
    case 0: {
      const value = reader.argument(additional);
      return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
    }
    case 1: {
      const value = reader.argument(additional);
      const negative = -1n - value;
      return negative >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(negative) : negative;
    }
    case 2: {
      const length = readLength(reader, additional);
      return reader.slice(length).slice();
    }
    case 3: {
      const length = readLength(reader, additional);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(reader.slice(length));
      return text;
    }
    case 4: {
      const length = readLength(reader, additional);
      const items: CborValue[] = [];
      for (let i = 0; i < length; i++) items.push(decodeValue(reader, depth + 1));
      return items;
    }
    case 5: {
      const length = readLength(reader, additional);
      const map = new Map<number | string, CborValue>();
      for (let i = 0; i < length; i++) {
        const key = decodeValue(reader, depth + 1);
        if (typeof key !== "number" && typeof key !== "string") {
          throw new CborError("CBOR map keys must be integers or strings");
        }
        map.set(key, decodeValue(reader, depth + 1));
      }
      return map;
    }
    case 6: {
      // Tags are transparent for our purposes (e.g. tag 18 bignum).
      reader.argument(additional);
      return decodeValue(reader, depth + 1);
    }
    case 7: {
      switch (additional) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return undefined;
        case 25:
          return reader.argument(additional); // half-precision float, unused
        case 26: {
          const raw = reader.slice(4);
          return new DataView(raw.buffer, raw.byteOffset, 4).getFloat32(0, false);
        }
        case 27: {
          const raw = reader.slice(8);
          return new DataView(raw.buffer, raw.byteOffset, 8).getFloat64(0, false);
        }
        default:
          throw new CborError(`unsupported CBOR simple value ${additional}`);
      }
    }
    default:
      throw new CborError(`unsupported CBOR major type ${major}`);
  }
}

export function decodeCbor(bytes: Uint8Array): CborValue {
  const { value, length } = decodeCborWithLength(bytes);
  if (length !== bytes.length) throw new CborError("trailing bytes after CBOR value");
  return value;
}

/**
 * Decode one CBOR item and report how many bytes it consumed.
 *
 * WebAuthn needs the consumed length: `authenticatorData` embeds a COSE key
 * with no explicit size, so the key's extent is defined by where its CBOR
 * encoding stops rather than by a length prefix.
 */
export function decodeCborWithLength(bytes: Uint8Array): { value: CborValue; length: number } {
  const reader = new Reader(bytes);
  const value = decodeValue(reader, 0);
  return { value, length: reader.offset };
}

export function decodeCborMap(bytes: Uint8Array): Map<number | string, CborValue> {
  const value = decodeCbor(bytes);
  if (!(value instanceof Map)) throw new CborError("expected a CBOR map");
  return value;
}
