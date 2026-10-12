/**
 * A software authenticator used by the test suite.
 *
 * It performs exactly what a real platform authenticator does: mint a P-256
 * key, build `authenticatorData` and `clientDataJSON`, and sign their
 * concatenation. Using it as a *verifier* fixture means the tests exercise the
 * real verification path (CBOR, COSE, flags, counters) rather than a stub.
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { concat } from "@homobio/crypto-utils";

export interface SoftwareAuthenticatorOptions {
  rpId: string;
  origin: string;
  signCount?: number;
  userPresent?: boolean;
  userVerified?: boolean;
  backupEligible?: boolean;
  backupState?: boolean;
  aaguid?: Uint8Array;
}

export class SoftwareAuthenticator {
  private readonly key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  private signCountValue: number;

  constructor(private readonly options: SoftwareAuthenticatorOptions) {
    this.signCountValue = options.signCount ?? 0;
  }

  get publicKeySpkiBase64Url(): string {
    const der = this.key.publicKey.export({ type: "spki", format: "der" }) as Buffer;
    return Buffer.from(der).toString("base64url");
  }

  bumpCounter(delta = 1): void {
    this.signCountValue += delta;
  }

  setCounter(value: number): void {
    this.signCountValue = value;
  }

  get counter(): number {
    return this.signCountValue;
  }

  private rpIdHash(): Buffer {
    return createHash("sha256").update(this.options.rpId).digest();
  }

  private flags(extra: number): number {
    let flags = 0;
    if (this.options.userPresent !== false) flags |= 0x01;
    if (this.options.userVerified !== false) flags |= 0x04;
    if (this.options.backupEligible) flags |= 0x08;
    if (this.options.backupState) flags |= 0x10;
    return flags | extra;
  }

  private clientData(type: string, challenge: string): Buffer {
    return Buffer.from(
      JSON.stringify({
        type,
        challenge,
        origin: this.options.origin,
        crossOrigin: false,
      }),
      "utf-8",
    );
  }

  /** Produce an attestation response (`webauthn.create`). */
  create(options: { challenge: string; credentialId?: Uint8Array }) {
    const credentialId = options.credentialId ?? randomBytes(32);
    const aaguid = this.options.aaguid ?? new Uint8Array(16).fill(7);

    const coseKey = encodeCborMap(
      new Map<number, unknown>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, rawX(this.key.publicKey.export({ type: "spki", format: "der" }) as Buffer)],
        [-3, rawY(this.key.publicKey.export({ type: "spki", format: "der" }) as Buffer)],
      ]),
    );

    const header = Buffer.concat([
      this.rpIdHash(),
      Buffer.from([this.flags(0x40)]),
      uint32(this.signCountValue),
      Buffer.from(aaguid),
      uint16(credentialId.length),
      Buffer.from(credentialId),
    ]);
    const authData = Buffer.concat([header, coseKey]);
    const attestationObject = encodeCborMap(
      new Map<string, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", new Uint8Array(authData)],
      ]),
    );

    return {
      credentialId: credentialId.toString("base64url"),
      clientDataJSON: this.clientData("webauthn.create", options.challenge).toString("base64url"),
      attestationObject: Buffer.from(attestationObject).toString("base64url"),
    };
  }

  /** Produce an assertion response (`webauthn.get`). */
  get(options: { challenge: string; credentialId?: Uint8Array }) {
    const clientDataJSON = this.clientData("webauthn.get", options.challenge);
    const authData = Buffer.concat([
      this.rpIdHash(),
      Buffer.from([this.flags(0)]),
      uint32(this.signCountValue),
    ]);

    const signer = createSign("SHA256");
    signer.update(Buffer.concat([authData, createHash("sha256").update(clientDataJSON).digest()]));
    signer.end();
    const signature = signer.sign({ key: this.key.privateKey, dsaEncoding: "ieee-p1363" });

    const out: Record<string, string | undefined> = {
      clientDataJSON: clientDataJSON.toString("base64url"),
      authenticatorData: authData.toString("base64url"),
      signature: signature.toString("base64url"),
    };
    if (options.credentialId) out.credentialId = Buffer.from(options.credentialId).toString("base64url");
    return out as { clientDataJSON: string; authenticatorData: string; signature: string; credentialId?: string };
  }
}

function uint32(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value >>> 0, 0);
  return out;
}

function uint16(value: number): Buffer {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
}

/** Extract the uncompressed point from a P-256 SPKI DER and split x / y. */
function rawPoint(der: Buffer): { x: Uint8Array; y: Uint8Array } {
  // The SubjectPublicKey BIT STRING is the last 65 bytes of the structure.
  const pointOffset = der.length - 65;
  if (der[pointOffset] !== 0x04) throw new Error("unexpected SPKI point encoding");
  return {
    x: new Uint8Array(der.subarray(pointOffset + 1, pointOffset + 33)),
    y: new Uint8Array(der.subarray(pointOffset + 33, pointOffset + 65)),
  };
}

const rawX = (der: Buffer): Uint8Array => rawPoint(der).x;
const rawY = (der: Buffer): Uint8Array => rawPoint(der).y;

// ---------------------------------------------------------------------------
// Minimal CBOR encoder (test fixture only)
// ---------------------------------------------------------------------------

export function encodeCbor(value: unknown): Uint8Array {
  if (value === null) return Uint8Array.of(0xf6);
  if (typeof value === "boolean") return Uint8Array.of(value ? 0xf5 : 0xf4);
  if (typeof value === "number") {
    if (value >= 0) return head(0, value);
    return head(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (value instanceof Map) {
    const parts: Uint8Array[] = [head(5, value.size)];
    for (const [key, item] of value) parts.push(encodeCbor(key), encodeCbor(item));
    return concat(...parts);
  }
  if (Array.isArray(value)) {
    const parts: Uint8Array[] = [head(4, value.length)];
    for (const item of value) parts.push(encodeCbor(item));
    return concat(...parts);
  }
  throw new Error(`cannot encode ${typeof value} as CBOR`);
}

function head(major: number, length: number): Uint8Array {
  const base = major << 5;
  if (length < 24) return Uint8Array.of(base | length);
  if (length < 0x100) return Uint8Array.of(base | 24, length);
  if (length < 0x10000) return Uint8Array.of(base | 25, (length >> 8) & 0xff, length & 0xff);
  if (length < 0x100000000) {
    return Uint8Array.of(base | 26, (length >>> 24) & 0xff, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff);
  }
  throw new Error("CBOR length too large for this fixture");
}

export const encodeCborMap = encodeCbor;
