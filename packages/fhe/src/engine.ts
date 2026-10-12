/**
 * The homomorphic similarity engine used by the coprocessor and by the browser
 * client. Both sides speak this exact interface so that "the client encrypts,
 * the server only evaluates" is enforced by the type system, not by convention.
 */

import { keccak256Hex } from "@homobio/crypto-utils";
import { RingContext } from "./ring.js";
import { RlweScheme, type Ciphertext, type KeyMaterial, type SecretKeyShare } from "./scheme.js";
import {
  assertLayoutFits,
  decide,
  encodeEmbedding,
  similarityFromPlaintext,
  toPlaintext,
  type Decision,
  type Layout,
  type SimilarityResult,
} from "./encode.js";
import {
  base64UrlStringToBytes,
  bytesToBase64UrlString,
  parseCiphertext,
  serializeCiphertext,
} from "./serialize.js";
import { DEFAULT_FHE_PARAMS, type FheParams } from "./params.js";
import type { Poly } from "./sampler.js";

export interface PublicKeyBundle {
  engine: string;
  keyVersion: number;
  encodingVersion: number;
  ringDimension: number;
  modulus: string;
  scaleBits: number;
  embeddingDimension: number;
  securityLevelBits: number;
  publicKeyA: string;
  publicKeyB: string;
  /** keccak256 over the whole bundle — pinned by the client and on-chain. */
  fingerprint: string;
}

export interface FheCiphertext {
  ciphertext: string;
  commitment: string;
  ringDimension: number;
  modulus: string;
  scaleBits: number;
  dimension: number;
  /** Placement of the vector inside the plaintext polynomial. */
  layout: Layout | "product";
  engine: string;
  encodingVersion: number;
  /** Byte length of the raw payload, for budget accounting. */
  byteLength: number;
}

export interface KeySet {
  publicKey: PublicKeyBundle;
  shares: SecretKeyShare[];
  /** Full secret, only ever held transiently during key generation. */
  secret: Poly;
}

function polyToBase64(poly: Poly): string {
  const bytes = new Uint8Array(poly.length * 8);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < poly.length; i++) view.setBigUint64(i * 8, poly[i], false);
  return bytesToBase64UrlString(bytes);
}

function base64ToPoly(value: string): Poly {
  const bytes = base64UrlStringToBytes(value);
  if (bytes.length % 8 !== 0) throw new Error("polynomial payload is misaligned");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = new Array<bigint>(bytes.length / 8);
  for (let i = 0; i < out.length; i++) out[i] = view.getBigUint64(i * 8, false);
  return out;
}

export function publicKeyFingerprint(key: Omit<PublicKeyBundle, "fingerprint">): string {
  return keccak256Hex(
    [
      key.engine,
      String(key.keyVersion),
      String(key.encodingVersion),
      String(key.ringDimension),
      key.modulus,
      String(key.scaleBits),
      String(key.embeddingDimension),
      key.publicKeyA,
      key.publicKeyB,
    ].join("|"),
  );
}

export class HomomorphicEngine {
  readonly params: FheParams;
  readonly ring: RingContext;
  readonly scheme: RlweScheme;

  constructor(params: FheParams = DEFAULT_FHE_PARAMS) {
    this.params = params;
    this.ring = new RingContext(params.ringDimension, BigInt(params.modulus));
    this.scheme = new RlweScheme(this.ring);
  }

  /**
   * Create a key set. `threshold` decides how many shares must cooperate to
   * decrypt; all shares are required by construction.
   */
  generateKeySet(threshold = 3, keyVersion = 1): KeySet {
    const { publicKey, secretKey } = this.scheme.generateKeyPair();
    const secretSquared = this.ring.mul(secretKey, secretKey);
    const shares = RlweScheme.splitSecret(secretKey, secretSquared, threshold, this.ring.q);

    const bundle = {
      engine: this.params.engine,
      keyVersion,
      encodingVersion: this.params.encodingVersion,
      ringDimension: this.params.ringDimension,
      modulus: this.params.modulus,
      scaleBits: this.params.scaleBits,
      embeddingDimension: this.params.embeddingDimension,
      securityLevelBits: this.params.securityLevelBits,
      publicKeyA: polyToBase64(publicKey.publicKeyA),
      publicKeyB: polyToBase64(publicKey.publicKeyB),
    };

    return { publicKey: { ...bundle, fingerprint: publicKeyFingerprint(bundle) }, shares, secret: secretKey };
  }

  toKeyMaterial(key: PublicKeyBundle): KeyMaterial {
    if (key.ringDimension !== this.params.ringDimension || key.modulus !== this.params.modulus) {
      throw new Error("public key does not match the engine parameters");
    }
    const expected = publicKeyFingerprint(key);
    if (expected !== key.fingerprint) throw new Error("public key fingerprint mismatch");
    return {
      params: {
        ringDimension: key.ringDimension,
        modulus: key.modulus,
        securityLevelBits: key.securityLevelBits,
      },
      publicKeyA: base64ToPoly(key.publicKeyA),
      publicKeyB: base64ToPoly(key.publicKeyB),
    };
  }

  /** L2-normalise + quantise + encrypt. Runs on the client; the plaintext dies here. */
  encryptVector(
    key: PublicKeyBundle,
    vector: ArrayLike<number>,
    dimension?: number,
    layout: Layout = "low",
  ): FheCiphertext {
    const expected = dimension ?? this.params.embeddingDimension;
    if (vector.length !== expected) {
      throw new Error(`embedding dimension ${vector.length} does not match ${expected}`);
    }
    assertLayoutFits(this.ring, expected);
    const encoded = encodeEmbedding(vector, this.params.scaleBits);
    const plaintext = toPlaintext(this.ring, encoded, layout);
    const material = this.toKeyMaterial(key);
    const ct = this.scheme.encrypt(material, plaintext);
    return this.packCiphertext(ct, encoded.dimension, layout);
  }

  /**
   * Homomorphically multiply two ciphertexts. This is the only server-side op.
   *
   * One operand must use the `high` layout (enrolled templates) and the other
   * the `low` layout (live captures) so that the dot product collapses into
   * coefficient 0.
   */
  evaluateProduct(a: FheCiphertext, b: FheCiphertext): FheCiphertext {
    this.assertPairCompatible(a, b);
    const left = this.unpackCiphertext(a);
    const right = this.unpackCiphertext(b);
    const product = this.scheme.multiply(left, right);
    return this.packCiphertext(product, Math.min(a.dimension, b.dimension), "product");
  }

  /** Homomorphic sum of two ciphertexts (used for multi-sample templates). */
  evaluateSum(a: FheCiphertext, b: FheCiphertext): FheCiphertext {
    this.assertSameLayout(a, b);
    const sum = this.scheme.add(this.unpackCiphertext(a), this.unpackCiphertext(b));
    return this.packCiphertext(sum, Math.min(a.dimension, b.dimension), a.layout as Layout);
  }

  /**
   * Assert the two operands can be meaningfully multiplied: the enrolled
   * template is `high`, the live capture is `low`, and both must be 2-term.
   */
  assertPairCompatible(template: FheCiphertext, query: FheCiphertext): void {
    if (template.layout !== "high") throw new Error("enrolled template must use the high layout");
    if (query.layout !== "low") throw new Error("live capture must use the low layout");
    if (template.dimension !== query.dimension) {
      throw new Error(`dimension mismatch: template ${template.dimension} vs query ${query.dimension}`);
    }
  }

  private assertSameLayout(a: FheCiphertext, b: FheCiphertext): void {
    if (a.layout !== b.layout) throw new Error("cannot add ciphertexts with different layouts");
    if (a.dimension !== b.dimension) throw new Error("cannot add ciphertexts with different dimensions");
  }

  partialDecrypt(share: SecretKeyShare, ciphertext: FheCiphertext): Poly {
    return this.scheme.partialDecrypt(share, this.unpackCiphertext(ciphertext));
  }

  combinePartials(partials: Poly[], ciphertext: FheCiphertext): Poly {
    const ct = this.unpackCiphertext(ciphertext);
    return RlweScheme.recombine(partials, ct.p2, this.params.ringDimension, this.ring.q);
  }

  decrypt(secret: Poly, ciphertext: FheCiphertext): Poly {
    return this.scheme.decrypt(secret, this.unpackCiphertext(ciphertext));
  }

  similarity(plaintext: Poly, errorBound: number): SimilarityResult {
    return similarityFromPlaintext(this.ring, this.params, plaintext, errorBound);
  }

  decide(similarity: number, threshold: number, margin: number): Decision {
    return decide(similarity, threshold, margin);
  }

  packCiphertext(ct: Ciphertext, dimension: number, layout: Layout | "product"): FheCiphertext {
    const hasQuadratic = ct.p0.some((v) => v !== 0n);
    const polys = hasQuadratic ? [ct.p0, ct.p1, ct.p2] : [ct.p1, ct.p2];
    const bytes = serializeCiphertext(polys, this.params.ringDimension, this.ring.q);
    return {
      ciphertext: bytesToBase64UrlString(bytes),
      commitment: `0x${keccak256Hex(bytes)}`,
      ringDimension: this.params.ringDimension,
      modulus: this.params.modulus,
      scaleBits: this.params.scaleBits,
      dimension,
      layout,
      engine: this.params.engine,
      encodingVersion: this.params.encodingVersion,
      byteLength: bytes.length,
    };
  }

  unpackCiphertext(value: FheCiphertext): Ciphertext {
    if (value.engine !== this.params.engine) throw new Error("ciphertext engine mismatch");
    if (value.encodingVersion !== this.params.encodingVersion) throw new Error("ciphertext encoding mismatch");
    if (value.ringDimension !== this.params.ringDimension) throw new Error("ciphertext ring mismatch");
    if (value.modulus !== this.params.modulus) throw new Error("ciphertext modulus mismatch");
    if (value.scaleBits !== this.params.scaleBits) throw new Error("ciphertext scale mismatch");
    const bytes = base64UrlStringToBytes(value.ciphertext);
    const parsed = parseCiphertext(bytes, this.params.ringDimension, this.ring.q);
    if (parsed.commitment !== value.commitment) throw new Error("ciphertext commitment mismatch");
    // A 2-term ciphertext deserialises with an empty s^2 slot; normalise it to
    // zeros so downstream algebra never has to reason about short arrays.
    const p0 = parsed.polys[0].length === 0 ? this.ring.zero() : parsed.polys[0];
    return { p0, p1: parsed.polys[1], p2: parsed.polys[2] };
  }
}
