/**
 * Threshold decryption committee.
 *
 * The FHE coprocessor holds one share; the proof service holds another; a third
 * lives behind its own unlock token. No single service can turn a decision
 * ciphertext into a similarity, and the coprocessor in particular — the party
 * that sees the ciphertext — can never decrypt on its own.
 *
 * ## Known limitation
 *
 * Shares are additively split and recombined, but partial decryptions are not
 * yet MAC-checked (SPDZ-style authentication). A malicious committee member
 * could therefore bias a single decision. Before production this must be
 * replaced by OpenFHE threshold CKKS with MAC-checked shares, or an MPC
 * committee service. See `docs/threat-model.md` (T-9).
 */

import { keccak256Hex } from "@homobio/crypto-utils";
import type { HomomorphicEngine, FheCiphertext } from "./engine.js";
import type { SecretKeyShare } from "./scheme.js";
import type { Poly } from "./sampler.js";
import { bytesToBase64UrlString, base64UrlStringToBytes } from "./serialize.js";

function polyToBase64(poly: Poly): string {
  const bytes = new Uint8Array(poly.length * 8);
  const v = new DataView(bytes.buffer);
  for (let i = 0; i < poly.length; i++) v.setBigUint64(i * 8, poly[i], false);
  return bytesToBase64UrlString(bytes);
}

function base64ToPoly(value: string): Poly {
  const bytes = base64UrlStringToBytes(value);
  if (bytes.length % 8 !== 0) throw new Error("share payload is misaligned");
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out = new Array<bigint>(bytes.length / 8);
  for (let i = 0; i < out.length; i++) out[i] = v.getBigUint64(i * 8, false);
  return out;
}

export interface ShareFile {
  shareIndex: number;
  ringDimension: number;
  modulus: string;
  keyFingerprint: string;
  sigma: string;
  tau: string;
}

export function serializeShare(share: SecretKeyShare, ring: HomomorphicEngine, keyFingerprint: string): ShareFile {
  return {
    shareIndex: share.shareIndex,
    ringDimension: ring.params.ringDimension,
    modulus: ring.params.modulus,
    keyFingerprint,
    sigma: polyToBase64(share.sigma),
    tau: polyToBase64(share.tau),
  };
}

export function deserializeShare(file: ShareFile, ring: HomomorphicEngine, keyFingerprint: string): SecretKeyShare {
  if (file.ringDimension !== ring.params.ringDimension || file.modulus !== ring.params.modulus) {
    throw new Error("share parameters do not match the engine");
  }
  if (file.keyFingerprint !== keyFingerprint) throw new Error("share belongs to a different key version");
  return { shareIndex: file.shareIndex, sigma: base64ToPoly(file.sigma), tau: base64ToPoly(file.tau) };
}

/** A single committee member's contribution to one decryption. */
export class CommitteeMember {
  readonly id: string;
  private readonly share: SecretKeyShare;

  constructor(id: string, share: SecretKeyShare) {
    this.id = id;
    this.share = share;
  }

  partialDecrypt(engine: HomomorphicEngine, ciphertext: FheCiphertext): Poly {
    return engine.partialDecrypt(this.share, ciphertext);
  }

  /** Stable identifier for a (member, ciphertext) pair, for the audit trail. */
  contributionId(ciphertextCommitment: string): string {
    return keccak256Hex(new TextEncoder().encode(`${this.id}:${ciphertextCommitment}`));
  }
}

export interface CommitteeResult {
  similarity: number;
  squaredDistance: number;
  errorBound: number;
  rawDot: bigint;
  contributors: string[];
}

/**
 * Combines `required` partial decryptions into a plaintext polynomial.
 *
 * The threshold is structural: the shares additively sum to the secret, so a
 * partial set is uniformly random and cannot be brute-forced from ciphertexts.
 */
export class DecryptionCommittee {
  private readonly members: CommitteeMember[];
  readonly threshold: number;

  constructor(members: CommitteeMember[]) {
    if (members.length < 2) throw new Error("a committee needs at least two members");
    this.members = members;
    this.threshold = members.length;
  }

  static fromShares(shares: SecretKeyShare[], ids: string[]): DecryptionCommittee {
    if (shares.length !== ids.length) throw new Error("share/id count mismatch");
    return new DecryptionCommittee(shares.map((share, i) => new CommitteeMember(ids[i], share)));
  }

  decrypt(engine: HomomorphicEngine, ciphertext: FheCiphertext, errorBound: number): CommitteeResult {
    const partials = this.members.map((m) => m.partialDecrypt(engine, ciphertext));
    const plaintext = engine.combinePartials(partials, ciphertext);
    const result = engine.similarity(plaintext, errorBound);
    return { ...result, contributors: this.members.map((m) => m.id) };
  }
}
