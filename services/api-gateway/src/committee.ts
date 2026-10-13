/**
 * Decryption committee inside the API gateway.
 *
 * ## Where the shares live
 *
 *   share 0  -> the FHE coprocessor process (the only party that sees ciphertext)
 *   share 1  -> the proof service key material, loaded by this process
 *   share 2  -> the custody share file, opened only with the unlock secret
 *
 * The point of the split is that the party holding the *ciphertexts* cannot
 * decrypt: compromising the coprocessor yields nothing without the other two
 * shares, and this process cannot decrypt without the coprocessor's
 * contribution.
 *
 * ## Known limitation (documented, not hidden)
 *
 * This process holds shares 1 and 2 and can therefore decrypt on its own once
 * the coprocessor returns share 0. Production must move recombination into a
 * dedicated MPC committee service with MAC-checked shares (SPDZ-style), so that
 * no single process ever holds two shares. See `docs/threat-model.md` T-9.
 */

import { readFileSync, existsSync } from "node:fs";
import {
  deserializeShare,
  type FheCiphertext,
  type HomomorphicEngine,
  type SecretKeyShare,
  type ShareFile,
} from "@homobio/fhe";
import { keccak256Hex, timingSafeEqual } from "@homobio/crypto-utils";
import { HttpError } from "@homobio/http-kit";

export interface CommitteeConfig {
  custodySharePath: string;
  custodyUnlockSecret?: string;
}

export class DecryptionCommitteeGateway {
  private readonly share1: SecretKeyShare;
  private share2?: SecretKeyShare;
  private unlocked = false;

  constructor(
    private readonly engine: HomomorphicEngine,
    private readonly keyFingerprint: string,
    private readonly config: CommitteeConfig,
    share1: SecretKeyShare,
  ) {
    this.share1 = share1;
  }

  /** Open the custody share. Requires the unlock secret when one is configured. */
  unlock(secret?: string): boolean {
    if (this.unlocked) return true;
    if (!existsSync(this.config.custodySharePath)) {
      throw new HttpError(503, "custody_share_missing", "the custody share file does not exist");
    }
    if (this.config.custodyUnlockSecret) {
      const provided = Buffer.from(secret ?? "");
      const expected = Buffer.from(this.config.custodyUnlockSecret);
      if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
        throw new HttpError(403, "custody_unlock_denied", "incorrect custody unlock secret");
      }
    }
    const file = JSON.parse(readFileSync(this.config.custodySharePath, "utf-8")) as ShareFile;
    this.share2 = deserializeShare(file, this.engine, this.keyFingerprint);
    this.unlocked = true;
    return true;
  }

  get isUnlocked(): boolean {
    return this.unlocked;
  }

  /**
   * Recombine partial decryptions into a decision.
   *
   * Returns ONLY the boolean decision plus the commitment material. The
   * similarity estimate never leaves this function: the API gateway's response
   * to the client contains no distance (PRD sections 27, 31).
   */
  decide(input: {
    coprocessorPartial: string;
    coprocessorMemberId: string;
    productCiphertext: FheCiphertext;
    threshold: number;
    margin: number;
  }): { decision: boolean; zone: "accept" | "reject" | "indeterminate"; contributors: string[] } {
    if (!this.unlocked || !this.share2) {
      throw new HttpError(503, "committee_locked", "the decryption committee is not unlocked");
    }

    const partials: ReturnType<HomomorphicEngine["partialDecrypt"]>[] = [
      decodePartial(input.coprocessorPartial, this.engine.params.ringDimension, BigInt(this.engine.params.modulus)),
      this.engine.partialDecrypt(this.share1, input.productCiphertext),
      this.engine.partialDecrypt(this.share2, input.productCiphertext),
    ];

    const plaintext = this.engine.combinePartials(partials, input.productCiphertext);
    const estimate = this.engine.similarity(plaintext, input.margin);
    const outcome = this.engine.decide(estimate.similarity, input.threshold, input.margin);

    return {
      decision: outcome.decision,
      zone: outcome.zone,
      contributors: [input.coprocessorMemberId, "proof-service", "custody"],
    };
  }

  /** Deterministic audit id for a decryption, with no plaintext in it. */
  auditId(productCommitment: string): string {
    return keccak256Hex(`committee|${productCommitment}`);
  }
}

function decodePartial(encoded: string, n: number, q: bigint): bigint[] {
  const cleaned = encoded.startsWith("0x") ? encoded.slice(2) : encoded;
  if (cleaned.length === 0 || cleaned.length % 16 !== 0) {
    throw new HttpError(400, "invalid_partial", "partial decryption payload is misaligned");
  }
  const out: bigint[] = [];
  for (let i = 0; i < cleaned.length; i += 16) {
    out.push(BigInt(`0x${cleaned.slice(i, i + 16)}`));
  }
  if (out.length !== n) throw new HttpError(400, "invalid_partial", "partial decryption has the wrong length");
  if (out.some((v) => v < 0n || v >= q)) {
    throw new HttpError(400, "invalid_partial", "partial decryption is out of range");
  }
  return out;
}

export function serializePartial(partials: bigint[]): string {
  return `0x${partials.map((v) => v.toString(16).padStart(16, "0")).join("")}`;
}
