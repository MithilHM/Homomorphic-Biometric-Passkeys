/**
 * Proof / Attestation Service (PRD sections 13-15)
 *
 * The MVP decision path is *threshold decryption + signed attestation*, not a
 * zero-knowledge proof over the FHE arithmetic. That is an explicit, documented
 * choice: we do NOT claim the CKKS/RLWE computation is ZK-verified. We separate
 *   (1) privacy of the biometric input  -> FHE
 *   (2) authorization                   -> WebAuthn
 *   (3) verifiability of the decision   -> this service
 *
 * The service signs the canonical authorization hash with a secp256k1 key so
 * the on-chain verifier can use `ecrecover`, and it holds one share of the FHE
 * decryption committee.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { bytesToHex, hexToBytes, keccak256, keccak256Hex, nowSeconds } from "@homobio/crypto-utils";
import {
  authorizationHashHex,
  resultCommitmentHex,
  similarityToBps,
  type AuthorizationFields,
  type BiometricAuthorization,
  ProofSystem,
} from "@homobio/protocol-types";

const EIP191_PREFIX = Buffer.from("\x19Ethereum Signed Message:\n32", "utf-8");

export interface CommitteeKey {
  address: string;
  publicKeyPem: string;
}

export class ProofService {
  private readonly privateKey: import("node:crypto").KeyObject;
  private readonly publicKeyPem: string;
  readonly address: string;

  constructor(secretPem?: string) {
    if (secretPem) {
      this.privateKey = createPrivateKey(secretPem);
      this.publicKeyPem = createPublicKey(this.privateKey).export({ type: "spki", format: "pem" }).toString();
    } else {
      const generated = generateKeyPairSync("ec", { namedCurve: "secp256k1" });
      this.privateKey = generated.privateKey;
      this.publicKeyPem = generated.publicKey.export({ type: "spki", format: "pem" }).toString();
    }
    this.address = publicKeyToAddress(this.publicKeyPem);
  }

  committeeKey(): CommitteeKey {
    return { address: this.address, publicKeyPem: this.publicKeyPem };
  }

  /** keccak256("\x19Ethereum Signed Message:\n32" || keccak256(digest)) */
  static ethSignedDigest(digest: string): Buffer {
    const inner = keccak256(hexToBytes(`0x${digest}`));
    return Buffer.from(keccak256(Buffer.concat([EIP191_PREFIX, Buffer.from(inner)])));
  }

  /**
   * Sign the canonical authorization hash.
   *
   * EIP-191 prefixing means the signature can never be replayed as a raw
   * transaction on another chain.
   */
  signAttestation(fields: AuthorizationFields): { attestationHash: string; signature: string } {
    const attestationHash = authorizationHashHex(fields);
    const prefixed = ProofService.ethSignedDigest(attestationHash);
    const signature = cryptoSign("sha256", prefixed, { key: this.privateKey, dsaEncoding: "ieee-p1363" });
    return { attestationHash, signature: `0x${signature.toString("hex")}` };
  }
  /**
   * Build the authorization object the account consumes.
   *
   * Note what is NOT here: no image, no plaintext embedding, no plaintext
   * distance. Only a decision bit, the threshold that was applied, and
   * commitments to the ciphertexts that were compared.
   */
  authorize(input: {
    wallet: string;
    chainId: number;
    userOpHash: string;
    sessionId: string;
    policyHash: string;
    templateVersion: number;
    fheKeyVersion: number;
    templateCommitment: string;
    queryCommitment: string;
    threshold: number;
    decision: boolean;
    issuedAt?: number;
    ttlSeconds?: number;
    proofSystem?: ProofSystem;
    verifierVersion?: number;
    decisionProgramHash: string;
    version?: number;
  }): BiometricAuthorization {
    const issuedAt = input.issuedAt ?? nowSeconds();
    const expiresAt = issuedAt + (input.ttlSeconds ?? 180);

    const fields: AuthorizationFields = {
      version: input.version ?? 1,
      wallet: input.wallet.toLowerCase(),
      chainId: input.chainId,
      userOpHash: input.userOpHash.toLowerCase(),
      sessionId: input.sessionId,
      policyHash: input.policyHash,
      templateVersion: input.templateVersion,
      fheKeyVersion: input.fheKeyVersion,
      decision: input.decision,
      thresholdBps: similarityToBps(input.threshold),
      resultCommitment: resultCommitmentHex({
        sessionId: input.sessionId,
        templateCommitment: input.templateCommitment,
        queryCommitment: input.queryCommitment,
        decision: input.decision,
      }),
      issuedAt,
      expiresAt,
      proofSystem: input.proofSystem ?? ProofSystem.ThresholdAttestation,
      verifierVersion: input.verifierVersion ?? 1,
      decisionProgramHash: input.decisionProgramHash,
    };

    const { attestationHash, signature } = this.signAttestation(fields);
    return { ...fields, attestationHash, signature };
  }

  /** Local verification helper for the API gateway's submit path. */
  verify(authorization: BiometricAuthorization, committeeKey: CommitteeKey): boolean {
    if (authorizationHashHex(authorization) !== authorization.attestationHash) return false;
    try {
      const prefixed = ProofService.ethSignedDigest(authorization.attestationHash);
      const raw = authorization.signature.startsWith("0x")
        ? authorization.signature
        : `0x${authorization.signature}`;
      const signature = Buffer.from(hexToBytes(raw));
      // Web3 signatures are raw r||s, which is exactly what `sign` produced.
      return cryptoVerify(
        "sha256",
        prefixed,
        { key: createPublicKey(committeeKey.publicKeyPem), dsaEncoding: "ieee-p1363" },
        signature,
      );
    } catch {
      return false;
    }
  }
}

export function publicKeyToAddress(publicKeyPem: string): string {
  const spki = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  // SubjectPublicKeyInfo for secp256k1 has a 23-byte prefix; the uncompressed
  // point is the last 65 bytes and the address is the keccak256 tail.
  const point = spki.subarray(spki.length - 65);
  return `0x${bytesToHex(keccak256(point)).slice(-40)}`;
}

/**
 * The public-input digest an SP1 program would commit to.
 *
 * Exposed so the circuit, the prover and the verifier all derive the same
 * statement. The `Sp1` proof system is selectable but the service reports it as
 * unavailable until a prover is configured â€” we never fabricate a "proof".
 */
export function sp1PublicInputsHash(fields: AuthorizationFields): string {
  return keccak256Hex(
    `HOMOBIO/SP1-PUBLIC-INPUTS-V1|${authorizationHashHex(fields)}|${fields.sessionId}|${fields.expiresAt}`,
  );
}
