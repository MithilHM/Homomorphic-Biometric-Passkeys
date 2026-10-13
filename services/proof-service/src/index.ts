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
 * The service signs the canonical authorization hash with a secp256k1 key using
 * standard EIP-191 personal-message signing — exactly what
 * `AuthorizationVerifier._recover` verifies on-chain with `ecrecover`:
 *   digest    = keccak256("\x19Ethereum Signed Message:\n32" || attestationHash)
 *   signature = 65-byte r || s || v (v is 27 or 28)
 * The signer address is the last 20 bytes of keccak256(X || Y) (no 0x04 prefix).
 */

import { createPrivateKey, createPublicKey } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, concat, hexToBytes, keccak256, keccak256Hex, nowSeconds, randomBytes } from "@homobio/crypto-utils";
import {
  authorizationHashHex,
  resultCommitmentHex,
  similarityToBps,
  type AuthorizationFields,
  type BiometricAuthorization,
  ProofSystem,
} from "@homobio/protocol-types";

export const EIP191_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");

export interface CommitteeKey {
  address: string;
  publicKeyPem: string;
}

function toRawBytes(value: Uint8Array): Uint8Array {
  return value instanceof Uint8Array && value.constructor.name === "Uint8Array"
    ? value
    : Uint8Array.from(value);
}

export class ProofService {
  private readonly privateKeyBytes: Uint8Array;
  private readonly publicKeyPem: string;
  readonly address: string;

  constructor(secret?: string) {
    this.privateKeyBytes = loadPrivateKey(secret);
    const publicKey = secp256k1.getPublicKey(this.privateKeyBytes, false);
    this.address = addressFromUncompressedPoint(publicKey);
    this.publicKeyPem = pemFromRawPrivateKey(this.privateKeyBytes, publicKey);
  }

  committeeKey(): CommitteeKey {
    return { address: this.address, publicKeyPem: this.publicKeyPem };
  }

  /** keccak256("\x19Ethereum Signed Message:\n32" || attestationHashBytes) */
  static ethSignedDigest(digest: string): Uint8Array {
    return toRawBytes(keccak256(concat(EIP191_PREFIX, hexToBytes(digest.startsWith("0x") ? digest : `0x${digest}`))));
  }

  /**
   * Sign the canonical authorization hash.
   *
   * Standard EIP-191 personal-message signing over the 32-byte attestation
   * hash, so the signature verifies both here and on-chain via `ecrecover`.
   */
  signAttestation(fields: AuthorizationFields): { attestationHash: string; signature: string } {
    const attestationHash = authorizationHashHex(fields);
    const digest = toRawBytes(ProofService.ethSignedDigest(attestationHash));
    const sig = secp256k1.sign(digest, this.privateKeyBytes);
    const compact = toRawBytes(sig.toCompactRawBytes());
    const v = 27 + (sig.recovery ?? 0);
    return { attestationHash, signature: `0x${bytesToHex(compact)}${v.toString(16).padStart(2, "0")}` };
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
      const digest = toRawBytes(ProofService.ethSignedDigest(authorization.attestationHash));
      const raw = authorization.signature.startsWith("0x") ? authorization.signature : `0x${authorization.signature}`;
      const bytes = toRawBytes(hexToBytes(raw));
      // Standard 65-byte r || s || v. A legacy 64-byte r || s is tried with
      // both recovery bits so rotations never brick in-flight authorizations.
      const candidates: Array<{ compact: Uint8Array; recovery: number }> = [];
      if (bytes.length === 65) {
        let v = bytes[64];
        if (v < 27) v += 27;
        if (v !== 27 && v !== 28) return false;
        candidates.push({ compact: bytes.slice(0, 64), recovery: v - 27 });
      } else if (bytes.length === 64) {
        candidates.push({ compact: bytes, recovery: 0 }, { compact: bytes, recovery: 1 });
      } else {
        return false;
      }
      const expected = committeeKey.address.toLowerCase();
      for (const { compact, recovery } of candidates) {
        const signature = secp256k1.Signature.fromCompact(compact).addRecoveryBit(recovery);
        const point = toRawBytes(signature.recoverPublicKey(digest).toRawBytes(false));
        if (addressFromUncompressedPoint(point) === expected) return true;
      }
      return false;
    } catch {
      return false;
    }
  }
}

/** Ethereum address from an uncompressed (65-byte, 0x04-prefixed) point. */
export function addressFromUncompressedPoint(point: Uint8Array): string {
  const raw = toRawBytes(point);
  const body = raw.length === 65 ? raw.slice(1) : raw;
  return `0x${bytesToHex(toRawBytes(keccak256(body))).slice(-40)}`;
}

/** Legacy helper: address from a PEM SPKI key (drops the 0x04 prefix). */
export function publicKeyToAddress(publicKeyPem: string): string {
  const spki = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }) as Buffer;
  // SubjectPublicKeyInfo for secp256k1 ends with the 65-byte uncompressed
  // point; the address commits to X || Y only, never the 0x04 prefix.
  const point = new Uint8Array(spki.subarray(spki.length - 65));
  return addressFromUncompressedPoint(point);
}

function loadPrivateKey(secret?: string): Uint8Array {
  if (secret && secret.includes("BEGIN")) {
    const key = createPrivateKey(secret);
    const jwk = key.export({ format: "jwk" }) as { d?: string; crv?: string };
    if ((jwk.crv !== "secp256K1" && jwk.crv !== "secp256k1") || !jwk.d) {
      throw new Error("committee secret is not a secp256k1 private key");
    }
    const raw = base64UrlToBytes(jwk.d);
    if (raw.length !== 32) throw new Error("committee secret is not 32 bytes");
    return toRawBytes(raw);
  }
  if (secret && /^0x[0-9a-fA-F]{64}$/.test(secret.trim())) {
    return toRawBytes(hexToBytes(secret.trim()));
  }
  return toRawBytes(randomBytes(32));
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function pemFromRawPrivateKey(priv: Uint8Array, pub: Uint8Array): string {
  const x = bytesToHex(pub.slice(1, 33));
  const y = bytesToHex(pub.slice(33, 65));
  const d = bytesToHex(priv);
  const jwk = {
    kty: "EC",
    crv: "secp256k1",
    x: hexToBase64Url(x),
    y: hexToBase64Url(y),
    d: hexToBase64Url(d),
  };
  const key = createPrivateKey({ key: jwk, format: "jwk" });
  return createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
}

function hexToBase64Url(hex: string): string {
  const bytes = hexToBytes(hex.startsWith("0x") ? hex : `0x${hex}`);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The public-input digest an SP1 program would commit to.
 *
 * Exposed so the circuit, the prover and the verifier all derive the same
 * statement. The `Sp1` proof system is selectable but the service reports it as
 * unavailable until a prover is configured — we never fabricate a "proof".
 */
export function sp1PublicInputsHash(fields: AuthorizationFields): string {
  return keccak256Hex(
    `HOMOBIO/SP1-PUBLIC-INPUTS-V1|${authorizationHashHex(fields)}|${fields.sessionId}|${fields.expiresAt}`,
  );
}
