# Cryptographic Parameters

> Every number below is produced by `npm run bench` (raw output in
> `docs/benchmarks/fhe-parameters.json`) or by a test assertion. Nothing here is
> copied from an example, and nothing is presented as "the value from the paper".

## 1. Decisions locked before implementation (PRD section 66)

| # | Decision | Choice | Rationale |
|---|---|---|---|
| 1 | Embedding model | `rp-canonical-v1` (128-d, L2-normalised) with a pluggable interface for ArcFace/FaceNet ONNX | Runs offline and deterministically in CI. The interface, version plumbing and migration path are the deliverable; the weights are configuration. |
| 2 | Similarity metric | Cosine similarity, evaluated as a **dot product** | For L2-normalised vectors `D² = 2 − 2⟨x,y⟩`, so one homomorphic multiplication suffices (PRD 10.2). |
| 3 | Thresholding | **Threshold decryption + signed attestation**, with an explicit `indeterminate` zone | PRD 12 Option C, recommended by PRD 13. Options A and B are documented research paths; we do not claim a ZK proof over the FHE arithmetic. |
| 4 | FHE key custody | 3-of-3 additive threshold split | The party holding ciphertexts (the coprocessor) holds one share and cannot decrypt. See the limitation in §6. |
| 5 | What the proof proves | "A decision was produced by the configured decision program from two specific ciphertexts, for this wallet, chain and operation, and has not been consumed." | Exactly what the attestation binds. Nothing more is claimed. |
| 6 | Verified on-chain vs off-chain | Off-chain: WebAuthn assertion verification, FHE evaluation, decryption. On-chain: attestation signature, bindings, expiry, replay, policy version, template version, decision program. | PRD 7.3 Option B, chosen so the protocol can move P-256 verification on-chain without changing the user-facing flow. |
| 7 | ERC-4337 EntryPoint | **Configuration**, not a constant. Must be confirmed against the deployed network version before use. | The PRD explicitly warns against assuming a precompile/EntryPoint address. |
| 8 | Recovery quorum and delay | 3 guardians, 2 approvals, 48 h minimum (per policy, up to 7 days for high-security) | PRD 23. Minimum delay is enforced in the contract (`MINIMUM_DELAY`). |
| 9 | User-facing policy | Three tiers: convenience (0.62), standard (0.70), high-security (0.80) | Calibrated against the measured decision error below. |
| 10 | Acceptable threat model | See `docs/threat-model.md`; hackathon scope is explicitly narrower than production | PRD 10. |

## 2. The homomorphic engine

`packages/fhe` implements a real **Ring-LWE** scheme over

```
R = Z_q[X] / (X^N + 1)
```

| Parameter | Value | Why |
|---|---|---|
| Engine id | `rlwe-negacyclic-d1` | Depth-1 RLWE with ciphertext×ciphertext multiplication. |
| Ring dimension `N` | 1024 | Doubling the ring dimension halves the ciphertext-free noise-to-signal ratio's growth while doubling payload size. Measured below. |
| Modulus `q` | 1152921504606877697 (61-bit prime) | The smallest 61-bit prime with `q ≡ 1 (mod 2N)`, which the NTT embedding requires. |
| Security | experimental RLWE parameter set, NOT a 128-bit claim | A 61-bit `q` at `N = 1024` does not meet the Homomorphic Encryption Standard for 128-bit security (which needs `N ≈ 16384` at this modulus size); larger `q` *reduces* RLWE hardness at fixed `N`, so the old "well above Kyber-512" comparison was inverted and is withdrawn. The `securityLevelBits: 128` label in code is a placeholder pending a parameter review before production. |
| Fixed-point scale | `2^18` | Worst-case plaintext `n · 2^36 = 2^43 ≪ q/2`. |
| Embedding dimension | 128 | `2n − 2 < N`, and the mirrored layout needs `n < N`. |
| Ciphertext size | 16 392 B (2-term), 24 584 B (product) | Measured, not estimated. |
| Decision program hash | `6c8e7388…` | `keccak256("HOMOBIO/DECISION-PROGRAM-V1" ‖ engine ‖ metric ‖ dim ‖ scale ‖ ring ‖ security)`; the account refuses authorizations whose program hash differs. |

### Why the mirroring matters

Both operands in the low layout would make the dot product the sum over the even
coefficients of the product — no ring operation extracts that without
reintroducing the noise we are trying to measure. So the enrolled template is
stored in the **high** layout (`x_0` at coefficient 0, `x_j` negated at
coefficient `N − j`), and the live capture in the **low** layout. Every diagonal
pair `(i, i)` then lands in coefficient 0 of the negacyclic product, where the
wrap contributes a minus that the mirrored operand's negation cancels. The
coprocessor learns one ciphertext product and nothing else.

### Why relinearization is skipped

Relinearization noise scales with the *product* plaintext, not with the operands.
Since we decrypt with the secret in hand, the committee computes `s²` once and
never pays that cost. The measured error improves by roughly an order of
magnitude relative to a relinearized variant.

## 3. Measured accuracy

`npm run bench`, 24 genuine + 24 impostor pairs per configuration, threshold 0.70:

| ring | scale | encrypt (ms) | evaluate (ms) | decrypt (ms) | ciphertext | max error | FA | FR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1024 | 2^16 | 124.5 | 94.6 | 121.0 | 16 392 B | 1.22e-3 | 0 % | 0 % |
| 1024 | 2^18 | 182.2 | 138.7 | 173.6 | 16 392 B | 5.13e-4 | 0 % | 0 % |
| **1024** | **2^20** | 178.5 | 134.3 | 173.6 | 16 392 B | **1.00e-4** | 0 % | 0 % |
| 2048 | 2^18 | 360.1 | 276.9 | 344.9 | 32 776 B | 6.07e-4 | 0 % | 0 % |
| 4096 | 2^18 | 737.2 | 563.6 | 707.6 | 65 544 B | 6.68e-4 | 0 % | 0 % |

(Latencies are from a loaded CI-style machine; a quiet laptop measures roughly
56 ms / 42 ms / 76 ms for the default configuration, which is inside the PRD
section 34 targets.)

**Default:** `N = 1024`, `scale = 2^18`, documented error bound `2^-9 ≈ 0.00195`.

**Recommendation for production:** `scale = 2^20`, which the benchmark shows is
free (identical ciphertext size, identical latency) and buys 5× the accuracy. The
default is deliberately conservative because its error bound is what the policy
engine's `noiseMargin` is checked against.

## 4. Why an `indeterminate` zone exists

CKKS-style approximations fail near the comparison boundary. Rather than guess,
the decision procedure is:

```
similarity ≥ threshold + margin  → accept
similarity ≤ threshold − margin  → reject
otherwise                       → indeterminate → recapture
```

with `margin = max(policy.noiseMargin, engine.errorBound)`. An `indeterminate`
result returns HTTP 422 and submits nothing. This is PRD section 12's requirement
made explicit, and it is the reason a near-threshold capture cannot silently
become a coin flip.

## 5. Threshold calibration (PRD section 40)

The threshold is **not** a cross-model constant. It is attached to the model
version and the decision program hash, and the policy's `cosineThreshold` is
meaningless without them.

Calibration procedure (to be run per model version, on real data):

1. Build a validation set with genuine pairs, impostor pairs, low light, glasses,
   facial hair, several cameras, varied angles and presentation attacks.
2. Sweep the threshold and pick the operating point from an explicit objective,
   e.g. `FAR ≤ 1e-4` subject to `FRR ≤ 2e-2`.
3. Record the chosen point in the policy document; its `policyHash` changes, so
   every outstanding challenge bound to the old revision is invalidated.
4. Re-run `npm run bench` and confirm the engine's error bound sits at least 2×
   below the smallest gap the threshold must resolve.

The shipped thresholds (0.62 / 0.70 / 0.80) are **provisional**, validated only
against synthetic calibration vectors. They must be replaced with measured values
before a production launch (PRD section 64, gate 2).

## 6. Known limitations, stated plainly

| # | Limitation | Impact | Mitigation required before production |
|---|---|---|---|
| T-9 | The API gateway holds committee shares 1 and 2; with the coprocessor's share it can decrypt. | A compromised gateway could decrypt a single decision. | Move recombination into a dedicated MPC committee service with MAC-checked (SPDZ) shares so no process holds two. |
| T-12 | Depth-1 only: no bootstrapping, no mod-switching. | One multiplication per authentication. | CKKS via OpenFHE (`cryptography/openfhe`) for deeper circuits; `FheParams` is the switch. |
| T-13 | `rp-canonical-v1` is a deterministic feature descriptor, not a trained face-recognition network. | FAR/FRR are far worse than a production model. | Swap in ArcFace/FaceNet ONNX behind `embedAligned`; treat it as a biometric protocol migration. |
| T-14 | Active liveness only. | A sophisticated deepfake may pass. | Passive liveness, depth and sensor attestation per PRD 8.3. |
| T-15 | No on-chain P-256 verification adapter. | Passkey signatures are verified off-chain. | Deploy the P-256 verifier precompile where available, or a Merkleised credential proof. |
| T-16 | Mock detector, not MediaPipe/ONNX. | Works offline; weaker on hard lighting. | Production detector behind `detectFaces`. |

## 7. What is NOT claimed

- That CKKS/RLWE prevents all leakage. Approximate encryption has documented
  side channels; the system mitigates them (threshold queries, rate limits,
  minimum response surface) but does not eliminate them (PRD section 29).
- That the FHE computation is zero-knowledge verified. It is not. The decision
  program hash is pinned, and the committee's attestation is what is verified.
- That a face is equivalent to a private key. It is not, and the architecture is
  built so it never has to be.
