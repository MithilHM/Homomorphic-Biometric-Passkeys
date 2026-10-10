# Product Requirements Document (PRD)
# Homomorphic Biometric Passkeys
### Privacy-preserving biometric authentication + WebAuthn Passkeys + FHE + ZK + ERC-4337 Smart Accounts on Monad

**Document status:** Build-ready master PRD  
**Target:** Hackathon MVP → hardened production architecture  
**Primary audience:** Founders, product engineers, frontend engineers, ML engineers, cryptography/FHE engineers, ZK engineers, Solidity engineers, DevOps/SRE, security reviewers  
**Protocol style:** Privacy-preserving, non-custodial smart-account authentication  
**Reference implementation:** TypeScript/React/Next.js + WebAssembly/ONNX + OpenFHE + SP1/Halo2 + Solidity/EVM + ERC-4337  
**Last updated:** 2026-10-07

---

## 0. Executive Design Decision

The product is a biometric-authenticated smart-wallet system in which:

1. A user creates a **WebAuthn Passkey** that controls a smart account.
2. The user's camera is processed **locally** to produce a facial embedding.
3. The embedding is encrypted before leaving the device.
4. A remote FHE coprocessor evaluates a biometric similarity/distance computation without receiving the plaintext biometric vector.
5. A verification/proof layer establishes that the result satisfies the account's authentication policy.
6. An ERC-4337 smart account accepts the authenticated `UserOperation` and executes the transaction.
7. Recovery, device enrollment, session permissions, risk controls, and policy changes are handled by the smart account rather than by a centralized wallet backend.

### Critical security/product principle

The face must **not** literally become the wallet's cryptographic private key.

A biometric is not a good cryptographic root because it is not secret in the same way as a private key, cannot be rotated after compromise, can change over time, and is inherently probabilistic. The non-exportable WebAuthn credential remains the cryptographic signing root. The biometric match is an additional authorization factor/policy signal.

The product can still market the experience as **"your face unlocks your wallet"**, but the implementation must preserve the stronger primitive:

> **Passkey = cryptographic authority; biometric match = privacy-preserving authorization factor.**

This separation is a core product requirement, not an optional refinement.

---

# 1. Product Vision

## 1.1 Problem statement

Current Web3 wallets force users to manage seed phrases, private keys, or opaque signing flows. Web2 biometric authentication is dramatically easier to use but usually depends on device-local biometric systems or centralized identity databases. A centralized biometric database creates an especially sensitive breach target.

The system combines:

- Passkeys/WebAuthn for device-bound cryptographic authentication.
- Local ML inference for biometric feature extraction.
- FHE for privacy-preserving remote biometric comparison.
- ZK proofs or verifiable attestations for policy validation.
- ERC-4337 for programmable smart-account execution.
- Monad as the settlement and execution layer.

## 1.2 Product promise

A user should be able to:

1. Create a wallet without writing down a seed phrase.
2. Enroll a face without uploading a raw face image.
3. Authenticate with a familiar device biometric prompt.
4. Authorize wallet activity without exposing a plaintext facial embedding to the backend.
5. Execute gasless transactions when a sponsor is configured.
6. Recover access using explicit recovery methods without relying on an operator to manually restore a wallet.

## 1.3 Primary user personas

### Consumer user

Wants a wallet experience that feels similar to logging into a modern consumer app.

### Power user

Wants configurable policies, multiple passkeys, session keys, spending limits, and transparent security controls.

### dApp user

Wants a dApp to request a transaction from a biometric/passkey wallet without installing or managing seed phrases.

### Developer/integrator

Wants a clean SDK/API for requesting authentication and generating an ERC-4337 UserOperation.

### Security administrator / wallet operator

Wants observability, policy management, rate limits, abuse detection, audit trails, and emergency controls without gaining access to user biometrics.

---

# 2. Product Goals

## 2.1 Must-have goals

- Seedless onboarding.
- WebAuthn passkey registration and authentication.
- Local-only face capture and embedding extraction.
- No raw face image upload.
- No plaintext biometric embedding sent to application servers.
- Encrypted biometric template persistence.
- FHE-based similarity/distance computation.
- Replay-resistant authentication challenges.
- ERC-4337 smart-account execution.
- Multi-device passkey support.
- Recovery path.
- Session-key support with user-defined permissions.
- Strong transaction binding: biometric proof and passkey signature must refer to the exact intended operation.
- Auditability and observability.
- Explicit failure states instead of silent fallback to weaker authentication.

## 2.2 Nice-to-have goals

- Gas sponsorship via Paymaster.
- Cross-device passkey synchronization.
- Hardware security key support.
- Face template rotation/versioning.
- Multi-factor policies such as face + passkey + device risk score.
- Privacy-preserving liveness proof.
- Multiple biometric models.
- Wallet recovery through guardians.
- Multi-chain account abstraction adapters.
- Private telemetry with aggregate-only analytics.

## 2.3 Non-goals for MVP

- Building a new cryptographic scheme.
- Inventing a new passkey standard.
- Proving every pixel-to-embedding neural-network operation inside a ZK circuit.
- Making raw biometric data available to smart contracts.
- Putting full ciphertext blobs directly into ordinary contract storage without cost analysis.
- Supporting arbitrary chains on day one.
- Claiming mathematically perfect privacy merely because FHE is used.

---

# 3. Product Principles

## P1. Plaintext minimization

Raw facial images and plaintext embeddings must remain on-device during normal operation.

## P2. Cryptographic separation of duties

No single backend service should be able to authenticate a user and spend funds solely because it controls application infrastructure.

## P3. Biometric is probabilistic

The product must treat facial matching as a thresholded signal with false-accept and false-reject tradeoffs, not as an exact identity primitive.

## P4. User intent must be cryptographically bound

A successful face match for one operation must not be reusable for another transaction.

## P5. Recovery is a first-class feature

Lost device recovery must be explicit, auditable, rate-limited, and designed before production launch.

## P6. Privacy claims must be precise

"The server cannot decrypt the face" is materially different from "the protocol reveals no information." Metadata, repeated queries, failure responses, timing, ciphertext sizes, and compromised client devices can still leak information.

## P7. Every cryptographic assumption must be benchmarked

Do not hard-code ring dimensions, modulus sizes, precision, threshold values, proof systems, or latency claims before a benchmark and security-parameter review.

---

# 4. High-Level System Architecture

```text
                         ┌───────────────────────────────┐
                         │         User Device           │
                         │                               │
                         │ Camera ─► Detection/Liveness │
                         │              │                │
                         │              ▼                │
                         │        Face Embedding         │
                         │              │                │
                         │              ▼                │
                         │      Normalize / Quantize     │
                         │              │                │
                         │              ▼                │
                         │        FHE Encryption        │
                         │              │                │
                         │       WebAuthn Passkey        │
                         │              │                │
                         └──────────────┼────────────────┘
                                        │
                         TLS + signed challenge + ciphertext
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Off-chain infrastructure                         │
│                                                                         │
│ API Gateway                                                            │
│    │                                                                    │
│    ├── Challenge Service                                                │
│    ├── WebAuthn Verification Service                                    │
│    ├── Biometric Template Metadata Service                              │
│    ├── FHE Coprocessor                                                  │
│    │      └── OpenFHE / CKKS                                            │
│    │      └── Optional CKKS→FHEW/Boolean comparison                     │
│    │                                                                    │
│    ├── Proof / Verification Service                                     │
│    │      ├── SP1 / RISC-V zkVM                                        │
│    │      └── Halo2 fixed-circuit verifier                              │
│    │                                                                    │
│    ├── ERC-4337 Bundler / Relay Service                                 │
│    └── Observability / Risk Engine                                      │
└─────────────────────────────────────────────────────────────────────────┘
                                        │
                           UserOperation / proof / policy
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Monad EVM                                       │
│                                                                         │
│ EntryPoint                                                              │
│     │                                                                    │
│     ▼                                                                    │
│ BiometricSmartAccount                                                   │
│     ├── Passkey/WebAuthn verifier                                       │
│     ├── Biometric authorization module                                  │
│     ├── Session-key module                                              │
│     ├── Recovery module                                                 │
│     ├── Spending-policy module                                         │
│     └── Transaction executor                                            │
│                                                                         │
│ Optional Paymaster                                                      │
│                                                                         │
│ Events → Indexer / dashboard                                            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

# 5. Architecture Layers

## 5.1 Frontend / Edge layer

### Responsibilities

- Camera permission handling.
- Face detection.
- Face alignment.
- Liveness checks.
- Embedding extraction.
- Normalization.
- Local quality scoring.
- FHE encryption.
- WebAuthn operations.
- User consent.
- UserOperation construction.
- Transaction review.
- Recovery UX.
- Device/passkey management.

### Suggested implementation

- Next.js + React + TypeScript.
- Tailwind or CSS modules.
- Web Workers for ML and cryptographic work.
- ONNX Runtime Web / WebAssembly / WebGPU where supported.
- MediaPipe or another actively maintained detector as the default detection layer.
- A FaceNet-compatible embedding model or a newer, benchmarked face-recognition model.
- Web Crypto + WebAuthn browser APIs.
- OpenFHE compiled to WASM only after server-side correctness is proven.

### Important boundary

The camera frame must never enter the normal application API payload.

The frontend can log internal diagnostic metrics, but logs must never include:

- image pixels,
- embedding values,
- decrypted distance,
- FHE secret key,
- private passkey key material.

---

# 6. Backend Services

## 6.1 API Gateway

### Responsibilities

- Authentication request routing.
- Request size limits.
- TLS termination.
- Origin validation.
- Rate limiting.
- API versioning.
- Schema validation.
- Request correlation IDs.
- Abuse controls.

### Requirements

- Reject oversized ciphertext payloads.
- Reject malformed FHE metadata.
- Reject stale challenges.
- Reject replayed nonces.
- Require TLS.
- Enforce strict CORS policy.
- Support API versioning from day one, e.g. `/v1/...`.

---

## 6.2 Challenge Service

The challenge service generates an authentication intent that binds together:

- wallet address,
- chain ID,
- intended operation,
- user operation hash or transaction intent hash,
- nonce,
- expiration,
- biometric-policy version,
- FHE key version,
- WebAuthn RP ID/origin context.

### Challenge object

```json
{
  "challengeId": "uuid",
  "wallet": "0x...",
  "chainId": 143,
  "operationHash": "0x...",
  "nonce": "random-256-bit-value",
  "issuedAt": 1791370000,
  "expiresAt": 1791370060,
  "biometricPolicyVersion": 3,
  "fheKeyVersion": 2,
  "webauthnRpId": "app.example.com"
}
```

The exact chain ID must come from the configured network rather than being hard-coded in the frontend.

### Replay protection

A challenge is single-use and is invalidated after:

- successful authentication,
- explicit cancellation,
- expiration,
- nonce mismatch,
- account policy version change,
- chain reorganization conditions determined by the implementation.

The challenge must not depend solely on a public blockchain block hash because the backend must remain safe when chain data is delayed. Use a cryptographically random challenge, bind it to the intended transaction, and optionally mix in a recent chain state identifier.

---

# 7. WebAuthn / Passkey Subsystem

## 7.1 Registration

The browser calls `navigator.credentials.create()` using server-provided creation options.

The credential record must store:

- credential ID,
- public key,
- RP ID,
- sign counter where applicable,
- user handle,
- authenticator metadata needed by policy,
- creation time,
- last-used timestamp,
- device label chosen by user.

### Requirements

- Prefer discoverable credentials where appropriate.
- Prefer user verification (`UV`) for high-value transactions.
- Support multi-device credentials where the product chooses synced passkeys.
- Support security keys as a recovery/authentication option.
- Do not require attestation unless there is a justified trust requirement.

WebAuthn assertions contain `clientDataJSON`, `authenticatorData`, and `signature`; the relying party verifies the signature against the stored credential public key. citeturn672902search2turn946228view3

## 7.2 Authentication

The WebAuthn challenge must be derived from the authentication request and transaction intent.

### Required binding

The passkey signature must cover a message that commits to:

```text
chainId
wallet address
UserOperation hash
challenge nonce
biometric session ID
policy version
expiration
```

This prevents a valid passkey signature from being detached and reused for a different transaction.

## 7.3 On-chain WebAuthn verification

There are two implementation choices:

### Option A — On-chain verifier

The smart account verifies the authenticator assertion directly through an EVM-compatible P-256 verification implementation/precompile if the target chain/environment supports it.

### Option B — Off-chain WebAuthn verification + EIP-1271-style authorization

A backend verifies WebAuthn and produces a tightly scoped authorization artifact. The smart account validates that artifact through a custom verifier module.

**MVP recommendation:** keep the off-chain protocol modular so that WebAuthn verification can move on-chain without changing the user-facing protocol.

Do not hard-code an assumption that Monad provides a specific P-256 precompile until the deployed network's current precompile set is confirmed against the exact target network version. The PRD therefore treats P-256 verification as a configurable adapter.

---

# 8. Biometric Pipeline

## 8.1 Stage 1: Camera acquisition

Requirements:

- HTTPS-only camera access.
- Permission prompt with explicit explanation.
- No automatic upload.
- Camera stream stops immediately after the authentication session.
- Frames live in memory only.

## 8.2 Stage 2: Face detection

The detector should return:

- bounding box,
- confidence score,
- landmarks when supported,
- number of detected faces.

A detector such as MediaPipe's web-compatible face detection/landmark stack is preferred for the browser because it is designed for real-time viewfinder usage. MediaPipe's face detection API exposes detection confidence and multi-face handling. citeturn672902search0turn672902search9

MTCNN remains a valid experimental model, but the implementation team must benchmark MTCNN versus the selected production detector for browser performance, accuracy, and maintenance burden.

## 8.3 Stage 3: Liveness

MTCNN or a face detector is **not itself a complete liveness system**.

The product must have a separate liveness module.

### MVP liveness

Use randomized active prompts such as:

- turn head left,
- turn head right,
- raise eyebrows,
- blink twice,
- move closer.

### Production liveness

Add passive + active liveness with:

- texture analysis,
- depth where available,
- replay detection,
- screen-reflection detection,
- temporal consistency,
- randomized challenge-response.

### Anti-deepfake controls

The client should reject:

- static photographs,
- obvious replayed videos,
- frame-injected webcam streams where detectable,
- multiple simultaneous faces,
- face swap artifacts where detectable.

For high-risk operations, the backend should optionally require stronger device or sensor signals.

## 8.4 Stage 4: Face alignment

Normalize detected faces into a canonical geometry before embedding extraction.

Typical sequence:

```text
Detected face
   ↓
Landmarks
   ↓
Similarity transform
   ↓
Canonical crop
   ↓
Model-specific normalization
```

## 8.5 Stage 5: Embedding extraction

The system must standardize one model/version per biometric template.

### Example representation

```text
Face model: FaceNet-compatible
Vector dimension: 128 or 512
Type: float32 during local inference
Normalization: L2 normalization
Model version: explicit version ID
```

The exact model is a product decision and must not be treated as interchangeable after enrollment. Model changes require a migration strategy.

---

# 9. Biometric Template Processing

## 9.1 Enrollment template generation

At enrollment, do not rely on one frame.

Recommended process:

```text
Capture 5–10 high-quality samples locally
        ↓
Per-frame quality filtering
        ↓
Embedding extraction
        ↓
Outlier rejection
        ↓
Aggregation / template construction
        ↓
L2 normalization
        ↓
Template versioning
        ↓
FHE encryption
        ↓
Upload ciphertext only
```

The raw images and intermediate embeddings are deleted from browser memory after successful template creation.

## 9.2 Template stability

The enrollment process should minimize template drift caused by:

- lighting,
- hairstyle,
- facial hair,
- glasses,
- camera quality,
- pose.

A template can be represented as:

```text
T = Normalize(mean(e1, e2, ..., en))
```

but the exact aggregation method must be benchmarked.

## 9.3 Template rotation

The user must be able to re-enroll:

- on the same device,
- on a second device,
- after model upgrades,
- after confirmed facial changes.

A new template must not silently overwrite the old template. Use versioned templates and a controlled transition state.

---

# 10. FHE Architecture

## 10.1 Why CKKS

CKKS is intended for approximate arithmetic on real/complex values and is therefore a natural candidate for floating-point embedding operations. OpenFHE exposes CKKS and supports configurable multiplicative depth, scaling parameters, ring dimension, and multiparty capabilities. citeturn648773search1turn648773search5turn648773search7

## 10.2 Core computation

For normalized embeddings, use one of:

### Euclidean distance squared

\[
D^2 = \sum_{i=1}^{n}(x_i-y_i)^2
\]

### Cosine similarity

For L2-normalized vectors:

\[
S = \sum_{i=1}^{n} x_i y_i
\]

and:

\[
D^2 = 2 - 2S
\]

For an FHE implementation, normalized embeddings plus dot product can be attractive because it reduces the operation to one multiplication per slot followed by a reduction.

## 10.3 Required FHE operations

- encode
- encrypt
- homomorphic add
- homomorphic subtract
- homomorphic multiply
- relinearization/key switching where required
- rotation/sum for slot reduction
- rescaling
- optional ciphertext modulus management
- optional bootstrapping

## 10.4 FHE key architecture

### MVP

Use a system-scoped FHE public key with a controlled private/secret-key holder.

### Production

Use threshold/multiparty FHE so no single service possesses the complete decryption secret.

OpenFHE provides multiparty support and explicitly exposes multiparty FHE configuration capabilities. citeturn648773search7turn648773search5

### Important correction

The client **must not generate an FHE secret key and delete it immediately** if the system subsequently expects any party to decrypt the resulting similarity result. The encryption key lifecycle must be designed around whoever performs the authorized threshold decryption.

The recommended architecture is:

```text
                    FHE public key
                          │
          ┌───────────────┼─────────────────┐
          │               │                 │
      Client A        Client B          Enrollment client
          │               │                 │
       encrypt          encrypt              encrypt
          │               │                 │
          └───────────────┴─────────────────┘
                          │
                          ▼
                   FHE computation
                          │
                          ▼
                  Threshold decryption
                    /       |       \
                 share1   share2   share3
                    \       |       /
                     authenticated boolean
```

No single application server should be able to decrypt all stored templates in production.

---

# 11. CKKS Parameter Strategy

The previous proposal's fixed values such as ring dimension `2^13`, `2^14`, and scale `2^40` are **candidate starting points, not acceptance criteria**.

OpenFHE parameter generation depends on:

- ring dimension,
- multiplicative depth,
- scaling modulus size,
- security level,
- key-switching technique,
- precision requirements,
- ciphertext operations.

OpenFHE's parameter APIs expose these dimensions directly. citeturn648773search1turn648773search2

## Required benchmark matrix

Test at least:

```text
Ring dimension:   8192, 16384, 32768
Scale/mod size:   40, 50, 60 bits
Depth:             2, 3, 4+
Embedding size:    128, 256, 512
Reduction:         direct rotations vs optimized summation
```

For each configuration record:

- client encryption latency,
- ciphertext size,
- server evaluation latency,
- memory,
- network payload,
- numerical error,
- false-accept rate,
- false-reject rate,
- total proof/attestation latency.

### Acceptance requirement

The selected cryptographic parameters must be justified by measured precision and a recognized security target, not selected because a number was common in an example.

---

# 12. Thresholding Architecture

This is one of the hardest parts of the system.

A CKKS ciphertext contains an encrypted approximate result. Simply saying:

> "The FHE result is less than T, therefore the contract knows the user matched."

is incomplete.

A secure implementation needs an explicit mechanism that converts the encrypted numeric result into an authorization decision without leaking the biometric template.

## Option A — CKKS polynomial comparison

Approximate the comparison function with a polynomial.

Pros:

- stays inside CKKS;
- conceptually simple.

Cons:

- approximation error;
- extra multiplicative depth;
- difficult threshold calibration;
- can create false positives/negatives near the decision boundary.

## Option B — CKKS → FHEW/TFHE scheme switching

Compute the continuous distance in CKKS, then switch to a Boolean-friendly FHE representation for comparison.

OpenFHE provides CKKS/FHEW scheme-switching capabilities. citeturn648773search6turn648773search11

This is the preferred research path for a true encrypted comparator.

## Option C — Threshold decryption + secure attestation

Decrypt only the scalar result through a threshold committee and produce an authenticated decision artifact.

This is the recommended hackathon path because it is significantly easier to make correct and measurable.

The decrypted value itself must never be returned to the application client or written on-chain.

---

# 13. Recommended Hackathon Cryptographic Architecture

The first working version should use:

```text
Client
  └─ local face embedding
        ↓
  CKKS encryption under public FHE key
        ↓
Backend FHE worker
        └─ encrypted distance
              ↓
Threshold decryption service / isolated prover
        └─ decrypt scalar internally
              ↓
Decision: match / no-match
              ↓
SP1 proof or signed attestation
              ↓
Smart account
              ↓
ERC-4337 EntryPoint
              ↓
Monad
```

This does **not** claim that the entire FHE pipeline is itself zero-knowledge verified.

Instead, the system explicitly separates:

1. privacy of biometric inputs through FHE,
2. authorization through WebAuthn,
3. computation verifiability through a proof/attestation layer.

That is a much more defensible architecture for a hackathon.

---

# 14. ZK Architecture

## 14.1 Role of ZK

The proof layer must establish that an authentication decision was derived from a valid protocol execution.

The minimum statement is:

```text
Given:
  challenge
  transaction commitment
  wallet address
  biometric policy version
  FHE computation identifier
  authenticated result

Prove:
  the decision is valid
  the result corresponds to this operation
  the policy threshold was satisfied
  the authorization artifact was not replayed
```

## 14.2 SP1 role

SP1 is well suited to proving deterministic program execution in a zkVM-style architecture.

Recommended use:

```text
FHE result attestation
       ↓
SP1 program
       ↓
verify signed result
       ↓
check threshold
       ↓
check nonce
       ↓
check transaction hash
       ↓
emit compact proof
```

The SP1 circuit should not be described as proving the CKKS arithmetic unless the team has actually implemented and benchmarked a complete FHE reference computation inside the proving environment.

## 14.3 Halo2 role

Halo2 is appropriate if a fixed, custom arithmetic circuit is preferred.

Possible Halo2 circuit:

```text
Public:
  operationHash
  wallet
  policyHash
  commitment
  resultCommitment
  threshold

Private:
  authenticated distance result
  nonce-related witness

Constraints:
  distance < threshold
  hash(witness, public context) == resultCommitment
```

For a future fully cryptographic design, the circuit can be extended to validate a decryption proof or authenticated multiparty-decryption transcript.

---

# 15. Proof / Attestation Object

Define a canonical authorization object.

```json
{
  "version": 1,
  "wallet": "0x...",
  "chainId": 143,
  "userOpHash": "0x...",
  "challengeId": "uuid",
  "biometricPolicyId": "policy-v3",
  "fheKeyVersion": 2,
  "templateVersion": 4,
  "decision": true,
  "proofSystem": "SP1",
  "proof": "0x...",
  "issuedAt": 1791370000,
  "expiresAt": 1791370060
}
```

The decision object must never contain:

- raw image,
- plaintext embedding,
- plaintext distance,
- secret FHE key.

---

# 16. Smart Account Architecture

## 16.1 Contract family

Recommended contracts:

```text
BiometricAccountFactory.sol
BiometricSmartAccount.sol
BiometricValidator.sol
WebAuthnValidator.sol
BiometricPolicyModule.sol
SessionKeyModule.sol
RecoveryModule.sol
SpendingLimitModule.sol
ProofVerifier.sol
Paymaster.sol
```

## 16.2 `BiometricSmartAccount`

Responsibilities:

- own assets;
- execute authorized calls;
- implement ERC-4337 account validation;
- delegate signature checking to validator modules;
- store credential references and policy identifiers;
- manage recovery rules;
- manage session permissions.

ERC-4337 requires the account to validate `UserOperation`s through its account-validation interface, with EntryPoint orchestrating validation and execution. citeturn914256search0turn946228view2

## 16.3 UserOperation validation

Validation sequence:

```text
EntryPoint
  ↓
BiometricSmartAccount.validateUserOp()
  ↓
Verify domain / EntryPoint
  ↓
Verify nonce
  ↓
Decode authentication envelope
  ↓
Verify biometric proof/authorization
  ↓
Verify WebAuthn signature
  ↓
Verify transaction intent binding
  ↓
Check policy
  ↓
Return validationData
```

## 16.4 Important ordering rule

The account must not treat:

```text
biometric match == signature
```

The biometric result is an authorization condition. The cryptographic signature remains the transaction-authority proof.

---

# 17. ERC-4337 Integration

ERC-4337 introduces the `UserOperation`, EntryPoint, bundlers, and optional paymasters. Current documentation also covers session keys/delegation and modular accounts as related infrastructure. citeturn946228view2turn914256search0

## 17.1 UserOperation lifecycle

```text
User chooses action
      ↓
Frontend builds intended call
      ↓
Calculate UserOperation hash
      ↓
Create biometric authentication challenge
      ↓
Capture face / run liveness
      ↓
Encrypt biometric vector
      ↓
Request WebAuthn assertion
      ↓
Generate biometric proof
      ↓
Package signature + proof
      ↓
Send UserOperation to bundler
      ↓
Bundler simulation
      ↓
EntryPoint validation
      ↓
Account execution
      ↓
Monad settlement
```

## 17.2 Nonce management

Use ERC-4337 nonce semantics and support parallel nonce keys for independent workflows when useful.

Example nonce domains:

```text
0      → normal wallet transactions
1      → session-key operations
2      → recovery operations
3      → device-management operations
```

The account must never reuse a nonce for different intents.

## 17.3 Paymaster

The system should support an optional Paymaster so new users do not need native gas.

Possible policies:

- first 5 transactions sponsored;
- onboarding sponsored;
- transactions under a configured value sponsored;
- dApp-specific sponsorship.

ERC-4337 Paymasters validate sponsorship conditions and cover gas when the policy permits it. citeturn914256search3turn946228view2

---

# 18. Registration Flow — Detailed

## Step 1 — Landing

User selects:

> Create a wallet with a passkey

## Step 2 — Explain privacy

Show concise consent text:

- camera frames remain on this device;
- face data is converted into a numerical template locally;
- only encrypted data leaves the device;
- your passkey controls the wallet;
- recovery options must be configured.

## Step 3 — Camera setup

System checks:

- camera available,
- lighting adequate,
- face detected,
- one face only.

## Step 4 — Enrollment

Collect several samples with slightly different angles/expressions.

## Step 5 — Local embedding

Create embeddings and quality scores.

## Step 6 — Template aggregation

Generate versioned template.

## Step 7 — FHE encryption

Encrypt template under registered FHE public key.

## Step 8 — Passkey creation

Call WebAuthn credential creation.

## Step 9 — Account derivation

Derive deterministic smart-account address from:

```text
factory
implementation
credential identifier / public key commitment
configuration hash
salt
```

## Step 10 — Deployment

Either:

- deploy immediately, or
- use ERC-4337 counterfactual deployment on first UserOperation.

## Step 11 — Recovery setup

Require the user to configure at least one recovery option before declaring onboarding complete.

## Step 12 — Cleanup

Destroy:

- camera frames,
- plaintext embedding buffers,
- intermediate face crops,
- temporary keys no longer required.

---

# 19. Authentication Flow — Detailed

## Step 1 — User initiates transaction

Example:

```text
Send 50 USDC to 0xABC...
```

## Step 2 — Transaction preview

Show:

- token,
- amount,
- recipient,
- network,
- fee/sponsorship status.

## Step 3 — Create intent commitment

Compute:

```text
operationHash = H(chainId || account || calldata || nonce || policyVersion)
```

## Step 4 — Create challenge

Challenge includes the operation binding.

## Step 5 — Face check

Run:

```text
camera
→ detection
→ liveness
→ alignment
→ embedding
→ normalize
```

## Step 6 — Encrypt

```text
C_live = Encrypt(PK_FHE, embedding_live)
```

## Step 7 — WebAuthn assertion

Ask user to authenticate with platform passkey.

## Step 8 — FHE evaluation

Retrieve the encrypted enrolled template:

```text
C_reg
```

Compute:

```text
C_d = Distance(C_reg, C_live)
```

## Step 9 — Decision conversion

Use one of the supported threshold architectures.

## Step 10 — Proof/attestation

Generate authorization artifact.

## Step 11 — Build UserOperation

The UserOperation contains the minimum required proof references and authentication envelope.

## Step 12 — Bundler

Send to an ERC-4337 bundler.

## Step 13 — On-chain validation

Account checks:

```text
correct EntryPoint
correct chain
valid nonce
valid expiration
valid biometric authorization
valid WebAuthn signature
correct UserOperation hash
policy satisfied
```

## Step 14 — Execution

Execute requested call(s).

## Step 15 — Result

UI reports:

- submitted,
- confirmed,
- failed,
- reverted,
- expired.

---

# 20. Transaction Policy Engine

Users should be able to configure multiple security levels.

## Policy model

```json
{
  "policyId": "policy-v3",
  "biometricRequired": true,
  "passkeyRequired": true,
  "livenessRequired": true,
  "maxTransactionValue": "100000000",
  "sessionEnabled": true,
  "sessionDuration": 14400,
  "recoveryDelay": 172800
}
```

## Example policy tiers

### Convenience

- face + passkey;
- low-value transaction limit;
- optional session key.

### Standard

- face + passkey;
- liveness required;
- strict expiry;
- limited session lifetime.

### High security

- face + passkey;
- fresh biometric scan;
- hardware-backed passkey preferred;
- no session keys;
- lower allowed risk threshold.

---

# 21. User Preferences

The application must expose a security settings area.

## 21.1 Authentication settings

- Face required for every transaction.
- Face required above transaction threshold.
- Passkey always required.
- Liveness always required.
- Session authentication duration.

## 21.2 Device settings

- Current device name.
- Add passkey.
- Remove passkey.
- Rename device.
- Last used timestamp.
- Credential state.

## 21.3 Biometric settings

- Enrolled template version.
- Re-enroll face.
- Delete biometric template.
- Replace template.
- Model version.

## 21.4 Recovery settings

- Add recovery passkey.
- Add hardware security key.
- Add guardians.
- View recovery delay.
- Cancel pending recovery.

## 21.5 Transaction preferences

- default gas sponsorship;
- gas token when supported;
- transaction confirmation level;
- session key limits.

---

# 22. Session Keys

A major UX feature should allow the user to authenticate once and delegate limited actions.

## Session key format

```text
Session public key
Allowed contracts
Allowed functions
Maximum amount
Expiration timestamp
Nonce domain
Chain ID
```

Example:

```json
{
  "sessionKey": "0x...",
  "chainId": 143,
  "validUntil": 1791384400,
  "allowedTargets": ["0xDEX..."],
  "allowedSelectors": ["0x12345678"],
  "maxValuePerTx": "100000000000000000"
}
```

The biometric requirement should apply to **session creation**, not necessarily every operation within the delegated policy.

The smart account must enforce session permissions on-chain.

---

# 23. Recovery Architecture

Recovery must never become a hidden custodial backdoor.

## Recovery options

### Option A — Backup passkey

Recommended MVP recovery method.

### Option B — Hardware key

FIDO security key / passkey-capable hardware device.

### Option C — Social recovery

Guardians approve an account-recovery action.

### Recovery delay

High-risk recovery operations should have a timelock.

Recommended flow:

```text
Recovery initiated
      ↓
72-hour pending state
      ↓
User can cancel
      ↓
Guardians/backup key approval
      ↓
New credential registered
      ↓
Old credential revoked
```

The exact delay must be configurable by policy.

---

# 24. Smart Contract Functional Requirements

## `BiometricSmartAccount`

Must support:

```solidity
function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256 validationData);

function execute(address target, uint256 value, bytes calldata data) external;

function executeBatch(Call[] calldata calls) external;

function addCredential(bytes calldata credentialData) external;

function removeCredential(bytes32 credentialId) external;

function setPolicy(bytes32 policyId) external;

function initiateRecovery(bytes calldata recoveryData) external;

function cancelRecovery() external;

function finalizeRecovery(bytes calldata recoveryData) external;
```

## `BiometricValidator`

Must validate:

- proof version;
- proof verifier key/version;
- wallet binding;
- chain binding;
- UserOperation hash;
- nonce;
- template version;
- policy version;
- expiration;
- one-time challenge.

## `ProofVerifier`

Must support upgradeable verifier-key registration but only through a secured governance/recovery path.

Never allow arbitrary callers to replace verification keys.

---

# 25. Data Model

## Account

```text
accountId
smartAccountAddress
createdAt
chainId
policyId
status
```

## Credential

```text
credentialId
accountAddress
publicKey
rpId
credentialType
createdAt
lastUsedAt
status
```

## Biometric template

```text
templateId
accountAddress
modelVersion
embeddingDimension
fheKeyVersion
ciphertextLocation
ciphertextCommitment
createdAt
status
```

## Authentication session

```text
sessionId
accountAddress
challengeId
userOpHash
createdAt
expiresAt
status
```

## Proof record

```text
proofId
sessionId
proofSystem
proofVersion
publicInputsHash
createdAt
status
```

---

# 26. Storage Architecture

## On-chain storage

Store only small, stable metadata such as:

- credential hash/identifier;
- policy hash;
- biometric template commitment;
- template version;
- FHE key version;
- verifier version;
- recovery configuration hash.

Do not store giant ciphertext blobs in contract storage unless a cost benchmark proves it practical.

## Off-chain encrypted storage

Store FHE ciphertext in:

- object storage,
- content-addressed storage,
- decentralized storage,
- or another availability layer.

Store the content hash/commitment on-chain.

### Integrity rule

The coprocessor must retrieve the ciphertext by authenticated content identifier and verify the on-chain commitment before using it.

---

# 27. API Specification

## `POST /v1/auth/challenge`

Creates an authentication session.

### Request

```json
{
  "account": "0x...",
  "chainId": 143,
  "userOpHash": "0x..."
}
```

### Response

```json
{
  "challengeId": "uuid",
  "challenge": "base64url...",
  "expiresAt": 1791370060,
  "rpId": "app.example.com",
  "policyId": "policy-v3"
}
```

## `POST /v1/biometric/evaluate`

Receives:

- ciphertext of live embedding,
- challenge ID,
- template commitment,
- FHE key version,
- WebAuthn assertion metadata.

Returns a processing identifier.

It must not return the decrypted distance.

## `GET /v1/biometric/evaluate/:id`

Returns status:

```json
{
  "status": "proof_ready",
  "proofId": "uuid"
}
```

## `POST /v1/userop/submit`

Submits a fully assembled UserOperation to the configured bundler layer.

---

# 28. Authentication Envelope

Use a canonical envelope to avoid ad hoc concatenation across services.

```text
AuthEnvelopeV1 =
  version
  chainId
  account
  challengeId
  operationHash
  nonce
  policyId
  templateVersion
  fheKeyVersion
  webAuthnAssertion
  biometricAuthorization
  expiration
```

Hash with a domain separator:

```text
H("HOMOBIO-AUTH-V1" || AuthEnvelopeV1)
```

This value is the central binding primitive for the session.

---

# 29. Security Threat Model

## Threat: database breach

**Risk:** attackers obtain encrypted biometric templates.  
**Mitigation:** ciphertext only + rotating FHE keys + content integrity + threshold decryption.

## Threat: malicious FHE worker

**Risk:** worker returns forged match result.  
**Mitigation:** authenticated computation result + proof/attestation + on-chain verification.

## Threat: replayed valid authentication

**Risk:** attacker reuses an old face match.  
**Mitigation:** fresh challenge + operation binding + nonce + expiration.

## Threat: phishing

**Risk:** attacker causes user to sign a malicious request.  
**Mitigation:** WebAuthn RP binding + human-readable transaction review + strict operation commitment.

## Threat: compromised frontend

**Risk:** malicious JS captures data before encryption.  
**Mitigation:** CSP, SRI where practical, release signing, reproducible builds, minimal third-party JS, optional native app path, browser isolation.

## Threat: presentation attack

**Risk:** photo/video/deepfake.  
**Mitigation:** active/passive liveness + randomized challenges + optional hardware-backed signals.

## Threat: stolen device

**Risk:** device owner or thief accesses account.  
**Mitigation:** passkey user verification + biometric policy + session expiration + recovery controls.

## Threat: malicious recovery

**Risk:** attacker attempts account takeover through recovery.  
**Mitigation:** delay + guardian quorum + cancellation window + notifications.

## Threat: FHE chosen-ciphertext leakage

**Risk:** repeated adaptive queries reveal information from approximate encryption or side channels.  
**Mitigation:** strict query authorization, rate limits, privacy budget, threshold decryption, minimum response surface, and cryptographic review. CKKS has documented security considerations around approximate decryption and noise leakage; the system must not assume "encrypted" automatically means every possible leakage channel is eliminated. citeturn648773search0

---

# 30. Biometric Abuse Prevention

The system must prevent arbitrary biometric queries against a stored template.

## Rule

A server must never expose a generic API such as:

```text
compare(templateId, arbitraryCiphertext)
```

Instead, the service receives a request only when:

- a live authentication challenge exists;
- the operation is bound to a wallet action;
- the client has a valid WebAuthn assertion or an authorized pre-assertion token flow;
- the number of attempts is within policy.

## Rate limits

Recommended initial limits:

```text
5 failed biometric attempts / 15 min
10 total authentication attempts / hour
lockout escalation after repeated failures
```

These are product defaults to benchmark, not immutable constants.

---

# 31. Privacy Model

The product must explicitly document what each actor sees.

| Actor | Raw face | Plain embedding | Encrypted embedding | Match result | Tx intent |
|---|---:|---:|---:|---:|---:|
| Browser | Yes temporarily | Yes temporarily | Yes | Yes locally as status | Yes |
| API gateway | No | No | Yes | No | Yes |
| FHE worker | No | No | Yes | No plaintext | Metadata only |
| Threshold decryptors | No | No | Encrypted | Boolean/scalar internally | Bound context |
| ZK prover | No | Ideally no | References | Yes/no witness | Yes |
| Blockchain | No | No | Commitment only | Authorization proof | Yes |

The table above is the target architecture; specific implementation choices can shift what the prover/decryptor can observe.

---

# 32. Frontend UX Requirements

## 32.1 Home screen

Show:

- wallet address;
- network;
- asset balances;
- recent transactions;
- authentication status;
- enrolled device count.

## 32.2 Send flow

```text
Recipient
Amount
Review
Authenticate
Submitting
Confirmed
```

## 32.3 Authentication screen

State machine:

```text
idle
↓
request_permission
↓
camera_ready
↓
face_detected
↓
liveness_challenge
↓
face_quality_ok
↓
embedding_generated
↓
encrypting
↓
passkey_prompt
↓
processing
↓
proof_ready
↓
submitting
↓
success
```

Failure branches:

```text
camera_denied
no_face
multiple_faces
low_light
poor_quality
liveness_failed
passkey_cancelled
passkey_not_supported
fhe_error
proof_error
bundler_rejected
transaction_reverted
challenge_expired
```

Every state must provide a human-readable explanation and recovery action.

---

# 33. Accessibility Requirements

- Full keyboard navigation.
- Screen-reader labels.
- High-contrast authentication states.
- Non-color-only status indication.
- Camera prompt explanation in text.
- No authentication step that requires color perception.
- Reduced-motion support.

---

# 34. Performance Requirements

The system should target the following hackathon UX goals:

| Operation | Target |
|---|---:|
| Face detection | <150 ms/frame on capable laptop |
| Local embedding | <500 ms typical |
| Local FHE encryption | <2 s desktop target |
| FHE evaluation | <5 s target for MVP |
| Proof/attestation generation | <10 s target for MVP |
| UserOperation submission | <2 s before chain propagation |
| End-to-end perceived auth | <15 s target |

These are performance goals, not guarantees. Cryptographic parameter selection and browser capabilities can materially change them.

---

# 35. Reliability Requirements

## FHE worker

- stateless workers where possible;
- deterministic evaluation version;
- idempotent job IDs;
- retry-safe;
- timeout support;
- queue-based execution;
- ciphertext integrity verification.

## Proof worker

- deterministic public-input generation;
- verifier version pinning;
- proof artifact hash;
- replay prevention.

## Bundler

- multiple RPC endpoints;
- simulation before submission;
- failure diagnostics;
- replacement/retry policies.

---

# 36. Observability

## Metrics

Frontend:

- authentication-start count;
- camera permission failure rate;
- face-detection latency;
- liveness failure rate;
- embedding latency;
- FHE encryption latency;
- WebAuthn cancel/failure rate.

Backend:

- FHE queue depth;
- FHE evaluation latency;
- ciphertext size;
- proof latency;
- proof failure rate;
- authentication false reject rate;
- bundler rejection rate;
- gas cost.

Blockchain:

- UserOperation accepted;
- UserOperation reverted;
- account validation failures;
- paymaster failures;
- recovery events.

## Logging rules

Never log:

- embeddings;
- facial images;
- FHE secret keys;
- WebAuthn private material;
- decrypted distance.

Log instead:

- identifiers;
- hashes;
- durations;
- error codes;
- policy version;
- cryptographic version.

---

# 37. Security Engineering Requirements

## Key management

FHE keys:

- versioned;
- rotated;
- access-controlled;
- optionally threshold-split;
- backed up securely;
- revocable.

WebAuthn:

- credential IDs stored securely;
- public keys only;
- no private credential material stored by the website.

Proof keys:

- verification keys immutable unless governance changes them;
- proof version included in authorization envelope.

## Secrets manager

Use a dedicated secret manager / KMS for:

- API credentials;
- infrastructure secrets;
- deployer keys;
- relayer signing keys.

The biometric FHE secret should be isolated from ordinary API credentials.

---

# 38. Smart Contract Security Requirements

Contracts must include:

- strict EntryPoint validation;
- reentrancy-safe execution;
- bounded calldata parsing;
- signature domain separation;
- nonce enforcement;
- expiration checks;
- verifier key access control;
- recovery timelocks;
- event emission;
- emergency pause only where operationally justified;
- no arbitrary delegatecall from untrusted calldata;
- safe upgrade strategy.

### Upgradeability

For hackathon simplicity, prefer immutable or minimally upgradeable components.

If upgradeable:

- use timelock;
- emit upgrade event;
- protect admin with multisig;
- separate verifier upgrades from wallet logic;
- include downgrade/rollback process.

---

# 39. ML Model Management

The embedding model is a cryptographic protocol dependency.

Store:

```text
modelName
modelVersion
architecture
embeddingDimension
preprocessingVersion
normalizationVersion
training/source metadata
checksum
```

A model change can change similarity distributions. Therefore:

> A model version change is equivalent to a biometric protocol migration.

## Migration process

```text
new model evaluated offline
↓
benchmark FAR/FRR
↓
define migration threshold
↓
users re-enroll
↓
old template retained temporarily
↓
new template activated
↓
old template retired
```

---

# 40. Threshold Calibration

Do not hard-code a generic FaceNet threshold such as `0.6–0.8` as a universal production rule.

Thresholds depend on:

- model version;
- preprocessing;
- distance metric;
- embedding normalization;
- camera quality;
- population;
- attack conditions;
- target false acceptance rate;
- target false rejection rate.

## Calibration process

Create a validation set containing:

- genuine pairs;
- impostor pairs;
- low-light samples;
- glasses;
- facial hair;
- different cameras;
- varying angles;
- presentation attacks.

Choose threshold based on an explicit security objective.

Example:

```text
Primary objective: FAR <= X
Secondary objective: FRR <= Y
```

The actual X/Y numbers must be selected by the security team.

---

# 41. Testing Strategy

## 41.1 Unit tests

### Frontend

- camera permission state machine;
- embedding normalization;
- ciphertext serialization;
- challenge parsing;
- WebAuthn response parsing.

### Backend

- challenge uniqueness;
- replay rejection;
- FHE circuit correctness;
- proof input construction;
- API schema validation.

### Solidity

- nonce checks;
- proof validation;
- signature validation;
- policy limits;
- recovery delay;
- session key permissions.

## 41.2 Integration tests

```text
browser
→ API
→ FHE
→ proof
→ bundler
→ EntryPoint
→ account
→ Monad
```

## 41.3 Cryptographic test vectors

Maintain fixed vectors for:

- embeddings;
- ciphertext generation metadata;
- expected distance;
- expected decision;
- expected proof public inputs;
- expected contract result.

This allows every language boundary to be tested consistently.

## 41.4 Negative tests

Must include:

- wrong face;
- wrong passkey;
- modified proof;
- modified ciphertext;
- stale challenge;
- wrong chain ID;
- wrong wallet;
- wrong policy version;
- expired proof;
- replayed proof;
- modified UserOperation;
- changed recipient;
- changed transaction amount;
- malicious recovery request;
- multiple simultaneous faces;
- liveness bypass attempt.

---

# 42. Formal Security Properties

The system should aim to establish the following properties.

## Authentication soundness

An attacker cannot make the smart account accept a UserOperation unless:

```text
valid passkey authorization
AND
valid biometric authorization
AND
valid policy
AND
valid challenge
AND
valid nonce
AND
valid operation binding
```

## Replay resistance

A previously accepted authentication artifact cannot authorize a different UserOperation or be reused after its validity window.

## Biometric confidentiality

No ordinary application server learns the plaintext stored biometric template during normal operation.

## Template integrity

The coprocessor only evaluates the exact enrolled template identified by the on-chain commitment.

## Recovery integrity

Recovery cannot bypass the normal governance/recovery policy.

---

# 43. Feature Matrix

| Feature | MVP | Phase 2 | Production |
|---|---:|---:|---:|
| WebAuthn passkey | ✓ | ✓ | ✓ |
| Local embedding | ✓ | ✓ | ✓ |
| Local liveness | ✓ | ✓ | ✓ |
| CKKS encryption | ✓ | ✓ | ✓ |
| FHE distance | ✓ | ✓ | ✓ |
| Threshold decryption | Optional | ✓ | ✓ |
| CKKS→FHEW | — | Optional | ✓ |
| SP1 proof | ✓/attestation | ✓ | ✓ |
| Halo2 proof | — | Optional | Optional |
| ERC-4337 account | ✓ | ✓ | ✓ |
| Paymaster | Optional | ✓ | ✓ |
| Session keys | ✓ | ✓ | ✓ |
| Backup passkey | ✓ | ✓ | ✓ |
| Social recovery | — | ✓ | ✓ |
| Multi-device | Optional | ✓ | ✓ |
| On-chain P256 verification | Adapter | Adapter | ✓ if network supports |
| Decentralized ciphertext storage | — | ✓ | ✓ |
| Full threshold FHE | — | Optional | ✓ |
| Privacy-preserving liveness proof | — | Research | Future |

---

# 44. Phase 0 — Architecture & Cryptographic Feasibility
## Days 1–3

### Deliverables

- protocol specification;
- threat model;
- crypto parameter experiment;
- browser ML benchmark;
- smart-account skeleton;
- API schema.

### Exit criteria

- Face embedding successfully generated locally.
- FHE computes known test distance.
- WebAuthn credential created in supported browsers.
- ERC-4337 account validates a dummy UserOperation.

---

# 45. Phase 1 — Biometric Pipeline
## Days 4–10

### Tasks

1. Build webcam UI.
2. Add face detector.
3. Add face alignment.
4. Integrate embedding model.
5. Build liveness state machine.
6. Add quality scoring.
7. Build local memory cleanup.
8. Add model versioning.

### Deliverable

A browser can produce a deterministic, versioned biometric vector without uploading the source image.

---

# 46. Phase 2 — FHE Prototype
## Days 8–15

### Tasks

1. Build OpenFHE service.
2. Generate FHE context.
3. Implement key generation.
4. Implement encryption.
5. Implement encrypted distance.
6. Implement ciphertext persistence.
7. Build numerical precision tests.
8. Benchmark parameters.

### Deliverable

Two embeddings can be encrypted and compared with a measured error bound.

---

# 47. Phase 3 — Authentication Orchestrator
## Days 12–20

### Tasks

1. Challenge service.
2. Authentication session database.
3. WebAuthn registration.
4. WebAuthn assertion validation.
5. Operation hash binding.
6. FHE evaluation API.
7. Result authorization object.

### Deliverable

The backend can distinguish:

```text
same face + valid passkey + correct transaction
```

from:

```text
same face + valid passkey + modified transaction
```

---

# 48. Phase 4 — Proof System
## Days 18–26

### MVP track

Implement SP1 proof over:

- decision artifact;
- challenge;
- operation hash;
- threshold policy;
- expiration;
- result commitment.

### Advanced track

Investigate:

- threshold decryption proof;
- scheme switching;
- FHEW comparator;
- Halo2 arithmetic circuit;
- full computation verification.

### Deliverable

A proof can be generated, verified, and rejected when any public input is modified.

---

# 49. Phase 5 — Monad + ERC-4337
## Days 22–30

### Tasks

1. Implement smart account.
2. Implement account factory.
3. Implement biometric validator.
4. Implement proof verifier.
5. Implement recovery module.
6. Implement session keys.
7. Configure EntryPoint.
8. Configure bundler.
9. Configure Paymaster.
10. Deploy testnet contracts.

### Deliverable

A user can perform a real testnet transaction through the full authentication path.

---

# 50. Phase 6 — Production Hardening
## Days 28–42

### Tasks

- threshold FHE;
- external security review;
- adversarial ML testing;
- browser threat analysis;
- rate limits;
- key rotation;
- monitoring;
- recovery hardening;
- multi-device flows;
- encrypted storage HA;
- proof service HA;
- bundler failover.

### Deliverable

A system that can be demonstrated as a coherent privacy/security architecture rather than a collection of independent demos.

---

# 51. Repository Structure

Recommended monorepo:

```text
homobio/
├── apps/
│   ├── web/
│   ├── docs/
│   └── demo/
│
├── packages/
│   ├── biometric-client/
│   ├── webauthn/
│   ├── protocol-types/
│   ├── userop/
│   ├── crypto-utils/
│   └── sdk/
│
├── services/
│   ├── api-gateway/
│   ├── challenge-service/
│   ├── fhe-service/
│   ├── proof-service/
│   ├── webauthn-service/
│   └── relayer-service/
│
├── contracts/
│   ├── account/
│   ├── factory/
│   ├── validators/
│   ├── modules/
│   ├── paymaster/
│   └── test/
│
├── cryptography/
│   ├── openfhe/
│   ├── circuits/
│   └── vectors/
│
├── infra/
│   ├── docker/
│   ├── k8s/
│   └── terraform/
│
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── crypto-parameters.md
    └── protocol-spec.md
```

---

# 52. Technology Stack

## Frontend

- Next.js
- React
- TypeScript
- Tailwind CSS
- WebAuthn browser APIs
- ONNX Runtime Web / WebGPU/WASM
- MediaPipe or equivalent detector
- Face embedding model
- Web Workers

## Backend

- Go or Rust for low-latency services
- C++ service for OpenFHE where binding maturity favors it
- PostgreSQL for metadata
- Redis for challenges/rate limits
- object storage for ciphertexts
- queue such as NATS/Kafka/SQS-compatible system

## Cryptography

- OpenFHE
- CKKS
- optional FHEW/TFHE through supported scheme switching
- SP1
- Halo2 where custom arithmetic proving is justified

## Blockchain

- Solidity
- Foundry
- viem
- ERC-4337
- smart-account modules
- Monad deployment adapter

## Observability

- OpenTelemetry
- Prometheus
- Grafana
- structured logging
- Sentry or equivalent frontend error monitoring

---

# 53. CI/CD

Every pull request must execute:

```text
lint
↓
typecheck
↓
unit tests
↓
contract tests
↓
crypto vector tests
↓
integration tests
↓
security checks
↓
build artifacts
```

Crypto and contract changes must trigger an extended benchmark pipeline.

---

# 54. Deployment Topology

```text
                    CDN / Edge
                        │
                      Next.js
                        │
                     API GW
       ┌────────────────┼────────────────┐
       │                │                │
 Challenge         WebAuthn          UserOp API
       │                │                │
       └────────────────┴────────────────┘
                        │
                   Job Queue
                 ┌──────┴──────┐
                 │             │
              FHE Pool      Proof Pool
                 │             │
                 └──────┬──────┘
                        │
                  Relayer/Bundler
                        │
                      Monad
```

Critical cryptographic workers should run in isolated environments with explicit network policies.

---

# 55. Disaster Recovery

## Scenario: FHE worker outage

Frontend retries through queue-backed service.

## Scenario: proof worker outage

Proof job remains pending and can be resumed from immutable job state.

## Scenario: metadata database outage

No new enrollment/auth session is created, but already-submitted on-chain operations remain unaffected.

## Scenario: ciphertext store outage

Use replicated or content-addressable storage; do not lose the only copy of an enrolled template.

## Scenario: signer/relayer compromise

Relayer keys must not independently control user funds. Smart accounts must still enforce UserOperation authentication policy.

---

# 56. Account Lifecycle

```text
CREATED
  ↓
ENROLLED
  ↓
ACTIVE
  ├──────────────→ LOCKED
  │                  ↓
  │               RECOVERY
  │                  ↓
  └──────────────→ ACTIVE
                     ↓
                   REVOKED
```

### States

`CREATED`: smart-account identity exists, no biometric template yet.  
`ENROLLED`: passkey and biometric policy configured.  
`ACTIVE`: normal operation.  
`LOCKED`: authentication temporarily disabled.  
`RECOVERY`: recovery process pending.  
`REVOKED`: credential/template invalidated.

---

# 57. Failure Handling Matrix

| Failure | User message | Action |
|---|---|---|
| Camera denied | Camera access is required for biometric authentication | Retry or choose recovery |
| No face | Move into the camera frame | Retry |
| Multiple faces | Only one person can be present | Retry |
| Liveness failed | We could not verify that this is a live interaction | Retry |
| Low quality | Improve lighting / move closer | Retry |
| WebAuthn cancelled | Passkey authentication cancelled | Retry |
| Invalid passkey | This passkey is not authorized | Choose another credential |
| Challenge expired | Authentication session expired | Start again |
| FHE failure | Secure comparison failed | Retry; no transaction submitted |
| Proof invalid | Authorization proof invalid | Abort; log security event |
| Bundler rejected | Transaction could not enter the network | Retry after diagnostics |
| On-chain revert | Transaction execution failed | Show reason |
| Recovery pending | Recovery is waiting for the configured delay | Show timer |

---

# 58. Security Events

Emit internal security events for:

```text
BIOMETRIC_ENROLLMENT_CREATED
BIOMETRIC_ENROLLMENT_REPLACED
BIOMETRIC_AUTH_SUCCESS
BIOMETRIC_AUTH_FAILURE
LIVENESS_FAILURE
WEBAUTHN_FAILURE
PROOF_FAILURE
REPLAY_DETECTED
USEROP_REJECTED
RECOVERY_STARTED
RECOVERY_CANCELLED
RECOVERY_COMPLETED
CREDENTIAL_ADDED
CREDENTIAL_REMOVED
SESSION_KEY_CREATED
SESSION_KEY_REVOKED
POLICY_CHANGED
```

Security events should contain hashes/references rather than biometric material.

---

# 59. Admin / Operator Console

The operator console must not expose users' faces or plaintext biometric templates.

Allowed views:

- account ID;
- wallet address;
- authentication success/failure counts;
- cryptographic version;
- FHE job durations;
- proof status;
- UserOperation status;
- suspicious activity indicators;
- recovery state.

Not allowed:

- raw face images;
- raw embeddings;
- decrypted distance;
- private keys.

---

# 60. Developer SDK

Provide an SDK with functions such as:

```ts
createBiometricWallet()
addPasskey()
removePasskey()
enrollBiometric()
authenticateBiometric()
createUserOperation()
createSessionKey()
revokeSessionKey()
startRecovery()
getWalletPolicy()
updateWalletPolicy()
```

Example:

```ts
const wallet = await createBiometricWallet({
  chain: "monad",
  biometric: {
    enabled: true,
    liveness: "active"
  },
  gas: {
    sponsored: true
  }
});
```

The SDK must abstract protocol details without hiding the security state.

---

# 61. dApp Integration API

A dApp should be able to request:

```ts
wallet.request({
  method: "eth_sendUserOperation",
  params: [userOperation]
});
```

The wallet should show:

```text
App requests:
Swap 20 USDC for X

Security:
Biometric + Passkey

Gas:
Sponsored
```

The user should not have to understand FHE, CKKS, SP1, or ERC-4337 to use the product.

---

# 62. Demo Mode Requirements

The hackathon demo should include a visible end-to-end flow:

### Demo A — Registration

1. Create account.
2. Camera capture.
3. Face detection.
4. Liveness.
5. Passkey creation.
6. Encrypted template registration.
7. Account created.

### Demo B — Valid authentication

1. Initiate transaction.
2. Scan face.
3. Passkey prompt.
4. FHE comparison.
5. Proof/attestation.
6. UserOperation.
7. Monad confirmation.

### Demo C — Wrong face

Use a second person / test embedding.

Show:

```text
Biometric verification failed
Transaction not submitted
```

### Demo D — Tampered transaction

Generate a valid authentication artifact for one recipient, then modify the destination before submission.

The smart account must reject it.

### Demo E — Replay

Submit an already consumed proof.

The smart account must reject it.

### Demo F — Recovery

Trigger recovery and show the timelocked state.

---

# 63. Acceptance Criteria

The MVP is considered complete only when all of the following are true.

## Biometric

- [ ] Raw camera frames never leave the client.
- [ ] Embeddings are generated locally.
- [ ] Liveness is active and challenge-based.
- [ ] Template has explicit model version.

## FHE

- [ ] Client encrypts template/query locally.
- [ ] Backend compares ciphertexts.
- [ ] Plaintext embeddings are not persisted by the backend.
- [ ] Cryptographic parameter benchmark exists.
- [ ] Distance precision is documented.

## WebAuthn

- [ ] Passkey registration works.
- [ ] Passkey assertion works.
- [ ] Wrong credential fails.
- [ ] Transaction intent is cryptographically bound.

## ZK / proof

- [ ] Proof or attestation cannot be modified without detection.
- [ ] Expired proof fails.
- [ ] Wrong wallet fails.
- [ ] Wrong UserOperation fails.

## Smart account

- [ ] ERC-4337 UserOperation executes successfully.
- [ ] Invalid auth fails at validation.
- [ ] Session permissions are enforced.
- [ ] Recovery cannot instantly steal account.

## UX

- [ ] User can complete enrollment without seed phrase.
- [ ] User understands what is happening.
- [ ] Failure states are recoverable.

---

# 64. Production Readiness Gate

Do not claim the protocol is production-ready until:

1. FHE parameters have a documented security justification.
2. Biometric threshold has measured FAR/FRR.
3. Liveness has adversarial testing.
4. Browser supply-chain risk has been reviewed.
5. Recovery has been audited.
6. Smart contracts have an independent security review.
7. Proof verification has been independently tested.
8. Key management has been threat-modeled.
9. Template deletion semantics are verified.
10. Device-loss recovery has been tested end-to-end.
11. Privacy/legal requirements for biometric processing have been assessed for deployment jurisdictions.

---

# 65. Research / Future Extensions

## 65.1 Fully ZK-verifiable FHE

Future system could prove a larger relation around:

```text
ciphertext input
→ encrypted computation
→ authorized decryption transcript
→ threshold decision
```

This is substantially harder and should be treated as a research milestone.

## 65.2 ZK biometric proof

Long-term goal:

> Prove that the user possesses a biometric representation within an acceptable similarity bound without revealing the representation.

Potential approaches:

- commitment-based proofs;
- MPC-in-the-head;
- recursive SNARKs;
- privacy-preserving inference;
- zkML for the embedding network;
- proof-carrying inference.

## 65.3 Private liveness

Instead of sending any liveness result to a backend, prove locally that:

```text
random challenge
+ temporal sequence
+ valid face movement
→ live interaction
```

and send only a ZK proof/attestation.

---

# 66. Key Architectural Decisions to Lock Before Coding

The team must explicitly decide these before starting integration:

### Decision 1

Which embedding model?

### Decision 2

Which biometric similarity metric?

### Decision 3

How is thresholding performed?

- polynomial CKKS comparator;
- CKKS→FHEW;
- threshold decryption.

### Decision 4

Who controls the FHE secret/key shares?

### Decision 5

What exactly does the ZK proof prove?

### Decision 6

What is verified on-chain versus off-chain?

### Decision 7

Which ERC-4337 EntryPoint/version does the target environment use?

### Decision 8

What is the recovery quorum and delay?

### Decision 9

What is the user-facing security policy?

### Decision 10

What threat model is considered acceptable for the hackathon versus production?

---

# 67. Recommended Build Order

Do **not** build the entire system top-to-bottom in one pass.

Build vertically sliced milestones:

## Slice 1

```text
Camera
→ embedding
→ local similarity
```

## Slice 2

```text
embedding
→ CKKS encryption
→ FHE distance
→ internal decrypt
```

## Slice 3

```text
WebAuthn
→ challenge
→ authenticated result
```

## Slice 4

```text
authenticated result
→ UserOperation
→ smart account
```

## Slice 5

```text
FHE result
→ proof/attestation
→ on-chain verifier
```

## Slice 6

```text
all components
→ wrong-face rejection
→ replay rejection
→ tamper rejection
→ recovery
```

This approach prevents spending weeks on ZK before proving the underlying biometric/FHE pipeline works.

---

# 68. Final Target Architecture

The target product should ultimately satisfy this invariant:

```text
                 ┌───────────────────────────┐
                 │       User Device         │
                 │                           │
                 │ Face → Embedding          │
                 │       ↓                   │
                 │ FHE Encrypt               │
                 │       +                   │
                 │ WebAuthn Passkey          │
                 └──────────┬────────────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Privacy Coprocessor │
                 │                     │
                 │ CKKS / OpenFHE      │
                 │       ↓             │
                 │ comparator / MPC    │
                 │       ↓             │
                 │ proof/attestation   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   ERC-4337 Account  │
                 │                     │
                 │ Passkey validation │
                 │ + biometric policy  │
                 │ + nonce             │
                 │ + proof validation  │
                 │ + session policy   │
                 └──────────┬──────────┘
                            │
                            ▼
                       ┌───────────┐
                       │  Monad    │
                       │  EVM      │
                       └───────────┘
```

The defining property is:

> **The system should be able to authorize a transaction using a biometric match without requiring the backend, proof service, or blockchain to possess the user's plaintext facial template.**

At the same time, the system must never pretend that FHE alone solves authentication, that ZK alone proves biometric truth, or that a face is equivalent to a cryptographic private key. The security model is the composition of local biometric processing, privacy-preserving computation, passkey authentication, replay-resistant transaction binding, and programmable smart-account policy.

---

# 69. Reference Standards / Documentation

The implementation team should pin exact versions of every dependency and re-check these references before deployment.

- W3C WebAuthn Level 3 Recommendation (published 2026-08-25): https://www.w3.org/TR/webauthn-3/
- ERC-4337 documentation: https://docs.erc4337.io/core-standards/erc-4337.html
- OpenZeppelin Account Abstraction docs: https://docs.openzeppelin.com/contracts/5.x/account-abstraction
- OpenZeppelin Smart Accounts: https://docs.openzeppelin.com/contracts/5.x/accounts
- OpenFHE documentation: https://openfhe-development.readthedocs.io/
- OpenFHE CKKS security discussion: https://openfhe.org/security-of-ckks/
- MediaPipe face detection: https://github.com/google-ai-edge/mediapipe
- WebAuthn API details: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
- Monad developer documentation: https://docs.monad.xyz/

---

# 70. Final Product Definition

**Homomorphic Biometric Passkeys** is a privacy-preserving smart-wallet protocol built around four distinct security primitives:

```text
Biometric processing  → establishes a probabilistic identity signal
FHE                    → hides biometric feature values during remote computation
WebAuthn Passkey      → provides cryptographic user/device authority
ZK / attestation      → makes authorization decisions verifiable
ERC-4337 + Monad      → executes programmable wallet actions
```

The product is successful when those primitives are integrated into one coherent user experience:

> **Look at the camera → authenticate with the device passkey → prove the transaction is authorized → execute the smart-account action without exposing the user's plaintext biometric template.**

That is the core product. Everything else—session keys, gas sponsorship, recovery, multi-device support, policy engines, decentralized ciphertext storage, dashboards, and advanced ZK/FHE research—exists to make that core flow secure, usable, resilient, and extensible.
