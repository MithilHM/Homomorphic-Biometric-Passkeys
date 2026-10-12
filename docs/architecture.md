# Architecture

## 1. The one-sentence invariant

> A transaction can be authorized only when a **passkey signature**, a
> **privacy-preserving biometric decision**, and the **exact intended operation**
> all refer to the same `(wallet, chainId, userOpHash, sessionId, policyVersion,
> expiry)` tuple — and nobody outside the user's device ever holds a plaintext
> face template.

## 2. Components

```text
                       USER DEVICE (trusted for the biometric factor)
                       ┌───────────────────────────────────────────┐
                       │ camera → detect → liveness → align → embed │
                       │                     ↓                       │
                       │           normalise + quantise              │
                       │                     ↓                       │
                       │        encrypt under the FHE public key     │
                       │                     ↘                      │
                       │            WebAuthn passkey assertion       │
                       └─────────────────────┬───────────────────────┘
                                             │ ciphertext + assertion + intent
                                             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ API GATEWAY (no biometric plaintext, no ciphertext store, no signing key)     │
│  /v1/auth/challenge   binds (wallet, chain, userOpHash, policy, template)    │
│  /v1/auth/verify      challenge → passkey → coprocessor → committee → attest │
│  /v1/userop/submit    re-verifies the attestation, then relays               │
│  policy engine · rate limits · audit log · static web client                │
└───────┬───────────────────────────────┬──────────────────────┬──────────────┘
        │                               │                      │
        ▼                               ▼                      ▼
┌───────────────┐            ┌─────────────────────┐   ┌──────────────────┐
│ CHALLENGE SVC │            │ FHE COPROCESSOR     │   │ PROOF SERVICE    │
│ 256-bit nonce │            │ holds 1 of 3 shares │   │ holds 1 of 3     │
│ single use    │            │ sees ciphertexts    │   │ signs attestns   │
│ never chain-  │            │ CANNOT decrypt      │   │ = ecrecover key  │
│ dependent     │            │                    │   │                  │
└───────────────┘            └──────────┬──────────┘   └──────────────────┘
                                          │ product ciphertext
                                          ▼
                            ┌───────────────────────────────┐
                            │ DECRYPTION COMMITTEE          │
                            │ share0 (coprocessor, HTTP)    │
                            │ share1 (proof service)        │
                            │ share2 (custody, unlocked)    │
                            │ → accept / reject / INDETERMINATE │
                            │ the similarity never leaves it│
                            └───────────────┬───────────────┘
                                            │ decision bit only
                                            ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ MONAD EVM                                                                 │
│  EntryPoint → BiometricSmartAccount                                        │
│                 ├── AuthorizationVerifier (ecrecover + bindings + replay)  │
│                 ├── ProofVerifierRegistry  (governance-pinned keys)        │
│                 ├── SessionKeyRegistry    (scoped, capped, expiring)       │
│                 └── RecoveryRegistry      (48 h floor, cancellable)         │
│  BiometricAccountFactory (CREATE2 counterfactual) · SponsorshipPaymaster   │
└────────────────────────────────────────────────────────────────────────────┘
```

## 3. One authentication, step by step

1. **Client** builds the `UserOperation` it wants and computes `userOpHash`
   (ERC-4337 v0.7, verified against viem in `packages/userop/test`).
2. **`POST /v1/auth/challenge`** — the gateway binds the challenge to
   `(wallet, chainId, userOpHash, policyHash, templateVersion, fheKeyVersion,
   expiry)` and returns the **intent challenge**, which is what the passkey must
   sign. The nonce is 256 bits from the CSPRNG and never derived from a block
   hash, so a lagging or reorged chain view cannot break correctness.
3. **Browser** signs the intent challenge with the passkey. WebAuthn's own
   `challenge` is that value, so the signature is cryptographically bound to the
   transaction.
4. **Browser** runs detection → active liveness → alignment → embedding →
   quantisation, then encrypts locally. The plaintext vector is dropped.
5. **`POST /v1/auth/verify`**:
   1. the session must exist and be `pending`;
   2. the challenge is consumed **first** — a retry cannot get a second
      evaluation;
   3. the passkey assertion is verified for real: CBOR/COSE parsing, RP ID hash,
      origin, UP/UV flags, ES256 signature, counter monotonicity;
   4. the coprocessor multiplies the two ciphertexts;
   5. the committee recombines three partial decryptions and produces a decision;
   6. a negative decision fails the attempt; an `indeterminate` one returns 422;
   7. a positive one is signed into a `BiometricAuthorization` that contains no
      image, no embedding and no distance.
6. **Client** packs the authorization + passkey assertion into `userOp.signature`
   (envelope `0x48`) and submits.
7. **`POST /v1/userop/submit`** re-verifies the attestation signature and
   expiry, marks the authorization consumed, and relays.
8. **On-chain** `BiometricSmartAccount.validateUserOp` re-derives the
   authorization hash, checks the wallet/chain/operation/template/policy/threshold
   bindings, and calls `AuthorizationVerifier` for the signature and one-time
   consumption.

## 4. Why the pieces are separated

| Separation | What it buys | Where it is enforced |
|---|---|---|
| Coprocessor ≠ decryption quorum | The party that sees ciphertexts cannot decrypt | Key split at bootstrap; `share-0` never leaves the coprocessor process |
| Coprocessor ≠ gateway | The party that sees ciphertexts holds no signing key, no template metadata beyond commitments | Separate process, bearer-token channel, metadata-only API |
| Off-chain WebAuthn ≡ on-chain attestation | The protocol works today and can move P-256 verification on-chain without changing the client | Modular validator; `P256VerifierAdapter` is the swap point |
| Passkey ≡ biometric | Neither factor alone can spend | The `0x48` envelope requires both; the account rejects an empty assertion |
| Decision ≡ decision program | A weaker engine cannot be substituted silently | `decisionProgramHash` on-chain and in the registry |
| Policy revision ≡ challenge | A threshold change invalidates outstanding challenges | `policyHash` inside the authorization hash |

## 5. Trust boundaries

```text
  TRUSTED            |  SEMI-TRUSTED (mitigated)  |  UNTRUSTED
  user device        |  API gateway, proof svc    |  network, bundler,
  passkey            |  FHE coprocessor           |  dApp, relayer,
  decryption quorum  |  storage of ciphertexts    |  browser extensions
```

The relayer holds no key that can spend user funds: it forwards operations the
account already authorized (PRD section 55).

## 6. Data flow for biometric material

```text
frame ──► detect ──► liveness ──► align ──► embed ──► quantise ──► encrypt ──► discard
  │         │           │           │        │           │           │
  └─────────┴───────────┴───────────┴────────┴───────────┴───────────┘
                    never leave the device (PRD P1)
```

The only artefact that crosses the boundary is `CiphertextEnvelope`:
`{ ciphertext, commitment, dimension, modelVersion, fheKeyVersion, fheEngine,
encodingVersion, scaleBits, parameters }`. `commitment = keccak256(ciphertext)`
is what goes on-chain; the ciphertext itself stays in coprocessor storage.

## 7. Storage split

| Data | Where | Notes |
|---|---|---|
| Ciphertext templates | Coprocessor store (object storage in production) | Content-addressed; `commitment` verified before every use |
| Accounts, sessions, credentials, proofs | Gateway JSON store (Postgres in production) | `packages/store` is the seam |
| Committee shares | Files with `0600`, one per holder | Custody share needs an unlock secret |
| On-chain | Commitments, versions, policy hashes, verifier keys | No ciphertext blobs (PRD section 26) |

## 8. Repository map

```text
packages/
  crypto-utils      keccak256 (Ethereum), ABI encoder, byte/hash helpers
  protocol-types    canonical encodings mirrored by Solidity
  fhe               RLWE engine: field, ring/NTT, scheme, encode, committee
  webauthn          CBOR, COSE, registration + assertion verification, client
  biometric-client  detect, liveness, align, embed, templates, failures
  userop            ERC-4337 v0.7 hashing, nonce domains, envelopes
  http-kit          dependency-free HTTP layer + redaction + rate limits
  store             JSON document store
  sdk               developer-facing wallet API
services/
  api-gateway       orchestrator, policy engine, committee, static client
  challenge-service single-use challenges
  webauthn-service  credential storage + verification
  fhe-service       the coprocessor process (1 of 3 shares)
  proof-service     attestation signing (1 of 3 shares)
  relayer-service   bundler client + submission audit
contracts/          Solidity (account, factory, validators, modules, paymaster)
apps/web            browser client
apps/demo           offline negative-path demo
cryptography/       OpenFHE engine + cross-language vectors
docs/               architecture, threat model, crypto parameters, spec
```

## 9. Running it

```bash
npm install
npm run dev          # coprocessor + gateway + built web client on :5000
npm test             # 128 tests, including a full HTTP integration run
npm run demo         # negative paths, no services needed
npm run bench        # FHE parameter matrix -> docs/benchmarks/
npm run compile:contracts
```

The gateway refuses to start if the coprocessor is unreachable or the committee
shares on disk do not match the running coprocessor's key. A degraded FHE path is
a startup failure, not a silent downgrade.
