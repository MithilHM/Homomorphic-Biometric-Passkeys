# Homomorphic Biometric Passkeys

**A seedless, non-custodial ERC-4337 smart account where a WebAuthn passkey is
the cryptographic authority and a privacy-preserving biometric match is the
authorization condition.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Monad](https://img.shields.io/badge/Network-Monad_EVM-8A2BE2.svg)](https://monad.xyz)
[![ERC-4337](https://img.shields.io/badge/Standard-ERC--4337%20v0.7-green.svg)](https://eips.ethereum.org/EIPS/eip-4337)

---

## The one-paragraph version

The user enrolls a passkey and a biometric template. At authentication time the
browser computes a face embedding **on the device**, encrypts it with an FHE
public key, and discards the plaintext. The server multiplies the encrypted
live capture by the encrypted enrolled template, and a **3-of-3 decryption
committee** jointly recovers the cosine similarity — no single service, including
the one that did the multiplication, ever sees it. The committee signs a
statement containing a decision bit and commitments to the two ciphertexts. That
signature goes into `userOp.signature`, where the on-chain account checks it
against the exact operation hash the EntryPoint computed.

No image or plaintext embedding ever crosses a process boundary, and the only
biometric signal that leaves the server is a single bit plus two hashes.

---

## What this is not

Stated up front because these are the places this kind of project usually
overclaims:

- **Not ZK-proven.** The decision path is *threshold decryption + signed
  attestation*. We do **not** claim the homomorphic arithmetic is zero-knowledge
  verified. An SP1 verifier interface exists and is selectable, but the service
  reports it unavailable rather than fabricating a proof.
- **Not CKKS.** The engine is a real leveled **RLWE** scheme over
  `Z_q[X]/(X^1024+1)`, depth 1, ciphertext×ciphertext multiply, no
  bootstrapping. The OpenFHE CKKS path is optional and absent by default.
- **Not production-hardened.** See [`docs/threat-model.md`](docs/threat-model.md)
  for the open items — notably T-9 (partial decryptions are not MAC-checked).
  The shares are additively split and recombined, but a malicious committee
  member could bias a single decision until SPDZ-style MAC checking replaces it.
- **Not passive liveness.** The pipeline requires active liveness; the SDK
  refuses to construct a wallet configured for `passive`.

---

## Quickstart

Requires Node ≥ 20.11. There are **no runtime dependencies** — the FHE scheme,
keccak-256, CBOR, COSE, WebAuthn verification and the ABI encoder are all in
this repo.

```bash
npm install
npm run dev          # FHE coprocessor on :5001, then the API gateway on :5000
```

Open <http://localhost:5000>. The gateway builds and serves the web client on
first run.

```bash
npm test             # 166 tests
npm run typecheck    # strict TS, noEmit
npm run demo         # 7 end-to-end scenarios against a live stack
npm run bench        # regenerates docs/benchmarks/fhe-parameters.json
npm run vectors      # regenerates cryptography/vectors/protocol.json
```

---

## Architecture

```text
   ┌──────────────────────── User device ────────────────────────┐
   │  camera frame ──► skin/chroma gate ──► active liveness      │
   │        ──► alignment ──► embedding ──► L2 normalise         │
   │        ──► quantise (2^18) ──► RLWE encrypt as `low`         │
   │                                      plaintext discarded     │
   │  WebAuthn passkey signs the intent challenge                │
   └──────────────────────────┬─────────────────────────────────┘
                              │  assertion + ciphertext  (no plaintext)
                              ▼
   ┌───────────────────── API gateway :5000 ─────────────────────┐
   │  1. consume challenge      (burned BEFORE anything else)     │
   │  2. verify WebAuthn assertion (ES256, RP hash, UV, counter) │
   │  3. forward ciphertext ─────────────┐                       │
   └─────────────────────────────────────┼───────────────────────┘
                                       ▼
   ┌──────────────── FHE coprocessor :5001 ──────────────────────┐
   │  Enc(template_high) · Enc(query_low)  →  3-term product     │
   │  holds share 0 only; cannot decrypt alone                    │
   └──────────────────────┬──────────────────────────────────────┘
                          │ product ciphertext
   ┌──────────────────────▼──────────────────────────────────────┐
   │  Threshold decryption: share 0 (coprocessor)                 │
   │                      + share 1 (proof service)               │
   │                      + share 2 (custody, behind a token)     │
   │  similarity = coeff₀ / 2^36;  compare against threshold ± margin │
   └──────────────────────┬──────────────────────────────────────┘
                          │ decision bit only
   ┌──────────────────────▼──────────────────────────────────────┐
   │  Proof service signs the authorization (secp256k1, EIP-191)  │
   │  envelope = {decision, thresholdBps, commitments, …}         │
   └──────────────────────┬──────────────────────────────────────┘
                          ▼
   ┌──────────────── Monad EVM ──────────────────────────────────┐
   │  EntryPoint ──► BiometricSmartAccount.validateUserOp        │
   │     · decisionProgramHash / templateVersion / fheKeyVersion  │
   │     · thresholdBps ≥ account floor                           │
   │     · AuthorizationVerifier: ecrecover + re-derive hash      │
   │     · session consumed in the VALIDATION phase               │
   └─────────────────────────────────────────────────────────────┘
```

Service boundaries, trust assumptions and the data each component sees are in
[`docs/architecture.md`](docs/architecture.md).

---

## Repository layout

```text
packages/
  crypto-utils/        keccak-256 (Ethereum's), ABI encoder, vector math, base64url
  fhe/                 RLWE scheme: field, NTT, ring, encoding, scheme, committee
  webauthn/            strict CBOR, COSE→SPKI, registration + assertion verification
  biometric-client/    YCbCr skin gate, active liveness, embedding, template aggregation
  protocol-types/      canonical hashes and types, mirrored 1:1 by Solidity
  userop/              ERC-4337 v0.7 hashing, nonce domains, session envelope
  http-kit/            HTTP app with rate limits, CORS, body caps, error envelope
  store/               file-backed record store
  sdk/                 developer SDK + the `0x48` authorization envelope packer

services/
  api-gateway/         all routes, orchestration order, committee recombination
  fhe-service/         the coprocessor (separate process, own service token)
  challenge-service/   single-use, replay-protected challenges
  webauthn-service/    credential store + assertion verification
  proof-service/       authorization attestation + one decryption share
  relayer-service/     UserOperation submission (bundler or dry-run)

contracts/
  protocol/AuthDomain.sol         the canonical cross-language hash library
  account/BiometricSmartAccount.sol
  validators/AuthorizationVerifier.sol
  modules/SessionKeyRegistry.sol, RecoveryRegistry.sol
  factory/, paymaster/, interfaces/

apps/web/              vanilla-TS client, served by the gateway
apps/demo/             7 end-to-end scenarios
cryptography/vectors/  generated conformance vectors
docs/                  spec, architecture, threat model, parameters, benchmarks
```

---

## The two ideas worth understanding

### 1. The mirrored layout puts the dot product in coefficient 0

For L2-normalised embeddings, `‖x − y‖² = 2 − 2⟨x,y⟩`, so one ciphertext
multiplication evaluates the whole similarity. The difficulty is *extracting*
the dot product from a ring element.

If both operands sit in the low coefficients, the product's coefficient `k` is a
convolution and the dot product is the **sum over even coefficients** — which no
ring operation can isolate without reintroducing the noise being measured.

So the enrolled template is **mirrored**: component 0 stays at coefficient 0, and
component `j` goes to coefficient `N − j`, negated. Every diagonal pair then
lands in coefficient 0 of the negacyclic product:

```text
i + (N − i) = N   ⇒   X^i · X^(N−i) = X^N = −1
```

The wrap's minus sign is cancelled by the mirrored operand's negation. The
`(0,0)` pair doesn't wrap, so it is stored un-negated. Coefficient 0 **is** the
quantised dot product, exactly. Off-diagonal pairs land elsewhere and contribute
only noise — noise that is measured and bounded rather than assumed.

Without relinearization, the dominant key-switch error (which scales with the
*product* plaintext) simply does not exist. That is what makes a single
homomorphic multiplication accurate enough to threshold on.

### 2. Approximate comparison exposes its own uncertainty

The engine's error is a random variable. Measured over 300 trials at the default
parameters: mean 1.4e-4, p99 4.5e-4, max **4.9e-4**, against a documented bound
of 2⁻⁹ ≈ 1.95e-3.

A comparison landing inside that band returns `indeterminate` (HTTP 422), not a
coin flip. The account independently refuses any authorization whose
`thresholdBps` falls below its own floor, so a permissive off-chain policy
cannot widen the on-chain minimum.

---

## Security properties

1. **The passkey is the authority.** `decision == true` is never sufficient. The
   account rejects an authorization envelope whose passkey assertion is
   zero-length, regardless of how the biometric part evaluated.
2. **No plaintext biometric leaves the device.** Frames and embeddings exist
   only in `packages/biometric-client` memory.
3. **No silent degradation.** There is no fallback to passkey-only and no
   fallback to a weaker metric. Every failure is an explicit state.
4. **Intent binding.** The signed challenge commits to chain, wallet,
   `userOpHash`, nonce, session, policy revision and expiry simultaneously, so
   an assertion for one transaction cannot authorize another.
5. **One authorization, one execution.** Sessions are consumed in
   `validateUserOp`, not `execute`.
6. **Committee-incapable-by-construction.** Shares sum additively; any proper
   subset is uniformly random and leaks nothing.
7. **Replay is one-way.** A consumed session can never be consumed again, by
   anyone.

Known limitations are enumerated honestly in
[`docs/threat-model.md`](docs/threat-model.md).

---

## Testing

166 tests, no network access required beyond loopback.

| Suite | Tests | What it pins |
|---|---|---|
| `packages/crypto-utils` | 20 | keccak vs node SHA3, ABI encoder vs viem |
| `packages/fhe` | 18 | scheme correctness, the error bound, committee threshold |
| `packages/webauthn` | 22 | registration + assertion verification, counter rules |
| `packages/userop` | 16 | userOpHash vs viem, nonce domains, session envelope |
| `packages/biometric-client` | 24 | skin gate, liveness, determinism, failure messages |
| `contracts/test` | 31 | Solidity↔TS field order, spec conformance |
| `cryptography/vectors/test` | 19 | the CKKS engine matches the RLWE decision procedure |
| `services/test` | 16 | full HTTP pipeline with a software authenticator |

Foundry tests (`contracts/test/*.t.sol`) run in CI; `forge` is not required
locally. To run them:

```bash
forge install foundry-rs/forge-std --no-git
forge test -vv
```

Cross-language consistency is enforced two ways: by parsing the Solidity sources
and comparing every hashed field's order and width against the TypeScript, and
by executing the account's envelope decoder under Foundry.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/protocol-spec.md`](docs/protocol-spec.md) | Normative byte-level encoding of every structure |
| [`docs/architecture.md`](docs/architecture.md) | Services, data flow, trust boundaries |
| [`docs/threat-model.md`](docs/threat-model.md) | Attacks, mitigations, and what is *not* solved |
| [`docs/crypto-parameters.md`](docs/crypto-parameters.md) | Why N=1024, q, scale 2¹⁸, dim 128 — benchmarked |
| [`docs/benchmarks/`](docs/benchmarks) | Measured latency, size and accuracy matrix |

---

## Deployment

Configuration is entirely environment-driven; see [`.env.example`](.env.example).
The gateway **refuses to start** if the FHE coprocessor is unreachable — a
degraded FHE path must fail loudly rather than silently downgrade the security
posture.

```bash
docker compose up -d      # gateway + coprocessor
```

`RELATER_DRY_RUN` defaults to `true`: without a real bundler the relayer logs
the UserOperation instead of submitting it. Set `RELAYER_DRY_RUN=false` and
supply `BUNDLER_URL` to actually submit.

---

## License

MIT