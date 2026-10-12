# Protocol Specification

Byte-level definition of the Homomorphic Biometric Passkeys protocol.

Everything here is **normative**: the TypeScript in `packages/` and the Solidity
in `contracts/` are two implementations of this document, and
`contracts/test/cross-language.test.ts` fails the build if they drift. Where the
two languages disagree, this document decides which one is wrong.

**Read this alongside:**

- [`crypto-parameters.md`](./crypto-parameters.md) — why the FHE parameters are
  what they are, and what the noise bound actually is.
- [`threat-model.md`](./threat-model.md) — what each construction does *not*
  protect against. Read it before deploying anything.
- [`architecture.md`](./architecture.md) — service boundaries and data flow.

---

## 0. Notation and invariants

| Notation | Meaning |
|---|---|
| `‖A‖` | concatenation of byte strings |
| `be8/16/32/64(x)` | big-endian encoding of `x` in that many bytes |
| `keccak(x)` | keccak-256 (Ethereum's, **not** NIST SHA-3) |
| `sha256(x)` | NIST SHA-256 |
| `R_q` | `Z_q[X]/(X^N + 1)`, negacyclic ring |

Three invariants hold across the whole protocol:

1. **The passkey is the authority; the biometric is a condition.** A valid
   `decision == true` is *never* sufficient on its own. The account requires a
   non-empty WebAuthn assertion in the same envelope (§6).
2. **No plaintext biometric ever crosses a process boundary.** Frames and
   embeddings exist only in `packages/biometric-client` memory. What crosses is
   a ciphertext, and what leaves the server is a single bit.
3. **Approximate comparison is exposed, not hidden.** When the encrypted
   comparison lands inside the noise band the answer is `indeterminate`, not a
   coin flip (§5.4).

Domain separators, all ASCII, none of them prefixes of another:

| Constant | Value |
|---|---|
| `AUTH_DOMAIN` | `HOMOBIO/AUTH-V1` |
| `ENROLL_DOMAIN` | `HOMOBIO/ENROLL-V1` |
| `ENVELOPE_DOMAIN` | `HOMOBIO/ENVELOPE-V1` |
| `SESSION_DOMAIN` | `HOMOBIO/SESSION-V1` |
| `RESULT_DOMAIN` | `HOMOBIO/RESULT-V1` |
| `DECISION_PROGRAM_DOMAIN` | `HOMOBIO/DECISION-PROGRAM-V1` |
| `INTENT_DOMAIN` | `HOMOBIO/INTENT-V1` |
| `CREDENTIAL_DOMAIN` | `HOMOBIO/CREDENTIAL-V1` |
| `ACCOUNT_DOMAIN` | `HOMOBIO/ACCOUNT-V1` |

---

## 1. Canonical primitive encodings

### 1.1 Hashes and integers

All integers on the wire and in hashes are **unsigned big-endian** with a fixed
width. There are no signed integers in any hashed structure. Signedness only
appears *inside* the FHE plaintext, after decryption (§5.2).

```
be8(x)   = x.toString(16).padStart(2,  "0")
be16(x)  = x.toString(16).padStart(4,  "0")
be32(x)  = x.toString(16).padStart(8,  "0")
be64(x)  = x.toString(16).padStart(16, "0")
be256(x) = x.toString(16).padStart(64, "0")
```

`address` is always 20 bytes, lowercase hex, `0x` stripped inside a hash.

### 1.2 `bytes16` session identifiers

Session ids are 16 bytes on chain. The services mint UUIDv4 strings, so:

```
sessionIdToBytes(id):
  id matches /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/  -> strip "-", 16 bytes
  id matches /^[0-9a-fA-F]{32}$/                                               -> 16 bytes
  otherwise                                                                    -> error
```

Both encodings of the same identifier produce identical bytes. A client that
already holds one form does not need to convert.

### 1.3 Length prefixes

Where a variable-length field appears inside a hashed structure it is prefixed
with `be32(len)`:

```
lengthPrefixed(parts...) = ‖ Σ_i be32(len(parts[i])) ‖ parts[i] ‖ Σ_i parts[i]
```

Array-valued fields are hashed this way rather than inlined, so a length can
never be confused with content.

### 1.4 Canonical JSON

The one place JSON is hashed is the policy document. Keys are sorted
lexicographically by UTF-16 code unit, there is no insignificant whitespace,
and no trailing newline. `policyHash` is:

```
policyHash = keccak("HOMOBIO/ENROLL-V1" ‖ utf8(canonicalJson(policy)))
```

---

## 2. The ERC-4337 operation hash

ERC-4337 v0.7. This is the single most important binding in the system: the
passkey signs a challenge containing it, the biometric authorization names it,
and the EntryPoint recomputes it from calldata.

```
inner = keccak(abi.encode(
    address    sender,
    uint256    nonce,
    bytes      initCode,
    bytes      callData,
    uint256    callGasLimit,
    uint256    verificationGasLimit,
    uint256    preVerificationGas,
    uint256    maxPriorityFeePerGas,
    uint256    maxFeePerGas,
    bytes      paymasterAndData,
    bytes      signature))

userOpHash = keccak(abi.encode(inner, address entryPoint, uint256 chainId))
```

Two notes that are easy to get wrong:

- `inner` is `bytes32` in the outer encode, **not** `bytes`. Passing the 32-byte
  value as dynamic `bytes` produces a different hash.
- The `signature` field participates in `inner`. An authorization therefore
  commits to the very envelope that carries it; you cannot compute the final
  `userOpHash` until the envelope is packed (§6).

### 2.1 Nonce domains

The top byte of the 256-bit nonce selects the workflow, so wallet, session-key
and recovery flows never collide:

```
nonce = (uint8(domain) << 248) | uint248(sequence)
```

| Domain | Value |
|---|---|
| `Wallet` | 0 |
| `SessionKey` | 1 |
| `Recovery` | 2 |
| `DeviceManagement` | 3 |
| `Paymaster` | 4 |

A sequence ≥ 2²⁴⁸ is rejected rather than truncated.

---

## 3. Challenge issuance and the intent binding

### 3.1 Issue

`POST /v1/auth/challenge` returns a single-use challenge:

```jsonc
{
  "challengeId": "<uuid>",
  "sessionId":   "<uuid>",
  "wallet":      "0x…",
  "chainId":     143,
  "operationHash": "0x<userOpHash>",
  "nonce":       "<64 hex chars, CSPRNG>",
  "issuedAt":    1791370000,
  "expiresAt":   1791370060,       // issuedAt + 90s default
  "biometricPolicyVersion": 1,
  "fheKeyVersion": 1,
  "webauthnRpId": "app.example",
  "webauthnOrigin": "https://app.example",
  "policyHash":  "0x…"
}
```

The nonce is 256 bits from the CSPRNG and is **never** derived from a block
hash. The backend must remain correct when its view of the chain lags or
reorganises; a chain-state identifier may be mixed in as extra entropy, but
correctness never depends on it.

### 3.2 The intent challenge

This is the exact string the browser's authenticator signs:

```
intentChallenge = keccak(
    "HOMOBIO/INTENT-V1" ‖ "|" ‖
    dec(chainId)             ‖ "|" ‖
    wallet                   ‖ "|" ‖
    userOpHash               ‖ "|" ‖
    nonce                    ‖ "|" ‖
    sessionId                ‖ "|" ‖
    dec(biometricPolicyVersion) ‖ "|" ‖
    dec(expiresAt)           ‖ "|" ‖
    policyHash)
```

Note this is a **pipe-joined ASCII string hashed with keccak**, not a packed
binary struct. It is not mirrored in Solidity: the server recomputes it and
compares against `clientData.challenge`.

Because the intent commits to `userOpHash`, `nonce`, `sessionId`, policy
revision and expiry simultaneously, an assertion captured for one transaction
cannot be replayed for another. This is the whole reason a passkey is safe to
treat as an authority.

### 3.3 Consume — before anything else

`POST /v1/auth/verify` consumes the challenge as its **first** action, before
the assertion is verified and before the FHE engine is invoked. A retry carrying
a perfectly valid assertion therefore cannot obtain a second evaluation of the
same operation.

Rejection codes: `replay_detected`, `challenge_not_found`, `challenge_expired`,
`challenge_failed`, `wallet_mismatch`, `chain_mismatch`, `operation_mismatch`.

---

## 4. The WebAuthn assertion

### 4.1 Wire format

```jsonc
{
  "credentialId": "<base64url>",
  "clientDataJSON": "<base64url>",
  "authenticatorData": "<base64url>",
  "signature": "<base64url, 64 bytes, raw r‖s>",
  "userHandle": "<base64url, optional>"
}
```

Only **ES256** (`-7`, P-256/SHA-256) is accepted. RS256 is recognised in stored
credentials for migration but is not issued.

### 4.2 Verification

The signed message is:

```
signedData = authenticatorData ‖ sha256(clientDataJSON)
signature  = ECDSA-P256-SHA256(signedData)  // raw 64 bytes, no DER
```

Checked, in order:

| Check | Failure code |
|---|---|
| credential exists and is `active` | `credential_not_found` / `credential_revoked` |
| `signature.length == 64` (raw, not DER) | `malformed` |
| `clientData.type == "webauthn.get"` | `malformed` |
| `clientData.challenge == intentChallenge` | `challenge_mismatch` |
| `clientData.origin == configured origin` (exact) | `origin_mismatch` |
| `authenticatorData[0..32] == sha256(rpId)` | `rp_mismatch` |
| UP flag set | `malformed` |
| UV flag set (when policy requires it) | `user_verification_required` |
| `userHandle` matches the stored value | `credential_not_found` |
| signature verifies under the stored SPKI key | `signature_invalid` |
| counter is monotonic | `counter_regression` |

### 4.3 Counter rule

A zero counter is legitimate for synced passkeys (`BE` or `BS` set) and for
credentials that never increment. Regression is only an error when the
credential is **not** synced **and** both counters are non-zero:

```
if (!synced && authData.signCount != 0 && authData.signCount <= stored.signCount)
    reject counter_regression
```

### 4.4 Credential commitment

Used for account derivation and for the on-chain `passkeys` mapping:

```
credentialCommitment = keccak(
    utf8("HOMOBIO/CREDENTIAL-V1") ‖ utf8(wallet ‖ "|" ‖ credentialId ‖ "|" ‖ publicKeyFingerprint))
```

Note there is **no separator** between the domain and the payload — only
*within* the payload. The same applies to `intentChallenge` (§3.2) and the SP1
public-inputs hash: those join the domain with a `|`, these do not.

where `publicKeyFingerprint` is the last 32 bytes of the SPKI DER.

### 4.5 Attestation

Attestation statements are **not** verified against a metadata service. The
client requests `attestation: "none"` and the product does not need
authenticator attestation; the flags policy actually cares about (UV, BE, BS)
are parsed regardless.

---

## 5. The homomorphic biometric comparison

### 5.1 Parameters

```
R      = Z_q[X] / (X^1024 + 1)
q      = 1152921504606877697          (61-bit prime, q ≡ 1 mod 2N)
scale  = 2^18                        (fixed-point exponent)
dim    = 128                         (embedding dimension)
```

`dim = 128 < N` guarantees the negacyclic convolution wraps at most once, which
is what makes the mirrored layout below exact.

### 5.2 Encoding

An embedding `v` is L2-normalised and quantised:

```
encode(v) = round(normalize(v) * 2^18)      // 128 signed integers
```

**L2 normalisation is load-bearing, not cosmetic.** For unit vectors
`‖x − y‖² = 2 − 2⟨x,y⟩`, so one ciphertext multiplication evaluates the entire
similarity and the coprocessor never needs the plaintext distance.

### 5.3 The mirrored layout

Two placements exist:

```
low :  component i          -> coefficient i
high:  component 0          -> coefficient 0
       component j > 0      -> coefficient N − j,  negated
```

With **both** operands `low`, product coefficient `c_k` is a convolution and the
dot product is the *sum over even coefficients* — no ring operation extracts
that without reintroducing the noise being measured.

Mirroring one operand fixes it. Every diagonal pair `(i, i)` lands in
coefficient 0 of the negacyclic product:

```
i + (N − i) = N   =>   X^i · X^(N−i) = X^N = −1
```

The wrap contributes a minus sign, which the mirrored operand's negated
coefficient cancels exactly. The `(0, 0)` pair does not wrap, so it is stored
un-negated. Therefore:

```
coefficient 0 of Enc(template_high) · Enc(query_low)  ==  ⟨x, y⟩   exactly
```

Off-diagonal pairs land elsewhere and contribute only noise — noise that is
measured and bounded, never assumed. Only coefficient 0 is read after
decryption, so the error is one noise term rather than a sum over the ring.

**The enrolled template always uses `high`; the live capture always uses `low`.**

### 5.4 Reading the decision

```
raw        = toSigned(decrypted[0])                      // centred representative
similarity = raw / 2^(2·scaleBits)                      // 2^36
errorBound = 2^-9                                       // measured, see below
margin     = max(policy.noiseMargin, errorBound)
```

```
similarity ≥ threshold + margin  ->  accept   (decision = true)
similarity ≤ threshold − margin  ->  reject   (decision = false)
otherwise                        ->  indeterminate
```

`indeterminate` is an explicit, non-forgeable outcome (HTTP 422, code
`indeterminate`) meaning "capture a new sample". It is **not** collapsed into
either branch. The account additionally refuses any authorization whose
`thresholdBps` is below the account's `minimumSimilarityBps`, so a permissive
off-chain policy cannot widen the on-chain floor.

Measured error over 300 trials at the default parameters: mean 1.4e-4, p99
4.5e-4, **max 4.9e-4** — comfortably inside the documented 2⁻⁹ ≈ 1.95e-3 bound.

### 5.5 Ciphertext wire format

```
offset  size  field
0       4     magic "HBFH" (0x48424648)
4       1     encoding version (1)
5       1     flags — bit0 = carries an s^2 term
6       2     ringDimension, big-endian
8       …     2 or 3 polynomials of ringDimension × 8 bytes, big-endian, reduced mod q
```

Length is exactly `8 + count · N · 8`; a mismatch is rejected before any
arithmetic. Coefficients ≥ q are rejected — a coprocessor must never evaluate an
attacker-controlled polynomial.

Fresh encryptions are 2-term (`p0 = 0`); products are 3-term. The scheme is
**depth 1 with no relinearization**: the committee holds `s` and computes `s²`
once, and skipping key-switching removes the dominant noise term (the
key-switch error scales with the *product* plaintext).

---

## 6. The authorization object

### 6.1 Canonical hash

```
authorizationHash = keccak(abi.encodePacked(
    "HOMOBIO/AUTH-V1",                 // bytes
    uint8   version,
    address wallet,
    uint64  chainId,
    bytes32 userOpHash,
    bytes16 sessionId,
    bytes32 policyHash,
    uint32  templateVersion,
    uint32  fheKeyVersion,
    uint8   decision,                  // 0x00 | 0x01  (bool encodes identically)
    uint32  thresholdBps,              // millionths of the cosine scale
    bytes32 resultCommitment,
    uint64  issuedAt,
    uint64  expiresAt,
    uint32  proofSystem,
    uint32  verifierVersion,
    bytes32 decisionProgramHash))
```

Sol Solidity's `abi.encodePacked(bool)` is one byte `0x00`/`0x01`, identical to
the `uint8` above. Field order and widths are asserted by
`cross-language.test.ts` against the Solidity parameter list.

### 6.2 Result commitment

```
resultCommitment = keccak("HOMOBIO/RESULT-V1" ‖
    bytes16 sessionId ‖ bytes32 templateCommitment ‖
    bytes32 queryCommitment ‖ uint8 decision)
```

`templateCommitment` and `queryCommitment` are `keccak256` of the **raw
ciphertext bytes** — not of a re-serialised structure — so the commitment
commits to exactly what travelled.

### 6.3 Decision program hash

```
decisionProgramHash = keccak("HOMOBIO/DECISION-PROGRAM-V1" ‖ lengthPrefixed(
    engine, metric, dim(u32), scaleBits(u32), N(u32), securityBits(u32)))
```

The account stores this and rejects any authorization naming a different one,
so a substituted comparison cannot be presented as the real one.

### 6.4 Signature

```
prefixed  = keccak("\x19Ethereum Signed Message:\n32" ‖ authorizationHash)
signature = secp256k1-sign-sha256(prefixed)   // raw r‖s‖v, 65 bytes
```

Node signs `sha256(prefixed)`; the contract recovers over `keccak256(prefix ‖
digest)`. The EIP-191 prefix means the attestation can never be replayed as a
raw transaction on another chain. The verifier rejects malleable (high-s)
signatures, so one digest admits exactly one signature.

### 6.5 What the authorization deliberately omits

No image data, no plaintext embedding, no plaintext distance, no similarity
value. Only a decision bit, the threshold applied, and commitments.

---

## 7. The `userOp.signature` envelopes

`userOp.signature` carries exactly one of two envelopes, selected by a magic
byte. The account branches on `signature[0]` and rejects anything else.

### 7.1 Authorization envelope — `0x48`

```
offset  size        field
0       1           magic 0x48
1       2           bodyLength (big-endian), excludes this 3-byte header
3       32          envelopeHash
35      2           assertionLength
37      …           assertion bytes (variable)
…       1           version
        20          wallet
        8           chainId
        32          userOpHash
        16          sessionId
        32          policyHash
        4           templateVersion
        4           fheKeyVersion
        1           decision
        4           thresholdBps
        32          resultCommitment
        8           issuedAt
        8           expiresAt
        4           proofSystem
        4           verifierVersion
        32          decisionProgramHash
        32          attestationHash
        65          committee signature (r‖s‖v)
```

The authorization block is exactly **242 bytes** and the tail exactly **65**, so
the decoder is index-based: total body after the assertion must be
`242 + 65 = 307`.

Reverts: `MalformedEnvelope` (any length disagreement),
**`MissingPasskeyAssertion`** (zero-length assertion). The second is the
load-bearing one — an authorization envelope without a passkey assertion is
never accepted, regardless of how the biometric part evaluated.

Packed by `@homobio/sdk`'s `packAuthorizationEnvelope`. It deliberately does not
live in `packages/userop`: a second encoder for magic `0x48` is exactly how a
client ends up submitting an envelope the contract cannot parse.

### 7.2 Session envelope — `0x53`

```
offset  size  field
0       1     magic 0x53
1       2     bodyLength = 96
3       20    session key address
23      8     validUntil
31      4     selector
35      32    value
67      32    scopeHash
```

Total length is exactly `3 + 20 + 8 + 4 + 32 + 32 = 99` bytes. `scopeHash` must
equal the live `SessionKeyRegistry.scopeHashes(key)`. Packed by
`@homobio/userop`'s `packSessionEnvelope`.

A session key exists only because its grant went through the full §7.1 path, so
this envelope is a scoped delegation of an already-authorized authority, not a
weaker authentication.

### 7.3 Envelope hash

```
envelopeHash = keccak("HOMOBIO/ENVELOPE-V1" ‖ lengthPrefixed(
    wallet, chainId(u64), userOpHash, challengeId(16), sessionId(16),
    nonce, policyHash, authorizationHash, expiresAt(u64)))
```

---

## 8. On-chain verification

`AuthorizationVerifier.verify(account, userOpHash, chainId, authorization)` —
the order below is the security-relevant part:

1. `consumed[sessionId]` is false — replay protection is one-way and permanent.
2. `wallet == account`.
3. `chainId == block.chainid`.
4. `userOpHash ==` the hash the EntryPoint computed for **this** operation.
5. `issuedAt ≤ block.timestamp ≤ expiresAt`.
6. `expiresAt − issuedAt ≤ maxAuthorizationLifetime` — a hard cap that holds
   *even if the committee signs otherwise*. A stolen committee key cannot mint
   long-lived authorizations.
7. `decision == true` — **a negative decision is never an authorization, whatever
   it signed.**
8. `proofSystem == 1` (threshold attestation) and `verifierVersion ≥
   minVerifierVersion`.
9. `registry.verifier(proofSystem, verifierVersion) != 0`.
10. `registry.isAcceptedDecisionProgram(decisionProgramHash)`.
11. Re-derived `authorizationHash == attestationHash` — the signed digest is
    never trusted to describe its own contents.
12. `ecrecover(...) == verifier`, with a low-s malleability check.

On top of that, `BiometricSmartAccount.validateUserOp` independently rejects a
wrong `decisionProgramHash`, `templateVersion`, `fheKeyVersion`, `policyHash`, or
a `thresholdBps` below its own `minimumSimilarityBps`.

Consumption happens in `validateUserOp` (the validation phase), **not** in
`execute`, so one authorization authorises exactly one execution.

---

## 9. Full authentication flow

```
client                                  gateway                    coprocessor
  │                                        │                            │
  │ POST /v1/config                        │                            │
  │───────────────────────────────────────>│                            │
  │  publicKey, engine params, policy list  │                            │
  │<───────────────────────────────────────│                            │
  │                                        │                            │
  │ build UserOperation (signature = 0x)   │                            │
  │ userOpHash = keccak(...)               │                            │
  │                                        │                            │
  │ POST /v1/auth/challenge                │                            │
  │───────────────────────────────────────>│                            │
  │<──────────────────── intentChallenge    │                            │
  │                                        │                            │
  │ navigator.credentials.get()            │                            │
  │  (assertion over intentChallenge)      │                            │
  │                                        │                            │
  │ [ device-local ] frame -> liveness ->  │                            │
  │ embedding -> normalize -> x 2^18       │                            │
  │ encrypt as `low`  ── plaintext dropped │                            │
  │                                        │                            │
  │ POST /v1/auth/verify {assertion, ct}   │                            │
  │───────────────────────────────────────>│ consume challenge FIRST     │
  │                                        │ verify assertion            │
  │                                        │────────POST /v1/fhe/evaluate>│
  │                                        │                            │ Enc_t · Enc_q
  │                                        │                            │ (3-term product)
  │                                        │<── product ciphertext ──────│
  │                                        │                            │
  │                                        │ partial decrypt (share 1+2)  │
  │                                        │ recombine 3 shares           │
  │                                        │ similarity -> zone          │
  │                                        │                            │
  │                                        │ sign authorization (§6)     │
  │<──── { authorization, envelopeHash,    │                            │
  │         decision.zone }                │                            │
  │                                        │                            │
  │ pack 0x48 envelope (§7.1)              │                            │
  │ → userOp.signature                     │                            │
  │ submit to bundler / EntryPoint         │                            │
```

Failure states are explicit and never silently degrade:

| Condition | HTTP | Code |
|---|---|---|
| passkey assertion rejected | 401 | specific WebAuthn code |
| biometric below threshold | 403 | `biometric_mismatch` |
| inside the noise band | 422 | `indeterminate` |
| challenge replay | 409 | `session_not_replayable` |
| no enrolled template | 409 | `template_required` |
| wrong FHE key version | 409 | `fhe_key_mismatch` |
| wrong chain / operation | 400 | `chain_mismatch`, `operation_mismatch` |
| dimension mismatch | 400 | `dimension_mismatch` |

There is **no path that falls back to passkey-only**, and none that falls back to
a weaker similarity metric.

---

## 10. Session keys

Created only through the full §9 flow, then scoped:

```
sessionKeyHash = keccak("HOMOBIO/SESSION-V1" ‖
    address sessionKey ‖ address wallet ‖ u64 chainId ‖ u64 validUntil ‖
    u256 maxValuePerTxWei ‖ u32 nonceDomain ‖
    keccak(‖ allowedTargets) ‖ keccak(‖ allowedSelectors))
```

`allowedTargets` is normalised to lowercase and `allowedSelectors` to 4-byte
values; the SDK sorts both before hashing so client and contract agree on one
byte string.

Every session operation checks expiry, that `scopeHash` matches the live grant,
and that the specific call's selector and value are in scope, and accumulates
spend in the registry.

---

## 11. Recovery

Recovery is a delay-gated state machine, never an immediate takeover:

1. `initiateRecovery(newPasskeyHash, delay)` — `RecoveryRegistry` records the
   request with `executableAt = now + delay` and the account refuses operations
   while a recovery is pending.
2. During the delay, any party may `cancelRecovery`, including the wallet owner.
3. `finalizeRecovery` reverts with `RecoveryDelayNotElapsed` before
   `executableAt`.

---

## 12. Conformance vectors

`cryptography/vectors/protocol.json` is generated by `npm run vectors` and
asserted by the test suite. It pins the authorization hash, session-key hash,
`userOpHash`, result commitment and envelope layout against fixed inputs, so a
change to any encoding in this document fails CI.

Regenerate with:

```
npm run vectors     # rewrites cryptography/vectors/protocol.json
npm run bench       # rewrites docs/benchmarks/fhe-parameters.json
```

If `npm run bench` reports a maximum error approaching 2⁻⁹, the documented bound
in §5.4 is no longer conservative and the parameters must be re-justified before
the vectors are regenerated.