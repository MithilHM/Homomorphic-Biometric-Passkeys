# Threat Model

Scope: the homomorphic biometric passkey wallet as implemented in this
repository. Every row states what is implemented, what is measured, and what is
still open. "Implemented" means there is a test that fails if it regresses.

## 0. Assets

| Asset | Why it matters |
|---|---|
| Passkey private key | Never leaves the authenticator. Nothing in this repo can read it. |
| Biometric template | Compromise enables impersonation at a distance. Stored encrypted. |
| Live capture | Exfiltrating it would let an attacker replay. Never persisted, never transmitted in plaintext. |
| FHE secret key | Whoever holds it can decrypt every stored template. Split across three holders. |
| Attestation signing key | Whoever holds it can mint authorizations. Held by the proof service only. |
| Smart-account authority | Funds. Governed by passkey + policy, with a timelocked recovery. |

## 1. Threats and mitigations

### T-1 Database breach
**Risk:** encrypted templates are exfiltrated and later decrypted.
**Mitigated:** ciphertext only at rest; secret split 3-of-3; `commitment`
verified before every evaluation; the coprocessor cannot decrypt what it stores.
**Residual:** a full compromise of the quorum decrypts everything. Rotating the
FHE key invalidates every stored template (implemented: `fheKeyVersion` is
pinned on-chain and in every challenge).

### T-2 Malicious FHE coprocessor
**Risk:** the worker returns a forged decision.
**Mitigated:** the coprocessor returns a **ciphertext**, never a boolean. The
decision is produced by recombination in a different process. It also holds only
one share, so it cannot complete a decryption by itself — verified by
`packages/fhe/test/engine.test.ts` ("requires every committee share") and by
`apps/demo` ("one share reveals nothing").

### T-3 Malicious threshold committee
**Risk:** a member biases or blocks a decision.
**Implemented:** all three shares are required; a partial set is uniformly
random (tested).
**Open (T-9):** partial decryptions are **not** MAC-checked. A single member can
corrupt one decision. Fix: SPDZ-style authenticated shares, or OpenFHE threshold
CKKS with MAC verification.

### T-4 Replayed authentication
**Risk:** reusing a valid authorization.
**Implemented:** challenges are single-use and consumed *before* any evaluation;
`sessionId`s are one-time on-chain; the gateway keeps a consumed-authorization
set; the account re-checks `consumed(sessionId)`.
**Tests:** integration "rejects a replayed challenge", "refuses to submit the same
authorization twice"; demo E.

### T-5 Tampered transaction
**Risk:** a valid authorization is moved to a different transaction.
**Implemented:** the passkey signs an intent hash that contains `userOpHash`;
the authorization hash contains `userOpHash`; the gateway compares the submitted
hash to the authorization; the account re-derives the hash from the struct and
compares to the signed digest.
**Tests:** integration "rejects an assertion that signs a different operation";
demo D.

### T-6 Phishing
**Risk:** a look-alike origin captures a passkey signature.
**Implemented:** the RP ID is hashed into `authenticatorData` and verified; the
origin is compared to an exact allow-list; attestation requests `attestation:
"none"` to avoid metadata correlation. The signature is useless on another origin
because the challenge is origin-bound.
**Residual:** a compromised or coerced browser remains in scope.

### T-7 Compromised frontend
**Risk:** malicious JS captures frames or embeddings before encryption.
**Mitigated:** no third-party runtime dependency in the shipped bundle (the whole
client is our TypeScript); zero plaintext logging enforced by the redaction list
in `packages/http-kit`; the gateway serves a deny-ish `Content-Security-Policy`
(`default-src 'self'`, no `unsafe-inline`, no `unsafe-eval`) on every response
including the static bundle mount — see `defaultContentSecurityPolicy()` in
`packages/http-kit` and `packages/http-kit/test/csp.test.ts`.
**Open:** no Subresource Integrity is possible for our own bundle; reproducible
builds and a native client path are the mitigations listed in the PRD.

### T-8 Presentation attack (photo / video / deepfake)
**Risk:** a spoof is used to authenticate.
**Implemented:** randomised active liveness (turn left/right, blink twice, move
closer) that a still image cannot satisfy; multi-face rejection; explicit quality
gates on exposure, sharpness, size and centring.
**Tests:** `packages/biometric-client/test/pipeline.test.ts` — a still image fails
the motion challenge, a real trajectory passes, two blinks are counted.
**Open (T-14):** passive liveness, depth and sensor attestation are not
implemented. The product says so in the UI rather than implying otherwise.

### T-9 Stolen device
**Risk:** the attacker has an unlocked device.
**Implemented:** passkey user verification is mandatory at registration and at
assertion; attempt lockout after N failures; session-key expiry; recovery delay.
**Open:** device binding beyond the passkey is not implemented.

### T-10 Malicious recovery
**Risk:** takeover through the recovery path.
**Implemented:** the contract enforces a 48 h floor regardless of the request;
the account refuses to validate operations while a request is pending, so
recovery can only **lock**, never spend; the owner can cancel; only the owner
replaces the passkey.
**Tests:** integration "starts a timelocked request and can be cancelled"; demo F.

### T-11 Chosen-ciphertext probing
**Risk:** an attacker submits chosen ciphertexts to extract information from the
approximate encryption.
**Implemented:** the coprocessor's evaluate endpoint is only reachable through
`/v1/auth/verify`, which requires a live single-use challenge bound to a wallet
with an enrolled template; rate limits on challenge/verify/passkey/submit;
dimension and commitment checks; ciphertext length and format validation.
**Residual (stated in `docs/crypto-parameters.md`):** approximate encryption has
documented side channels. Query authorisation and rate limits reduce the surface;
they do not eliminate it.

### T-12 Oracle: binary search on the threshold
**Risk:** repeated queries to binary-search a stored template.
**Implemented:** no API accepts `(templateId, ciphertext)` directly; every
evaluation is tied to a fresh challenge and consumes it; `indeterminate` results
give no signal and require a fresh capture; attempt lockout after N mismatches.

### T-13 Malicious dApp
**Risk:** a dApp displays a fraudulent transaction.
**Implemented:** the user approves an intent string the gateway composes, not one
the dApp supplies; the authorization is bound to the exact `userOpHash`; the
envelope the account decodes contains both factors together.
**Open:** transaction decoding/simulation for human-readable calldata is not
implemented.

### T-14 Relayer compromise
**Risk:** the relayer censors or reorders operations.
**Implemented:** the relayer holds no spend key. It can only forward operations
the account already authorized; users can submit directly to any bundler.

### T-15 Key compromise of the attestation signer
**Risk:** the proof service key is stolen and authorizations are minted.
**Implemented:** authorization lifetime is capped by
`maxAuthorizationLifetime` in the contract, independently of what is signed;
verifier keys are versioned and rotated through governance; a stolen key still
needs a live challenge to be useful at the gateway.
**Open:** the contract does not enforce a per-account authorization budget.

### T-16 Fabricated model version
**Risk:** a weaker embedding model is substituted to lower the effective
threshold.
**Implemented:** the gateway refuses a `modelVersion` it is not configured for;
the `decisionProgramHash` and `templateVersion` are pinned on-chain; a model
change requires a contract change and a migration (PRD section 39).

## 2. What an attacker can still do

Stated plainly, because a threat model that claims completeness is not one:

1. **Phish a user on a look-alike origin** if they ignore browser warnings. The
   passkey is origin-bound, so a signature obtained elsewhere is useless.
2. **Present a good deepfake** to the active liveness module. Mitigation is
   specified (PRD 8.3) and not implemented.
3. **Win a single decision** by corrupting one committee share (T-9).
4. **Differentiate the threshold** with many attempts against one account. Rate
   limits and lockout slow this; they do not make it impossible.
5. **Observe metadata**: which wallet authenticated, when, how long it took, and
   ciphertext sizes. FHE does not hide metadata and we do not claim it does.
   Concretely observable (O9, accepted and disclosed): wallet addresses and
   credential/template identifiers in API payloads; timestamps, durations,
   challenge status, outcome and reason retained in operator logs
   (`GET /v1/operator/sessions`, which also emits a disclosure log line on
   every view); request timing; and ciphertext byte sizes on the wire and in
   the coprocessor store. None of these carry plaintext biometric content,
   and the redaction list keeps it that way — but an observer can always tell
   *who* authenticated, *when*, for *how long*, and *how large* the
   ciphertexts were.

## 3. Security events

`BIOMETRIC_ENROLLMENT_CREATED`, `BIOMETRIC_ENROLLMENT_REPLACED`,
`BIOMETRIC_TEMPLATE_DELETED`,
`BIOMETRIC_AUTH_SUCCESS`, `BIOMETRIC_AUTH_FAILURE`, `LIVENESS_FAILURE`,
`WEBAUTHN_FAILURE`, `PROOF_FAILURE`, `REPLAY_DETECTED`, `USEROP_REJECTED`,
`RECOVERY_STARTED`, `RECOVERY_CANCELLED`, `RECOVERY_COMPLETED`,
`CREDENTIAL_ADDED`, `CREDENTIAL_REMOVED`, `SESSION_KEY_CREATED`,
`SESSION_KEY_REVOKED`, `POLICY_CHANGED`.

Every one carries hashes, identifiers, versions and durations. The logger's
redaction list (`embedding`, `image`, `pixels`, `secretKey`, `privateKey`,
`distance`, `similarity`, `template`, `authorizationHeader`, `cookie`) is
enforced centrally rather than trusted to call sites, and the operator-session
view is asserted to contain no field whose name suggests biometric material.

## 4. Production readiness gate (PRD section 64)

| # | Gate | Status |
|---|---|---|
| 1 | FHE parameters documented with a security justification | **Done** (`docs/crypto-parameters.md`) |
| 2 | Biometric threshold measured FAR/FRR | **Open** — thresholds are provisional; synthetic vectors only |
| 3 | Liveness adversarially tested | **Open** — active only, no adversarial dataset |
| 4 | Browser supply-chain reviewed | **Partial** — no third-party runtime deps; CSP configured for the gateway static mount (http-kit default policy, no `unsafe-inline`); bundle reproducibility and release signing still open |
| 5 | Recovery audited | **Open** — implemented, not audited |
| 6 | Contracts independently reviewed | **Open** |
| 7 | Proof verification independently tested | **Partial** — property tests in-repo |
| 8 | Key management threat-modelled | **Done** |
| 9 | Template deletion semantics verified | **Done** — `DELETE /v1/wallet/:address/template` erases every coprocessor record for the wallet; proven end-to-end (record gone, commitment unresolvable, evaluate fails `template_not_found`) |
| 10 | Device-loss recovery tested end to end | **Partial** — timelock tested, full recovery not exercised on-chain |
| 11 | Biometric processing assessed for deployment jurisdictions | **Open** — legal, not engineering |
