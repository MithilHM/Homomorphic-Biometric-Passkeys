# Protocol Specification

## 1. Challenge Derivation
The server issues an ephemeral single-use challenge:
```json
{
  "challengeId": "uuid",
  "wallet": "0x...",
  "chainId": 143,
  "operationHash": "0x...",
  "nonce": "random-256-bit-value",
  "issuedAt": 1791370000,
  "expiresAt": 1791370060,
  "biometricPolicyVersion": 1,
  "fheKeyVersion": 1,
  "webauthnRpId": "app.homobio.io"
}
```

## 2. Intent Commitment
The client derives the WebAuthn challenge payload:
$$\text{IntentCommitment} = \text{SHA256}(\text{chainId} : \text{wallet} : \text{userOpHash} : \text{nonce} : \text{sessionId} : \text{policyVersion} : \text{expiration})$$

## 3. Homomorphic Biometric Query
- Client captures camera frame in browser memory only.
- Computes 512-D FaceNet embedding and normalizes $\|e\|_2 = 1.0$.
- Encrypts embedding under OpenFHE CKKS public key $pk$.
- Deletes plaintext embedding and raw frame from memory.
- Submits ciphertext payload $\text{Enc}(e)$ to API Gateway.

## 4. Attestation & Execution
- Coprocessor computes encrypted distance without decrypting vector.
- Coprocessor issues signed decision attestation.
- Smart account (`BiometricSmartAccount.sol`) validates WebAuthn signature + Biometric attestation and executes transaction.
