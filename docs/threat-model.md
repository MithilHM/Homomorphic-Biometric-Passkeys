# Threat Model & Mitigation Strategy

## 1. Threats Considered

### T1: Compromised Backend Server
- **Threat**: Attacker steals server database.
- **Mitigation**: Database contains only encrypted CKKS ciphertexts and credential IDs. Plaintext embeddings and raw face images never leave the client device.

### T2: Presentation Attacks (Spoofing)
- **Threat**: Attacker presents a photograph or pre-recorded video to the camera.
- **Mitigation**: Active randomized liveness detection challenge (head rotation, blinking, eye tracking).

### T3: Replay Attacks
- **Threat**: Attacker intercepts valid ciphertext or WebAuthn assertion and resubmits it for another transaction.
- **Mitigation**: Replay-resistant single-use challenge binding:
  `Hash(chainId + wallet + userOpHash + nonce + sessionId + policyVersion + expiration)`.
  Challenges are consumed immediately upon verification.

### T4: Transaction Tampering
- **Threat**: Attacker alters recipient or amount after biometric authentication.
- **Mitigation**: WebAuthn signature explicitly commits to the `UserOperation` hash. Any alteration invalidates the cryptographic assertion.

### T5: Device Loss
- **Threat**: User loses device holding the passkey.
- **Mitigation**: Timelocked multi-guardian Recovery Module (`RecoveryModule.sol`) allows account state recovery without instant takeover.
