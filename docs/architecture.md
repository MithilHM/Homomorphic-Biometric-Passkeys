# System Architecture

## Overview
Homomorphic Biometric Passkeys provides privacy-preserving biometric authentication for ERC-4337 smart accounts on Monad EVM.

```
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
│    ├── Challenge Service (Replay-resistant, single-use nonces)          │
│    ├── WebAuthn Verification Service (P-256 authenticator assertions)   │
│    ├── FHE Coprocessor (OpenFHE CKKS Euclidean distance evaluation)     │
│    ├── Proof / Attestation Service (SP1 / signed decision artifacts)   │
│    └── Relayer Service (ERC-4337 Bundler to Monad EVM)                  │
└─────────────────────────────────────────────────────────────────────────┘
                                        │
                           UserOperation / proof / policy
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Monad EVM                                       │
│                                                                         │
│ EntryPoint (ERC-4337)                                                   │
│     │                                                                    │
│     ▼                                                                    │
│ BiometricSmartAccount                                                   │
│     ├── Passkey authority validation                                    │
│     ├── BiometricValidator (Attestation & distance threshold)          │
│     ├── SessionKeyModule                                                │
│     └── RecoveryModule (2-day timelocked guardian recovery)             │
└─────────────────────────────────────────────────────────────────────────┘
```

## Security Separation of Duties
- **WebAuthn Passkey**: Provides cryptographic authority and intent binding.
- **Biometric Processing**: Provides a privacy-preserving authorization factor.
- **FHE Coprocessor**: Evaluates distance without learning the biometric template.
