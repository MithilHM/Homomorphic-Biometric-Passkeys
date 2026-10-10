# Homomorphic Biometric Passkeys

> **Privacy-preserving biometric authentication + WebAuthn Passkeys + FHE + ZK + ERC-4337 Smart Accounts on Monad EVM.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Monad](https://img.shields.io/badge/Network-Monad_EVM-8A2BE2.svg)](https://monad.xyz)
[![FHE](https://img.shields.io/badge/Cryptography-OpenFHE_CKKS-blue.svg)](https://openfhe.org)
[![ERC-4337](https://img.shields.io/badge/Standard-ERC--4337-green.svg)](https://eips.ethereum.org/EIPS/eip-4337)

---

## 💡 Executive Summary

Homomorphic Biometric Passkeys provides a **seedless, non-custodial smart wallet** where:
1. A **WebAuthn Passkey** serves as the cryptographic signing root on-device.
2. The user's camera produces a facial embedding **locally in the browser**.
3. The embedding is **encrypted via CKKS homomorphic encryption** before leaving the client.
4. A remote **FHE coprocessor** evaluates biometric similarity/distance without ever receiving or decrypting the user's plaintext facial vector.
5. A **cryptographic attestation / proof** confirms policy satisfaction.
6. An **ERC-4337 Smart Account** on **Monad EVM** verifies both the passkey authority and the biometric authorization factor to execute transactions.

> **Key Primitive**: *Passkey = cryptographic signing authority; Biometric match = privacy-preserving authorization factor.*

---

## 🏛 Architecture

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
│                         Off-chain Infrastructure                        │
│                                                                         │
│ API Gateway                                                            │
│    ├── Challenge Service (Replay-resistant, single-use nonces)          │
│    ├── WebAuthn Service (P-256 authenticator assertions)                │
│    ├── FHE Coprocessor (OpenFHE CKKS Euclidean distance evaluation)     │
│    ├── Proof / Attestation Service (Decision commitments)              │
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

---

## 📂 Repository Structure

Conforms directly to Master PRD Section 51:

```text
.
├── apps/
│   ├── web/                    # Frontend dApp with viewfinder and wallet dashboard
│   ├── demo/                   # Interactive Hackathon Demo suite (Scenarios A through F)
│   └── docs/                   # Documentation portal
│
├── packages/
│   ├── biometric-client/       # Camera capture, face detector, FaceNet embedding extractor
│   ├── webauthn/               # WebAuthn passkey registration, assertion & intent binding
│   ├── protocol-types/         # Protocol TypeScript definitions (Challenge, UserOp, etc.)
│   ├── userop/                 # ERC-4337 UserOperation builder for Monad
│   ├── crypto-utils/           # Vector math, L2 normalization, CKKS parameters
│   └── sdk/                    # High-level Developer SDK (createBiometricWallet, etc.)
│
├── services/
│   ├── api-gateway/            # Microservices gateway, rate limiter, and CORS
│   ├── challenge-service/      # Single-use challenge issuance with replay protection
│   ├── fhe-service/            # OpenFHE CKKS coprocessor evaluating encrypted distance
│   ├── proof-service/          # Biometric authorization decision attestation service
│   ├── webauthn-service/       # Passkey credential verification service
│   └── relayer-service/        # ERC-4337 Bundler client for Monad
│
├── contracts/
│   ├── account/                # BiometricSmartAccount.sol (ERC-4337 smart wallet)
│   ├── factory/                # SmartAccountFactory.sol (CREATE2 deployment)
│   ├── validators/             # BiometricValidator.sol & Passkey verifiers
│   ├── modules/                # SessionKeyModule.sol & RecoveryModule.sol
│   └── paymaster/              # Gas sponsorship paymaster
│
├── cryptography/
│   ├── openfhe/                # CKKS encryptor, multi-key switching & benchmarks
│   ├── circuits/               # SP1 / ZK verification circuit schemas
│   └── vectors/                # Calibration embeddings & test vectors
│
├── infra/
│   ├── docker/                 # Service Dockerfiles & compose manifests
│   ├── k8s/                    # Kubernetes deployment configurations
│   └── terraform/              # Cloud infrastructure IaC
│
├── docs/                       # Architecture, threat model, crypto params, protocol spec
└── homomorphic_biometric_passkeys_prd (1).md # Master Product Requirements Document
```

---

## 🚀 Quickstart

### Prerequisites
- Node.js $\ge 18$
- Python $\ge 3.10$
- Docker & Docker Compose

### 1. Install Dependencies
```bash
npm install
```

### 2. Start Off-chain Services via Docker
```bash
docker compose up -d
```

### 3. Run Microservices Locally (Development)
```bash
# Start API Gateway (Port 5000)
npm run start --workspace=@homobio/api-gateway

# Start FHE Coprocessor (Port 5001)
python services/fhe-service/app.py
```

---

## 🔒 Security Principles

1. **Plaintext Minimization**: Camera frames and plaintext facial embeddings never leave client memory.
2. **Replay Resistance**: Ephemeral challenges bind `(chainId, wallet, userOpHash, nonce, sessionId, expiration)`.
3. **Intent Binding**: The passkey signature cryptographically covers the entire transaction intent.
4. **Timelocked Recovery**: Social/guardian recovery enforces a minimum 48-hour delay to prevent instant account takeover.

---

## 📜 License
MIT
