# Cryptographic Parameter Strategy

## 1. CKKS Scheme Parameters

Conforming to PRD Section 11 & Homomorphic Encryption Standard (128-bit classical security):

| Parameter | Recommended Value | Notes |
|---|---|---|
| **Ring Dimension ($N$)** | $8192$ (Hackathon / MVP) / $16384$ (Production) | Determines batch SIMD slots $N/2$ ($4096$ or $8192$ slots) |
| **Multiplicative Depth** | $5$ to $7$ | Enables difference squaring $(x_i - y_i)^2$ and logarithmic sum reduction |
| **Scaling Modulus Size** | $50$ bits | Maintains floating-point precision for 512-D embeddings |
| **Security Level** | `HEStd_128_classic` | Compliant with HomomorphicEncryption.org standard |
| **Batch Size** | $4096$ | Sufficient to pack 512-D vector in a single ciphertext |

## 2. Distance Computation & Error Bound

- Normalized Embedding: $\|x\|_2 = 1.0, \|y\|_2 = 1.0$
- Euclidean Distance Squared:
  $$D^2 = \sum_{i=1}^{512} (x_i - y_i)^2 = 2 - 2 \cdot \langle x, y \rangle$$
- Measured homomorphic noise / approximation error bound: $< 10^{-4}$
- Default Verification Threshold: $D^2 \le 0.45$ (corresponding to cosine similarity $\ge 0.775$)
