"""Fully Homomorphic Encryption operations using OpenFHE."""

import os
from openfhe import *


class FHEManager:
    """Manages FHE encryption and decryption operations."""

    def __init__(self):
        self.context = None
        self.key_pair = None
        self.poly_degree = int(os.getenv("CKKS_POLY_DEGREE", "8192"))

    def setup_context(self):
        """Initialize FHE context with CKKS scheme."""
        parameters = CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(1)
        parameters.SetScalingModSize(50)
        parameters.SetBatchSize(8)
        parameters.SetSecurityLevel(SecurityLevel.HEStd_128_classic)
        parameters.SetRingDim(self.poly_degree)

        self.context = GenCryptoContext(parameters)
        self.context.Enable(PKESchemeFeature.PKE)
        self.context.Enable(PKESchemeFeature.KEYSWITCH)
        self.context.Enable(PKESchemeFeature.LEVELEDSHE)

    def generate_keys(self):
        """Generate public and private keys."""
        if not self.context:
            self.setup_context()
        self.key_pair = self.context.KeyGen()

    def encrypt_vector(self, data: list[float]) -> str:
        """Encrypt a vector of floats."""
        if not self.key_pair:
            self.generate_keys()
        plaintext = self.context.MakeCKKSPackedPlaintext(data)
        ciphertext = self.context.Encrypt(self.key_pair.publicKey, plaintext)
        # Return serialized ciphertext (placeholder)
        return str(ciphertext)

    def decrypt_vector(self, encrypted_data: str) -> list[float]:
        """Decrypt a vector of floats."""
        if not self.key_pair:
            raise ValueError("Keys not generated")
        # Deserialize and decrypt (placeholder implementation)
        ciphertext = None  # Deserialize from encrypted_data
        plaintext = self.context.Decrypt(self.key_pair.secretKey, ciphertext)
        plaintext.SetLength(len(plaintext))
        return plaintext.GetRealPackedValue()
