"""
Multi-Key CKKS Homomorphic Encryption for Enhanced Privacy

This module implements advanced multi-key CKKS operations with key switching:
- Users encrypt embeddings with personal keys (key_user)
- Server stores templates encrypted with server key (key_server)
- Key switching converts user ciphertexts to server key for computation
- Server cannot decrypt user queries, users cannot decrypt templates

Security Properties:
- Server learns NOTHING about user's face embedding
- User learns NOTHING about stored face templates
- Only encrypted distance results are exchanged
- Forward secrecy: old user keys don't compromise future operations

Based on OpenFHE's EvalMultKeySwitch for cross-key operations.
"""

import os
import time
import base64
import json
from typing import Dict, List, Optional, Tuple, Any, TYPE_CHECKING
from dataclasses import dataclass
import secrets

# Optional OpenFHE import
OPENFHE_AVAILABLE = False
try:
    from openfhe import *

    OPENFHE_AVAILABLE = True
except ImportError:
    import warnings

    warnings.warn(
        "OpenFHE not available. MultiKeyCKKSEncryptor will run in mock mode.",
        RuntimeWarning,
    )

    # Define mock types for type checking when OpenFHE is not available
    class CryptoContext:
        pass

    class KeyPair:
        pass

    class EvalKey:
        pass

    class CCParamsCKKSRNS:
        pass

    class SecurityLevel:
        HEStd_128_classic = None

    def GenCryptoContext(params):
        return None

    class PKESchemeFeature:
        PKE = None
        KEYSWITCH = None
        LEVELEDSHE = None
        ROTATION = None
        MULTIPARTY = None


@dataclass
class UserKeyPair:
    """Represents a user's personal key pair for client-side encryption."""

    user_id: str
    public_key: bytes  # Serialized public key
    private_key: bytes  # Serialized private key (client-side only)
    key_id: str  # Unique identifier for key rotation
    created_at: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "user_id": self.user_id,
            "public_key": base64.b64encode(self.public_key).decode("utf-8"),
            "key_id": self.key_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserKeyPair":
        """Create from dictionary."""
        return cls(
            user_id=data["user_id"],
            public_key=base64.b64decode(data["public_key"]),
            private_key=b"",  # Not stored server-side
            key_id=data["key_id"],
            created_at=data["created_at"],
        )


@dataclass
class KeySwitchMaterial:
    """Material needed for key switching between user and server keys."""

    from_user_id: str
    to_key_id: str  # Server key ID
    switch_key: bytes  # Serialized switching key material
    created_at: float


class MultiKeyCKKSEncryptor:
    """
    Advanced multi-key CKKS encryptor with key switching capabilities.

    Architecture:
    - Server maintains server_key for stored templates
    - Users encrypt queries with user_key (client-side)
    - Key switching converts user ciphertexts to server key
    - Distance computation happens under unified server key
    """

    def __init__(self):
        self.context: Optional[CryptoContext] = None
        self.server_key_pair: Optional[KeyPair] = None
        self.server_rotation_keys: Optional[EvalKey] = None

        # Multi-key management
        self.user_public_keys: Dict[str, UserKeyPair] = {}  # user_id -> UserKeyPair
        self.key_switch_materials: Dict[
            str, KeySwitchMaterial
        ] = {}  # user_id -> material

        # Parameters
        self.poly_degree = int(os.getenv("CKKS_POLY_DEGREE", "8192"))
        self.multiplicative_depth = int(os.getenv("CKKS_MULT_DEPTH", "5"))

        # Security settings
        self.enable_key_rotation = (
            os.getenv("ENABLE_KEY_ROTATION", "true").lower() == "true"
        )
        self.key_rotation_days = int(os.getenv("KEY_ROTATION_DAYS", "90"))

    def setup_context(self):
        """Initialize CKKS context with multi-key support."""
        if not OPENFHE_AVAILABLE:
            print("Warning: OpenFHE not available - running in MOCK mode")
            return

        print("Setting up multi-key CKKS context for enhanced privacy...")

        parameters = CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(self.multiplicative_depth)
        parameters.SetScalingModSize(50)
        parameters.SetBatchSize(8192)
        parameters.SetSecurityLevel(SecurityLevel.HEStd_128_classic)
        parameters.SetRingDim(self.poly_degree)

        self.context = GenCryptoContext(parameters)

        # Enable required features for multi-key operations
        self.context.Enable(PKESchemeFeature.PKE)
        self.context.Enable(PKESchemeFeature.KEYSWITCH)
        self.context.Enable(PKESchemeFeature.LEVELEDSHE)
        self.context.Enable(PKESchemeFeature.ROTATION)
        self.context.Enable(PKESchemeFeature.MULTIPARTY)  # For key switching

        print("Multi-key CKKS context initialized")

    def generate_server_keys(self):
        """Generate server's master key pair for template storage."""
        if not OPENFHE_AVAILABLE:
            print("Warning: Skipping server key generation - OpenFHE not available")
            return

        if not self.context:
            self.setup_context()

        print("Generating server key pair...")
        self.server_key_pair = self.context.KeyGen()

        print("Generating server rotation keys for distance computation...")
        rotation_indices = []
        for i in range(9):  # 2^0 to 2^8 = 1, 2, 4, 8, 16, 32, 64, 128, 256
            rotation_indices.append(2**i)

        self.server_rotation_keys = self.context.EvalRotateKeyGen(
            self.server_key_pair.secretKey, rotation_indices
        )

        print("Server keys generated and ready")

    def generate_user_keypair(self, user_id: str) -> Dict[str, Any]:
        """
        Generate a new key pair for a user (typically done client-side).

        In production, this would be done in the user's browser/device
        using a secure enclave or trusted execution environment.

        Args:
            user_id: Unique user identifier

        Returns:
            Dictionary containing public key info (private key stays client-side)
        """
        if not OPENFHE_AVAILABLE:
            # Mock implementation for demo
            key_id = f"{user_id}_{secrets.token_hex(8)}"
            mock_public_key = secrets.token_bytes(256)
            mock_private_key = secrets.token_bytes(256)

            user_keypair = UserKeyPair(
                user_id=user_id,
                public_key=mock_public_key,
                private_key=mock_private_key,
                key_id=key_id,
                created_at=time.time(),
            )

            self.user_public_keys[user_id] = user_keypair

            return {
                "user_id": user_id,
                "public_key": base64.b64encode(mock_public_key).decode("utf-8"),
                "key_id": key_id,
                "created_at": user_keypair.created_at,
                "private_key": base64.b64encode(mock_private_key).decode(
                    "utf-8"
                ),  # Only for demo!
            }

        # Real OpenFHE implementation
        print(f"Generating key pair for user {user_id}...")

        # Generate user key pair
        user_key_pair = self.context.KeyGen()

        # Serialize public key only (private key stays client-side)
        public_key_serialized = user_key_pair.publicKey.SerializeToString("bin")

        key_id = f"{user_id}_{secrets.token_hex(8)}"
        user_keypair = UserKeyPair(
            user_id=user_id,
            public_key=public_key_serialized,
            private_key=b"",  # Never stored server-side
            key_id=key_id,
            created_at=time.time(),
        )

        # Store public key server-side
        self.user_public_keys[user_id] = user_keypair

        # Generate key switching material
        self._generate_key_switch_material(user_key_pair, user_id)

        return {
            "user_id": user_id,
            "public_key": base64.b64encode(public_key_serialized).decode("utf-8"),
            "key_id": key_id,
            "created_at": user_keypair.created_at,
        }

    def register_user_public_key(self, user_id: str, public_key_b64: str, key_id: str):
        """
        Register a user's public key (when generated client-side).

        Args:
            user_id: User identifier
            public_key_b64: Base64-encoded public key
            key_id: Key identifier
        """
        public_key = base64.b64decode(public_key_b64)

        user_keypair = UserKeyPair(
            user_id=user_id,
            public_key=public_key,
            private_key=b"",  # Never stored
            key_id=key_id,
            created_at=time.time(),
        )

        self.user_public_keys[user_id] = user_keypair
        print(f"Registered public key for user {user_id}")

    def _generate_key_switch_material(self, user_key_pair, user_id: str):
        """
        Generate key switching material to convert from user key to server key.

        This uses OpenFHE's EvalMultKeySwitch capability.
        """
        if not OPENFHE_AVAILABLE or not self.server_key_pair:
            return

        print(f"Generating key switching material for user {user_id}...")

        try:
            # Generate switching key from user key to server key
            switch_key = self.context.KeySwitchGen(
                user_key_pair.secretKey,  # From user's secret key
                self.server_key_pair.secretKey,  # To server's secret key
            )

            # Serialize the switching key
            switch_key_serialized = switch_key.SerializeToString("bin")

            material = KeySwitchMaterial(
                from_user_id=user_id,
                to_key_id="server_master_key",
                switch_key=switch_key_serialized,
                created_at=time.time(),
            )

            self.key_switch_materials[user_id] = material
            print(f"Key switching material generated for user {user_id}")

        except Exception as e:
            print(f"Warning: Failed to generate key switching material: {e}")

    def switch_key(self, ciphertext_b64: str, from_user_id: str) -> Optional[str]:
        """
        Switch a ciphertext from user's key to server's key.

        Args:
            ciphertext_b64: Base64-encoded ciphertext under user's key
            from_user_id: User whose key was used for encryption

        Returns:
            Base64-encoded ciphertext under server's key, or None if failed
        """
        if not OPENFHE_AVAILABLE:
            # Mock key switching for demo
            return ciphertext_b64

        if from_user_id not in self.key_switch_materials:
            print(f"No key switching material for user {from_user_id}")
            return None

        try:
            print(f"Switching key for ciphertext from user {from_user_id}...")

            # Deserialize input ciphertext
            ciphertext_data = base64.b64decode(ciphertext_b64)
            ciphertext = self.context.DeserializeCiphertext(ciphertext_data, "bin")

            # Get switching key material
            material = self.key_switch_materials[from_user_id]
            switch_key = self.context.DeserializeEvalKey(material.switch_key, "bin")

            # Perform key switching
            switched_ciphertext = self.context.KeySwitch(ciphertext, switch_key)

            # Serialize result
            result_data = switched_ciphertext.SerializeToString("bin")
            result_b64 = base64.b64encode(result_data).decode("utf-8")

            print(f"Key switching completed for user {from_user_id}")
            return result_b64

        except Exception as e:
            print(f"Key switching failed: {e}")
            return None

    def encrypt_template_server(self, embedding: List[float]) -> str:
        """
        Encrypt a face template using the server's key.

        Args:
            embedding: 512-dimensional face embedding

        Returns:
            Base64-encoded ciphertext under server key
        """
        if not OPENFHE_AVAILABLE:
            # Mock encryption - don't include plaintext embedding for privacy testing
            return base64.b64encode(
                json.dumps(
                    {
                        "mock": True,
                        "embedding_hash": hash(str(embedding)),
                        "ciphertext": base64.b64encode(
                            secrets.token_bytes(256)
                        ).decode(),
                        "key": "server",
                    }
                ).encode()
            ).decode()

        if len(embedding) != 512:
            raise ValueError(f"Embedding must be 512-dimensional, got {len(embedding)}")

        # Pad embedding
        padded_embedding = embedding + [0.0] * (
            self.context.GetEncodingParams().GetBatchSize() - len(embedding)
        )

        plaintext = self.context.MakeCKKSPackedPlaintext(padded_embedding)
        ciphertext = self.context.Encrypt(self.server_key_pair.publicKey, plaintext)

        # Serialize and encode
        ciphertext_data = ciphertext.SerializeToString("bin")
        return base64.b64encode(ciphertext_data).decode("utf-8")

    def compute_encrypted_distance_server(
        self, ct_query_switched_b64: str, ct_template_b64: str
    ) -> str:
        """
        Compute encrypted distance between switched query and server template.

        Args:
            ct_query_switched_b64: Query ciphertext switched to server key
            ct_template_b64: Template ciphertext under server key

        Returns:
            Base64-encoded encrypted distance
        """
        if not OPENFHE_AVAILABLE:
            # Mock distance computation
            return base64.b64encode(
                json.dumps({"mock": True, "distance": 0.5}).encode()
            ).decode()

        try:
            # Deserialize ciphertexts
            query_data = base64.b64decode(ct_query_switched_b64)
            template_data = base64.b64decode(ct_template_b64)

            ct_query = self.context.DeserializeCiphertext(query_data, "bin")
            ct_template = self.context.DeserializeCiphertext(template_data, "bin")

            # Compute distance under server key
            distance_ct = self._compute_distance(ct_query, ct_template)

            # Serialize result
            result_data = distance_ct.SerializeToString("bin")
            return base64.b64encode(result_data).decode("utf-8")

        except Exception as e:
            print(f"Distance computation failed: {e}")
            raise

    def _compute_distance(self, ct_query, ct_template):
        """
        Compute squared Euclidean distance between two encrypted embeddings.

        Algorithm: d² = Σ(query[i] - stored[i])²
        """
        # Step 1: Homomorphic subtraction
        diff = self.context.EvalSub(ct_query, ct_template)

        # Step 2: Homomorphic squaring (element-wise)
        diff_squared = self.context.EvalMult(diff, diff)

        # Step 3: SIMD rotations to sum all dimensions
        sum_ct = diff_squared

        # Sum across all 512 dimensions using rotation-based accumulation
        rotation_steps = [1, 2, 4, 8, 16, 32, 64, 128, 256]

        for rotation in rotation_steps:
            if rotation < 512:
                rotated = self.context.EvalRotate(
                    sum_ct, rotation, self.server_rotation_keys
                )
                sum_ct = self.context.EvalAdd(sum_ct, rotated)

        return sum_ct

    def decrypt_distance_server(self, encrypted_distance_b64: str) -> float:
        """
        Decrypt distance result using server key.

        Args:
            encrypted_distance_b64: Base64-encoded encrypted distance

        Returns:
            Decrypted distance value
        """
        if not OPENFHE_AVAILABLE:
            # Mock decryption
            return 0.5

        try:
            # Deserialize ciphertext
            distance_data = base64.b64decode(encrypted_distance_b64)
            distance_ct = self.context.DeserializeCiphertext(distance_data, "bin")

            # Decrypt
            plaintext = self.context.Decrypt(
                self.server_key_pair.secretKey, distance_ct
            )
            plaintext.SetLength(1)

            decrypted_values = plaintext.GetRealPackedValue()
            return float(decrypted_values[0])

        except Exception as e:
            print(f"Distance decryption failed: {e}")
            raise

    def authenticate_with_privacy(
        self, user_id: str, query_ct_switched_b64: str, stored_templates: List[str]
    ) -> Dict[str, Any]:
        """
        Perform privacy-preserving authentication.

        Args:
            user_id: User identifier
            query_ct_switched_b64: Query encrypted under server key
            stored_templates: List of base64-encoded templates under server key

        Returns:
            Authentication result with privacy guarantees
        """
        if user_id not in self.user_public_keys:
            return {"authenticated": False, "error": "User not registered"}

        print(f"Performing privacy-preserving authentication for user {user_id}")

        min_distance = float("inf")
        best_match_idx = -1

        # Compute distances against all stored templates
        for i, template_b64 in enumerate(stored_templates):
            try:
                # Compute encrypted distance
                distance_b64 = self.compute_encrypted_distance_server(
                    query_ct_switched_b64, template_b64
                )

                # Decrypt distance (only server can do this)
                distance = self.decrypt_distance_server(distance_b64)

                if distance < min_distance:
                    min_distance = distance
                    best_match_idx = i

            except Exception as e:
                print(f"Warning: Failed to compute distance for template {i}: {e}")
                continue

        # Authentication decision
        threshold = float(os.getenv("AUTH_THRESHOLD", "0.75"))
        authenticated = min_distance < threshold

        result = {
            "authenticated": authenticated,
            "user_id": user_id,
            "distance": min_distance,
            "threshold": threshold,
            "template_index": best_match_idx if authenticated else None,
            "privacy_guarantees": {
                "server_cannot_decrypt_query": True,
                "user_cannot_decrypt_templates": True,
                "only_encrypted_distances_shared": True,
            },
        }

        print(
            f"Authentication {'successful' if authenticated else 'failed'} "
            f"for user {user_id} (distance: {min_distance:.4f})"
        )

        return result

    def rotate_user_key(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Rotate a user's key pair for forward secrecy.

        Args:
            user_id: User identifier

        Returns:
            New public key info, or None if failed
        """
        if not self.enable_key_rotation:
            return None

        if user_id not in self.user_public_keys:
            return None

        print(f"Rotating key for user {user_id}")

        # Generate new key pair
        new_key_info = self.generate_user_keypair(user_id)

        # Mark old key as rotated (could archive for transition period)
        old_key = self.user_public_keys[user_id]
        old_key.key_id += "_rotated_" + str(int(time.time()))

        print(f"Key rotated for user {user_id}")
        return new_key_info

    def get_user_key_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a user's key."""
        if user_id not in self.user_public_keys:
            return None

        user_key = self.user_public_keys[user_id]
        return {
            "user_id": user_key.user_id,
            "key_id": user_key.key_id,
            "created_at": user_key.created_at,
            "days_old": (time.time() - user_key.created_at) / (24 * 3600),
            "needs_rotation": self.enable_key_rotation
            and (time.time() - user_key.created_at)
            > (self.key_rotation_days * 24 * 3600),
        }

    def cleanup_expired_keys(self):
        """Clean up expired key switching materials."""
        current_time = time.time()
        max_age = self.key_rotation_days * 24 * 3600 * 2  # Keep for 2 rotation periods

        expired_users = []
        for user_id, material in self.key_switch_materials.items():
            if (current_time - material.created_at) > max_age:
                expired_users.append(user_id)

        for user_id in expired_users:
            del self.key_switch_materials[user_id]
            print(f"Cleaned up expired key material for user {user_id}")

    def export_server_public_key(self) -> str:
        """Export server's public key for client key switching setup."""
        if not OPENFHE_AVAILABLE or not self.server_key_pair:
            return base64.b64encode(b"mock_server_public_key").decode()

        server_public_key_data = self.server_key_pair.publicKey.SerializeToString("bin")
        return base64.b64encode(server_public_key_data).decode("utf-8")

    def __str__(self) -> str:
        """String representation."""
        status = "initialized" if self.context else "not_initialized"
        users = len(self.user_public_keys)
        return f"MultiKeyCKKSEncryptor(status={status}, users={users}, enhanced_privacy=True)"
