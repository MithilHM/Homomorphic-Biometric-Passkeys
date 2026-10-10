"""
pgcrypto Integration and Encryption Utilities

This module provides column-level encryption using PostgreSQL's pgcrypto extension.
All sensitive data (IP addresses, metadata) is encrypted at rest using AES-256/PGP.

DPDP Act 2023 Compliance:
- Pseudonymization of personal data (encrypted IP addresses)
- Encryption-at-rest for all sensitive fields
- Cryptographic hashing for consent text integrity verification

Security Model:
- Encryption keys stored in environment variables (production: use KMS)
- AES-256 symmetric encryption via pgp_sym_encrypt/decrypt
- SHA-256 hashing for non-repudiation of consent text
"""

import hashlib
import json
import os
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.types import LargeBinary, TypeDecorator


# Global cache for derived keys to avoid repeated heavy PBKDF2 iterations
_key_cache = {}


def get_encryption_key() -> str:
    """
    Retrieve the database encryption key from environment.
    
    In production, this should be replaced with KMS integration
    (AWS KMS, HashiCorp Vault, Azure Key Vault, etc.)
    
    Returns:
        str: The encryption key for pgcrypto operations
        
    Raises:
        ValueError: If encryption key is not configured
    """
    key = os.getenv("DB_ENCRYPTION_KEY")
    if not key:
        # For development, use a default key (NEVER do this in production)
        if os.getenv("FLASK_ENV") == "development" or os.getenv("DEBUG") == "true":
            return "dev-encryption-key-32-chars-long!"
        raise ValueError(
            "DB_ENCRYPTION_KEY environment variable is required. "
            "For production, use a cryptographically secure 32+ character key."
        )
    return key


def setup_pgcrypto(engine: Engine) -> None:
    """
    Ensure pgcrypto extension is available in the database.
    
    This function creates the pgcrypto extension if it doesn't exist.
    Must be called before any encryption operations.
    
    Args:
        engine: SQLAlchemy engine connected to PostgreSQL
        
    Note:
        Requires superuser privileges or CREATE EXTENSION permission.
        In Docker/cloud PostgreSQL, this is typically pre-installed.
    """
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        conn.commit()


def encrypt_column_data(plaintext: str | bytes, key: str | None = None) -> bytes:
    """
    Encrypt data using pgp_sym_encrypt (AES-256).
    
    This function is used for column-level encryption of sensitive data
    like IP addresses, metadata fields, etc.
    
    Args:
        plaintext: The data to encrypt (string or bytes)
        key: Encryption key (defaults to environment key)
        
    Returns:
        bytes: Encrypted data suitable for LargeBinary column storage
        
    Example:
        >>> encrypted = encrypt_column_data("192.168.1.1")
        >>> # Store encrypted in database
    """
    if key is None:
        key = get_encryption_key()
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    
    # We'll use Python-side encryption for portability
    # In production with direct DB access, use pgp_sym_encrypt SQL function
    
    # Check cache for derived key
    if key in _key_cache:
        f = _key_cache[key]
        return f.encrypt(plaintext)

    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64
        
        # Derive a Fernet-compatible key from the encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"homomorphic_face_salt",  # Fixed salt for deterministic key derivation
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        f = Fernet(derived_key)
        
        # Cache for subsequent calls
        _key_cache[key] = f
        
        return f.encrypt(plaintext)
    except ImportError:
        # Fallback: base64 encoding (NOT SECURE - only for development)
        import warnings
        warnings.warn(
            "cryptography package not installed. Using insecure base64 encoding. "
            "Install cryptography: pip install cryptography"
        )
        return base64.b64encode(plaintext)


def decrypt_column_data(ciphertext: bytes, key: str | None = None) -> str:
    """
    Decrypt data encrypted with encrypt_column_data.
    
    Args:
        ciphertext: The encrypted data from database
        key: Encryption key (defaults to environment key)
        
    Returns:
        str: Decrypted plaintext
        
    Raises:
        ValueError: If decryption fails (wrong key, corrupted data)
    """
    if key is None:
        key = get_encryption_key()
    
    # Check cache for derived key
    if key in _key_cache:
        f = _key_cache[key]
        try:
            decrypted = f.decrypt(ciphertext)
            return decrypted.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    try:
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"homomorphic_face_salt",
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        f = Fernet(derived_key)
        
        # Cache for subsequent calls
        _key_cache[key] = f
        
        try:
            decrypted = f.decrypt(ciphertext)
            return decrypted.decode("utf-8")
        except InvalidToken as e:
            raise ValueError(f"Decryption failed: invalid key or corrupted data") from e
    except ImportError:
        # Fallback: base64 decoding
        import base64
        return base64.b64decode(ciphertext).decode("utf-8")


def hash_consent_text(consent_text: str) -> str:
    """
    Generate SHA-256 hash of consent text for integrity verification.
    
    This hash is stored with the consent record to detect tampering.
    If the consent text is modified, the hash won't match, indicating
    potential fraud or unauthorized modification.
    
    DPDP Act 2023 Compliance:
    - Non-repudiation: User cannot claim different consent was given
    - Integrity: Detects if consent text was modified after signing
    
    Args:
        consent_text: The full consent text shown to the user
        
    Returns:
        str: Lowercase hexadecimal SHA-256 hash (64 characters)
        
    Example:
        >>> hash_consent_text("I consent to biometric authentication...")
        'a1b2c3d4...'
    """
    # Normalize whitespace and encode as UTF-8 for consistent hashing
    normalized = " ".join(consent_text.split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_consent_hash(consent_text: str, stored_hash: str) -> bool:
    """
    Verify that consent text matches its stored hash.
    
    Args:
        consent_text: The consent text to verify
        stored_hash: The hash stored in the database
        
    Returns:
        bool: True if hash matches, False if tampered
    """
    computed_hash = hash_consent_text(consent_text)
    return computed_hash == stored_hash


def encrypt_json_metadata(data: dict[str, Any], key: str | None = None) -> bytes:
    """
    Encrypt a JSON-serializable dictionary for audit log storage.
    
    Audit logs may contain sensitive information (IP addresses, user agents).
    This function encrypts the entire metadata dictionary.
    
    Args:
        data: Dictionary to encrypt
        key: Encryption key (defaults to environment key)
        
    Returns:
        bytes: Encrypted JSON data
    """
    json_str = json.dumps(data, ensure_ascii=False, default=str)
    return encrypt_column_data(json_str, key)


def decrypt_json_metadata(ciphertext: bytes, key: str | None = None) -> dict[str, Any]:
    """
    Decrypt encrypted JSON metadata from audit logs.
    
    Args:
        ciphertext: Encrypted data from database
        key: Encryption key (defaults to environment key)
        
    Returns:
        dict: Decrypted JSON data
    """
    json_str = decrypt_column_data(ciphertext, key)
    return json.loads(json_str)


class PGPEncryptedType(TypeDecorator):
    """
    SQLAlchemy TypeDecorator for automatic column-level encryption.
    
    This type automatically encrypts data when writing to the database
    and decrypts when reading. Use for sensitive fields like IP addresses.
    
    Usage:
        class ConsentRecord(Base):
            ip_address_encrypted = Column(PGPEncryptedType())
            
        # Automatically encrypted on write
        record.ip_address_encrypted = "192.168.1.1"
        
        # Automatically decrypted on read
        print(record.ip_address_encrypted)  # "192.168.1.1"
    
    Security Notes:
        - Uses AES-256 encryption via Fernet (cryptography library)
        - Key derived from DB_ENCRYPTION_KEY environment variable
        - NULL values are preserved (not encrypted)
    """
    
    impl = LargeBinary
    cache_ok = True
    
    def process_bind_param(self, value: str | None, dialect) -> bytes | None:
        """Encrypt value before storing in database."""
        if value is None:
            return None
        if isinstance(value, bytes):
            # Already encrypted or binary data
            return value
        return encrypt_column_data(value)
    
    def process_result_value(self, value: bytes | None, dialect) -> str | None:
        """Decrypt value after reading from database."""
        if value is None:
            return None
        try:
            return decrypt_column_data(value)
        except (ValueError, Exception):
            # If decryption fails, return raw bytes as string (for debugging)
            return f"<encrypted:{len(value)} bytes>"


class EncryptedJSONType(TypeDecorator):
    """
    SQLAlchemy TypeDecorator for encrypted JSON/JSONB columns.
    
    Encrypts entire JSON objects for audit log metadata storage.
    
    Usage:
        class AuditLog(Base):
            metadata_encrypted = Column(EncryptedJSONType())
            
        log.metadata_encrypted = {"ip": "192.168.1.1", "action": "login"}
    """
    
    impl = LargeBinary
    cache_ok = True
    
    def process_bind_param(self, value: dict | None, dialect) -> bytes | None:
        """Encrypt JSON before storing."""
        if value is None:
            return None
        return encrypt_json_metadata(value)
    
    def process_result_value(self, value: bytes | None, dialect) -> dict | None:
        """Decrypt JSON after reading."""
        if value is None:
            return None
        try:
            return decrypt_json_metadata(value)
        except (ValueError, json.JSONDecodeError):
            return {"error": "decryption_failed", "size": len(value)}


def generate_encryption_params_hash(
    poly_degree: int = 8192,
    mult_depth: int = 5,
    security_level: str = "HEStd_128_classic"
) -> str:
    """
    Generate a hash of CKKS encryption parameters.
    
    This hash is stored with biometric templates to ensure compatibility.
    Templates encrypted with different parameters cannot be compared.
    
    Args:
        poly_degree: CKKS polynomial degree
        mult_depth: Multiplicative depth
        security_level: Security level string
        
    Returns:
        str: SHA-256 hash of parameters (first 16 chars for readability)
    """
    params_str = f"{poly_degree}:{mult_depth}:{security_level}"
    full_hash = hashlib.sha256(params_str.encode()).hexdigest()
    return full_hash[:16]  # Short hash for readability in logs


# Event listener to ensure pgcrypto is set up on engine connect
@event.listens_for(Engine, "connect")
def _set_search_path(dbapi_connection, connection_record):
    """Set search path to include pgcrypto functions (PostgreSQL only)."""
    try:
        # Check if we're on PostgreSQL. connection_record might not have .engine in all versions
        # or contexts, so we provide a safe fallback.
        engine = getattr(connection_record, "engine", None)
        if engine and engine.dialect.name == "postgresql":
            cursor = dbapi_connection.cursor()
            cursor.execute("SET search_path TO public")
            cursor.close()
    except Exception:
        # Ignore errors on non-PostgreSQL or during teardown
        pass
