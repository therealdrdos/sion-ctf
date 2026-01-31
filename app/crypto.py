"""Encryption utilities for sensitive data storage."""

import base64
import hashlib

from cryptography.fernet import Fernet

from app.config import settings


def _get_fernet_key() -> bytes:
    """Derive a Fernet-compatible key from the secret_key."""
    # Use SHA256 to get a 32-byte key, then base64 encode for Fernet
    key_bytes = hashlib.sha256(settings.secret_key.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _get_fernet() -> Fernet:
    """Get a Fernet instance for encryption/decryption."""
    return Fernet(_get_fernet_key())


def encrypt_api_key(api_key: str) -> str:
    """Encrypt an API key for storage."""
    fernet = _get_fernet()
    encrypted = fernet.encrypt(api_key.encode())
    return encrypted.decode()


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt an API key from storage."""
    fernet = _get_fernet()
    decrypted = fernet.decrypt(encrypted_key.encode())
    return decrypted.decode()


def mask_api_key(api_key: str) -> str:
    """Mask an API key for display (e.g., 'sk-...xxxx')."""
    if len(api_key) <= 8:
        return "***"
    return f"{api_key[:3]}...{api_key[-4:]}"
