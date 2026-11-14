"""Field-level encryption for government identifiers (AES-GCM, key from KMS)."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_field(value: str) -> bytes:
    key = bytes.fromhex(os.environ["FIELD_KEY_HEX"])  # injected from AWS Secrets Manager
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, value.encode(), None)
