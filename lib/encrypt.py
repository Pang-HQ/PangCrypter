# lib/encrypt.py
import os, unicodedata

from typing import Optional
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
from nacl.utils import random as nacl_random
from argon2.low_level import hash_secret_raw, Type
from enum import Enum

# cryptography for HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from uuid import UUID, uuid4

class EncryptModeType(Enum):
    MODE_PASSWORD_ONLY = 0x00
    MODE_PASSWORD_PLUS_KEY = 0x01
    MODE_KEY_ONLY = 0x02

# Constants
UUID_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 24  # XChaCha20 uses 192-bit nonces


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Normalize the password and derive a fixed-length key using Argon2id.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes")

    # Normalize to avoid multiple Unicode representations of the same password.
    normalized = unicodedata.normalize("NFKC", password)
    return hash_secret_raw(
        secret=normalized.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=KEY_SIZE,
        type=Type.ID
    )


def _combine_pw_and_key_with_hkdf(pw_key: bytes, usb_key: bytes) -> bytes:
    """
    Combine a password-derived key and an external usb_key into a single symmetric key
    using HKDF-SHA256.

    Design choices:
    - Use usb_key as the HKDF 'salt' and pw_key as the IKM (input keying material).
      This treats the usb_key as a secret salt which provides strong extraction.
      Both sides will compute the same result deterministically.
    - info is a context string to namespace the derivation for future-proofing.
    """
    if not (isinstance(pw_key, (bytes, bytearray)) and isinstance(usb_key, (bytes, bytearray))):
        raise TypeError("pw_key and usb_key must be bytes")
    if len(usb_key) != KEY_SIZE:
        raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=usb_key,                    # secret salt
        info=b"PangCrypter v1 key combine"  # domain separation / versioning
    )
    return hkdf.derive(pw_key)


def encrypt_file(input_bytes: bytes, output_path: str,
                 mode: EncryptModeType,
                 uuid: UUID,
                 password: Optional[str] = None,
                 usb_key: Optional[bytes] = None) -> None:
    """
    Encrypts and writes a file, embedding a unique UUID in the header.
    """
    if not isinstance(mode, EncryptModeType):
        try:
            mode = EncryptModeType(mode)
        except ValueError:
            raise TypeError("mode must be an EncryptModeType")

    if mode == EncryptModeType.MODE_PASSWORD_ONLY:
        if not password:
            raise ValueError("Password is required for password-only mode")
        salt = nacl_random(SALT_SIZE)
        key = derive_key_from_password(password, salt)
        # header = mode + salt + uuid
        header = bytes([mode.value]) + salt + uuid.bytes

    elif mode == EncryptModeType.MODE_PASSWORD_PLUS_KEY:
        if not (password and usb_key):
            raise ValueError("Both password and key required for password+key mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")
        salt = nacl_random(SALT_SIZE)
        pw_key = derive_key_from_password(password, salt)
        key = _combine_pw_and_key_with_hkdf(pw_key, usb_key)
        header = bytes([mode.value]) + salt + uuid.bytes

    elif mode == EncryptModeType.MODE_KEY_ONLY:
        if not usb_key:
            raise ValueError("Key required for key-only mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")
        key = usb_key
        header = bytes([mode.value]) + uuid.bytes

    else:
        raise ValueError(f"Invalid mode: {mode}")

    nonce = nacl_random(NONCE_SIZE)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        input_bytes,
        header,  # Associated Data binds mode/salt/uuid to ciphertext
        nonce,
        key
    )

    with open(output_path, "wb") as f:
        f.write(header + nonce + ciphertext)


def decrypt_file(input_path: str,
                 password: Optional[str] = None,
                 usb_key: Optional[bytes] = None) -> bytes:
    """Decrypts and returns the file contents. Performs robust sanity checks first."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(input_path)

    with open(input_path, "rb") as f:
        data = f.read()

    # Basic sanity: mode(1) + nonce + tag(16) + UUID(16) + salt(if any)
    if len(data) < 1 + NONCE_SIZE + 16 + UUID_SIZE:
        raise ValueError("Input file is too short or corrupted")

    mode_byte = data[0]
    try:
        mode = EncryptModeType(mode_byte)
    except ValueError:
        raise ValueError(f"Invalid mode byte: {mode_byte}")

    # Extract UUID bytes position depends on mode:
    if mode == EncryptModeType.MODE_PASSWORD_ONLY:
        expected_min_len = 1 + SALT_SIZE + UUID_SIZE + NONCE_SIZE + 16
        if len(data) < expected_min_len:
            raise ValueError("Input file too short for password-only mode")

        salt = data[1:1+SALT_SIZE]
        file_uuid = data[1+SALT_SIZE:1+SALT_SIZE+UUID_SIZE]
        nonce = data[1+SALT_SIZE+UUID_SIZE:1+SALT_SIZE+UUID_SIZE+NONCE_SIZE]
        ciphertext = data[1+SALT_SIZE+UUID_SIZE+NONCE_SIZE:]

        if not password:
            raise ValueError("Password is required for password-only mode")

        key = derive_key_from_password(password, salt)
        # header includes mode + salt + UUID for authentication
        header = bytes([mode.value]) + salt + file_uuid

    elif mode == EncryptModeType.MODE_PASSWORD_PLUS_KEY:
        expected_min_len = 1 + SALT_SIZE + UUID_SIZE + NONCE_SIZE + 16
        if len(data) < expected_min_len:
            raise ValueError("Input file too short for password+key mode")

        salt = data[1:1+SALT_SIZE]
        file_uuid = data[1+SALT_SIZE:1+SALT_SIZE+UUID_SIZE]
        nonce = data[1+SALT_SIZE+UUID_SIZE:1+SALT_SIZE+UUID_SIZE+NONCE_SIZE]
        ciphertext = data[1+SALT_SIZE+UUID_SIZE+NONCE_SIZE:]

        if not (password and usb_key):
            raise ValueError("Both password and key required for password+key mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")

        pw_key = derive_key_from_password(password, salt)
        key = _combine_pw_and_key_with_hkdf(pw_key, usb_key)
        header = bytes([mode.value]) + salt + file_uuid

    elif mode == EncryptModeType.MODE_KEY_ONLY:
        expected_min_len = 1 + UUID_SIZE + NONCE_SIZE + 16
        if len(data) < expected_min_len:
            raise ValueError("Input file too short for key-only mode")

        file_uuid = data[1:1+UUID_SIZE]
        nonce = data[1+UUID_SIZE:1+UUID_SIZE+NONCE_SIZE]
        ciphertext = data[1+UUID_SIZE+NONCE_SIZE:]

        if not usb_key:
            raise ValueError("Key required for key-only mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")

        key = usb_key
        header = bytes([mode.value]) + file_uuid

    else:
        raise ValueError(f"Unsupported mode: {mode}")

    # Decrypt using the full header (including UUID) as Associated Data
    return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, header, nonce, key)


def test_all_modes() -> None:
    test_data = b"Secret text for PangCrypter!"
    usb_key = nacl_random(KEY_SIZE)
    password = "CorrectHorseBatteryStaple"

    # Generate UUID for testing
    test_uuid = uuid4()

    # Mode 0: Password only
    encrypt_file(test_data, "test_pw.enc", EncryptModeType.MODE_PASSWORD_ONLY, test_uuid, password=password)
    assert decrypt_file("test_pw.enc", password=password) == test_data

    # Mode 1: Password + key
    encrypt_file(test_data, "test_pw_key.enc", EncryptModeType.MODE_PASSWORD_PLUS_KEY, test_uuid, password=password, usb_key=usb_key)
    assert decrypt_file("test_pw_key.enc", password=password, usb_key=usb_key) == test_data

    # Mode 2: Key only
    encrypt_file(test_data, "test_key.enc", EncryptModeType.MODE_KEY_ONLY, test_uuid, usb_key=usb_key)
    assert decrypt_file("test_key.enc", usb_key=usb_key) == test_data

    # Clean up test files
    import os
    for f in ["test_pw.enc", "test_pw_key.enc", "test_key.enc"]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    test_all_modes()
    print("Encryption and decryption tests completed successfully.")
