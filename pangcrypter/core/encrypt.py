# lib/encrypt.py
import os
import unicodedata

from typing import Optional, Union
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)
from nacl.utils import random as nacl_random
from nacl.exceptions import CryptoError as NaClCryptoError
from argon2.low_level import hash_secret_raw, Type
from enum import Enum

# cryptography for HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from uuid import UUID
from .errors import DecryptionAuthError

from .format_config import (
    HEADER_VERSION,
    SETTINGS_SIZE,
    MODE_OFFSET,
    CONTENT_MODE_OFFSET,
    SALT_SIZE,
    UUID_SIZE,
    NONCE_SIZE,
    CONTENT_MODE_PLAINTEXT,
    CONTENT_MODE_HTML,
    encode_version,
    decode_version,
)

class EncryptModeType(Enum):
    MODE_PASSWORD_ONLY = 0x00
    MODE_PASSWORD_PLUS_KEY = 0x01
    MODE_KEY_ONLY = 0x02

# Constants
KEY_SIZE = 32


def _normalize_password_bytes(password: Union[str, bytes, bytearray]) -> bytes:
    if isinstance(password, str):
        normalized = unicodedata.normalize("NFKC", password)
        return normalized.encode("utf-8")
    if isinstance(password, (bytes, bytearray)):
        return bytes(password)
    raise TypeError("password must be str, bytes, or bytearray")


def derive_key_from_password(password: Union[str, bytes, bytearray], salt: bytes) -> bytes:
    """
    Normalize the password and derive a fixed-length key using Argon2id.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes")

    # Normalize to avoid multiple Unicode representations of the same password.
    normalized = _normalize_password_bytes(password)
    return hash_secret_raw(
        secret=normalized,
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
                 password: Optional[Union[str, bytes, bytearray]] = None,
                 usb_key: Optional[bytes] = None,
                 content_mode: int = 0x00) -> None:
    """
    Encrypts and writes a file, embedding a unique UUID in the header.
    """
    if not isinstance(mode, EncryptModeType):
        try:
            mode = EncryptModeType(mode)
        except ValueError:
            raise TypeError("mode must be an EncryptModeType")

    if content_mode not in (CONTENT_MODE_PLAINTEXT, CONTENT_MODE_HTML):
        raise ValueError("Unsupported content mode")

    settings = bytearray(SETTINGS_SIZE)
    settings[0:2] = encode_version(HEADER_VERSION)
    settings[MODE_OFFSET] = mode.value
    settings[CONTENT_MODE_OFFSET] = content_mode

    if mode == EncryptModeType.MODE_PASSWORD_ONLY:
        if not password:
            raise ValueError("Password is required for password-only mode")
        salt = nacl_random(SALT_SIZE)
        key = derive_key_from_password(password, salt)
        header = bytes(settings) + salt + uuid.bytes

    elif mode == EncryptModeType.MODE_PASSWORD_PLUS_KEY:
        if not (password and usb_key):
            raise ValueError("Both password and key required for password+key mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")
        salt = nacl_random(SALT_SIZE)
        pw_key = derive_key_from_password(password, salt)
        key = _combine_pw_and_key_with_hkdf(pw_key, usb_key)
        header = bytes(settings) + salt + uuid.bytes

    elif mode == EncryptModeType.MODE_KEY_ONLY:
        if not usb_key:
            raise ValueError("Key required for key-only mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")
        key = usb_key
        salt = bytes([0] * SALT_SIZE)
        header = bytes(settings) + salt + uuid.bytes

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
                 password: Optional[Union[str, bytes, bytearray]] = None,
                 usb_key: Optional[bytes] = None) -> bytes:
    """Decrypts and returns the file contents. Performs robust sanity checks first."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(input_path)

    with open(input_path, "rb") as f:
        data = f.read()

    min_len = SETTINGS_SIZE + SALT_SIZE + UUID_SIZE + NONCE_SIZE + 16
    if len(data) < min_len:
        raise ValueError("Input file is too short or corrupted")

    settings = data[:SETTINGS_SIZE]
    version = decode_version(settings[0:2])
    if version != HEADER_VERSION:
        raise ValueError(f"Unsupported file version: {version}")

    mode_byte = settings[MODE_OFFSET]
    try:
        mode = EncryptModeType(mode_byte)
    except ValueError:
        raise ValueError(f"Invalid mode byte: {mode_byte}")

    salt_start = SETTINGS_SIZE
    salt_end = salt_start + SALT_SIZE
    uuid_start = salt_end
    uuid_end = uuid_start + UUID_SIZE
    nonce_start = uuid_end
    nonce_end = nonce_start + NONCE_SIZE

    salt = data[salt_start:salt_end]
    nonce = data[nonce_start:nonce_end]
    ciphertext = data[nonce_end:]

    if mode == EncryptModeType.MODE_PASSWORD_ONLY:
        if not password:
            raise ValueError("Password is required for password-only mode")
        key = derive_key_from_password(password, salt)

    elif mode == EncryptModeType.MODE_PASSWORD_PLUS_KEY:
        if not (password and usb_key):
            raise ValueError("Both password and key required for password+key mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")
        pw_key = derive_key_from_password(password, salt)
        key = _combine_pw_and_key_with_hkdf(pw_key, usb_key)

    elif mode == EncryptModeType.MODE_KEY_ONLY:
        if not usb_key:
            raise ValueError("Key required for key-only mode")
        if len(usb_key) != KEY_SIZE:
            raise ValueError(f"usb_key must be exactly {KEY_SIZE} bytes")
        key = usb_key

    else:
        raise ValueError(f"Unsupported mode: {mode}")

    header = data[:uuid_end]

    # Decrypt using the full header (settings + salt + UUID) as Associated Data.
    # Re-raise auth/tag failures as a dual-inheritance error so existing callers
    # expecting CryptoError continue working while UI code catching ValueError
    # also remains stable.
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, header, nonce, key)
    except NaClCryptoError as exc:
        raise DecryptionAuthError("Decryption failed: wrong password/key or corrupted file") from exc
