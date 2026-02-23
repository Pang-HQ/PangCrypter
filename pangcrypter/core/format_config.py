"""
File format configuration for PangCrypter encrypted files.

Header layout (fixed for all modes):
  - settings block (16 bytes)
      bytes 0-1: version (uint16, big-endian)
      byte 2   : encryption mode (EncryptModeType value)
      byte 3   : content mode (0x00 plaintext, 0x01 HTML)
      bytes 4-15: reserved (0x00)
  - salt (16 bytes, zeroed for key-only mode)
  - uuid (16 bytes)
  - nonce (24 bytes)
  - ciphertext (variable)
"""

HEADER_VERSION = 1

CONTENT_MODE_PLAINTEXT = 0x00
CONTENT_MODE_HTML = 0x01

SETTINGS_SIZE = 16
VERSION_SIZE = 2
MODE_OFFSET = 2
CONTENT_MODE_OFFSET = 3
RESERVED_OFFSET = 4

# KDF metadata stored in reserved settings bytes for HEADER_VERSION=1 files.
# This keeps backward compatibility while enabling future tuning.
KDF_TIME_COST_OFFSET = 4
KDF_MEMORY_COST_KIB_OFFSET = 5
KDF_PARALLELISM_OFFSET = 6
KDF_PROFILE_OFFSET = 7

DEFAULT_KDF_TIME_COST = 3
DEFAULT_KDF_MEMORY_COST_KIB = 65536
DEFAULT_KDF_PARALLELISM = 1

SALT_SIZE = 16
UUID_SIZE = 16
NONCE_SIZE = 24

HEADER_SIZE = SETTINGS_SIZE + SALT_SIZE + UUID_SIZE


def encode_version(version: int) -> bytes:
    return int(version).to_bytes(VERSION_SIZE, "big")


def decode_version(version_bytes: bytes) -> int:
    if len(version_bytes) != VERSION_SIZE:
        raise ValueError("Invalid version bytes")
    return int.from_bytes(version_bytes, "big")