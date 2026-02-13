#!/usr/bin/env python3
"""Integration test for PangCrypter - tests all encryption modes."""

import os
import tempfile
from uuid import uuid4

import pytest
from nacl.exceptions import CryptoError

from pangcrypter.core.encrypt import EncryptModeType, encrypt_file, decrypt_file
from pangcrypter.core.key import generate_secure_key


def _mktemp_enc_path() -> str:
    fd, path = tempfile.mkstemp(suffix=".enc")
    os.close(fd)
    return path


def _cleanup(path: str) -> None:
    try:
        os.remove(path)
    except (FileNotFoundError, PermissionError):
        pass

def test_all_modes_basic():
    """Test basic encryption/decryption without file system dependencies."""
    test_data = b"This is a test of PangCrypter encryption modes!"

    # Test Mode 0: Password-only
    password_only_uuid = uuid4()
    password_only_path = _mktemp_enc_path()
    try:
        encrypt_file(
            test_data,
            password_only_path,
            EncryptModeType.MODE_PASSWORD_ONLY,
            password_only_uuid,
            password="TestPassword123!",
        )
        decrypted = decrypt_file(password_only_path, password="TestPassword123!")
        assert decrypted == test_data
    finally:
        _cleanup(password_only_path)

    # Test Mode 1: Password + Key
    pw_key_uuid = uuid4()
    pw_key_path = _mktemp_enc_path()
    try:
        usb_key = generate_secure_key()
        encrypt_file(
            test_data,
            pw_key_path,
            EncryptModeType.MODE_PASSWORD_PLUS_KEY,
            pw_key_uuid,
            password="TestPassword123!",
            usb_key=usb_key,
        )
        decrypted = decrypt_file(pw_key_path, password="TestPassword123!", usb_key=usb_key)
        assert decrypted == test_data
    finally:
        _cleanup(pw_key_path)

    # Test Mode 2: Key-only
    key_only_uuid = uuid4()
    key_only_path = _mktemp_enc_path()
    try:
        usb_key2 = generate_secure_key()
        encrypt_file(
            test_data,
            key_only_path,
            EncryptModeType.MODE_KEY_ONLY,
            key_only_uuid,
            usb_key=usb_key2,
        )
        decrypted = decrypt_file(key_only_path, usb_key=usb_key2)
        assert decrypted == test_data
    finally:
        _cleanup(key_only_path)

def test_error_conditions():
    """Test error conditions and security."""
    test_data = b"Test data for error conditions"
    test_uuid = uuid4()

    # Test wrong password for password-only
    wrong_pw_path = _mktemp_enc_path()
    try:
        encrypt_file(
            test_data,
            wrong_pw_path,
            EncryptModeType.MODE_PASSWORD_ONLY,
            test_uuid,
            password="CorrectPassword123!",
        )
        with pytest.raises(CryptoError):
            decrypt_file(wrong_pw_path, password="WrongPassword456!")
    finally:
        _cleanup(wrong_pw_path)

    # Test wrong key for key-only
    wrong_key_path = _mktemp_enc_path()
    try:
        wrong_key_uuid = uuid4()
        correct_key = generate_secure_key()
        wrong_key = generate_secure_key()
        encrypt_file(
            test_data,
            wrong_key_path,
            EncryptModeType.MODE_KEY_ONLY,
            wrong_key_uuid,
            usb_key=correct_key,
        )
        with pytest.raises(CryptoError):
            decrypt_file(wrong_key_path, usb_key=wrong_key)
    finally:
        _cleanup(wrong_key_path)

    # Test corrupted file detection
    corrupt_path = _mktemp_enc_path()
    try:
        # Create an obviously corrupted file
        with open(corrupt_path, "wb") as f:
            f.write(b"x")
        with pytest.raises(ValueError):
            decrypt_file(corrupt_path, password="AnyPassword")
    finally:
        _cleanup(corrupt_path)

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
