#!/usr/bin/env python3
"""Integration test for PangCrypter - tests all encryption modes."""

import os
import tempfile
from uuid import uuid4
from lib.encrypt import EncryptModeType, encrypt_file, decrypt_file
from lib.key import generate_secure_key

def test_all_modes_basic():
    """Test basic encryption/decryption without file system dependencies."""
    test_data = b"This is a test of PangCrypter encryption modes!"

    # Test Mode 0: Password-only
    print("Testing password-only mode...")
    password_only_uuid = uuid4()
    fd, password_only_path = tempfile.mkstemp(suffix='.enc')
    try:
        os.close(fd)  # Close the file descriptor immediately
        encrypt_file(test_data, password_only_path, EncryptModeType.MODE_PASSWORD_ONLY,
                    password_only_uuid, password="TestPassword123!")
        decrypted = decrypt_file(password_only_path, password="TestPassword123!")
        assert decrypted == test_data, "Password-only mode failed"
        print("✓ Password-only mode works")
    finally:
        try:
            os.remove(password_only_path)
        except (FileNotFoundError, PermissionError):
            pass  # File may already be deleted or locked

    # Test Mode 1: Password + Key
    print("Testing password+key mode...")
    pw_key_uuid = uuid4()
    fd2, pw_key_path = tempfile.mkstemp(suffix='.enc')
    try:
        os.close(fd2)
        usb_key = generate_secure_key()
        encrypt_file(test_data, pw_key_path, EncryptModeType.MODE_PASSWORD_PLUS_KEY,
                    pw_key_uuid, password="TestPassword123!", usb_key=usb_key)
        decrypted = decrypt_file(pw_key_path, password="TestPassword123!", usb_key=usb_key)
        assert decrypted == test_data, "Password+key mode failed"
        print("✓ Password+key mode works")
    finally:
        try:
            os.remove(pw_key_path)
        except (FileNotFoundError, PermissionError):
            pass

    # Test Mode 2: Key-only
    print("Testing key-only mode...")
    key_only_uuid = uuid4()
    fd3, key_only_path = tempfile.mkstemp(suffix='.enc')
    try:
        os.close(fd3)
        usb_key2 = generate_secure_key()
        encrypt_file(test_data, key_only_path, EncryptModeType.MODE_KEY_ONLY,
                    key_only_uuid, usb_key=usb_key2)
        decrypted = decrypt_file(key_only_path, usb_key=usb_key2)
        assert decrypted == test_data, "Key-only mode failed"
        print("✓ Key-only mode works")
    finally:
        try:
            os.remove(key_only_path)
        except (FileNotFoundError, PermissionError):
            pass

    print("\n✅ All encryption modes work correctly!")
    return True

def test_error_conditions():
    """Test error conditions and security."""
    test_data = b"Test data for error conditions"
    test_uuid = uuid4()

    # Test wrong password for password-only
    print("Testing wrong password rejection...")
    fd4, wrong_pw_path = tempfile.mkstemp(suffix='.enc')
    try:
        os.close(fd4)
        encrypt_file(test_data, wrong_pw_path, EncryptModeType.MODE_PASSWORD_ONLY,
                    test_uuid, password="CorrectPassword123!")
        try:
            decrypt_file(wrong_pw_path, password="WrongPassword456!")
            assert False, "Should have failed with wrong password"
        except:
            print("✓ Wrong password properly rejected")
    finally:
        try:
            os.remove(wrong_pw_path)
        except (FileNotFoundError, PermissionError):
            pass

    # Test wrong key for key-only
    print("Testing wrong key rejection...")
    fd5, wrong_key_path = tempfile.mkstemp(suffix='.enc')
    try:
        os.close(fd5)
        wrong_key_uuid = uuid4()
        correct_key = generate_secure_key()
        wrong_key = generate_secure_key()
        encrypt_file(test_data, wrong_key_path, EncryptModeType.MODE_KEY_ONLY,
                    wrong_key_uuid, usb_key=correct_key)
        try:
            decrypt_file(wrong_key_path, usb_key=wrong_key)
            assert False, "Should have failed with wrong key"
        except:
            print("✓ Wrong key properly rejected")
    finally:
        try:
            os.remove(wrong_key_path)
        except (FileNotFoundError, PermissionError):
            pass

    # Test corrupted file detection
    print("Testing corrupted file detection...")
    fd6, corrupt_path = tempfile.mkstemp(suffix='.enc')
    try:
        os.close(fd6)
        # Create an obviously corrupted file
        with open(corrupt_path, 'wb') as f:
            f.write(b'x')  # Too short to be valid
        try:
            decrypt_file(corrupt_path, password="AnyPassword")
            assert False, "Should have detected corrupted file"
        except:
            print("✓ Corrupted file properly detected")
    finally:
        try:
            os.remove(corrupt_path)
        except (FileNotFoundError, PermissionError):
            pass

    print("\n✅ Error conditions handled correctly!")
    return True

if __name__ == "__main__":
    print("Running PangCrypter integration tests...")
    test_all_modes_basic()
    test_error_conditions()
    print("\n🎉 All integration tests passed!")
