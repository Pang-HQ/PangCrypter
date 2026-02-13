#!/usr/bin/env python3
"""
Comprehensive test suite for PangCrypter application.
Tests all main functions, GUI components, encryption/decryption, and edge cases.
"""

import sys
import os
import shutil
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4
import platform
import tempfile

# Add repository root to Python path for imports
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

# Import PyQt6 components for GUI testing
from PyQt6.QtWidgets import QApplication  # noqa: E402

# Import application modules
from pangcrypter.main import MainWindow  # noqa: E402
from pangcrypter.utils.screen_recording import ScreenRecordingChecker  # noqa: E402
from pangcrypter.utils.usb import list_usb_drives  # noqa: E402
from pangcrypter.ui.main_ui import (  # noqa: E402
    EditorWidget,
    EncryptModeDialog,
    PasswordDialog,
    USBSelectDialog,
)
from pangcrypter.core.encrypt import (  # noqa: E402
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    EncryptModeType,
    _combine_pw_and_key_with_hkdf,
    decrypt_file,
    derive_key_from_password,
    encrypt_file,
)
from pangcrypter.core.format_config import UUID_SIZE  # noqa: E402
from pangcrypter.core.key import (  # noqa: E402
    create_or_load_key,
    decrypt_random_key,
    encrypt_random_key,
    generate_secure_key,
    get_drive_hardware_id,
    get_file_id,
    get_key_path,
)
from pangcrypter.ui.messagebox import PangMessageBox  # noqa: E402
from pangcrypter.utils.preferences import Preferences  # noqa: E402
import pangcrypter.utils.preferences as preferences  # noqa: E402
from pangcrypter.utils.mem_guard import MemGuardMode  # noqa: E402


class TestEncryptionCore(unittest.TestCase):
    """Test the core encryption/decryption functionality."""
    
    def setUp(self):
        self.test_data = b"This is secret test data for PangCrypter!"
        self.password = "TestPassword123!"
        self.usb_key = os.urandom(KEY_SIZE)
        self.test_uuid = uuid4()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_derive_key_from_password(self):
        """Test password-based key derivation."""
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key_from_password(self.password, salt)
        key2 = derive_key_from_password(self.password, salt)
        
        # Same password and salt should produce same key
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), KEY_SIZE)
        
        # Different salt should produce different key
        different_salt = os.urandom(SALT_SIZE)
        key3 = derive_key_from_password(self.password, different_salt)
        self.assertNotEqual(key1, key3)
        
        # Different password should produce different key
        key4 = derive_key_from_password("DifferentPassword", salt)
        self.assertNotEqual(key1, key4)
    
    def test_combine_pw_and_key_with_hkdf(self):
        """Test combining password-derived key with USB key."""
        pw_key = os.urandom(KEY_SIZE)
        usb_key = os.urandom(KEY_SIZE)
        
        combined1 = _combine_pw_and_key_with_hkdf(pw_key, usb_key)
        combined2 = _combine_pw_and_key_with_hkdf(pw_key, usb_key)
        
        # Same inputs should produce same output
        self.assertEqual(combined1, combined2)
        self.assertEqual(len(combined1), KEY_SIZE)
        
        # Different inputs should produce different outputs
        different_usb = os.urandom(KEY_SIZE)
        combined3 = _combine_pw_and_key_with_hkdf(pw_key, different_usb)
        self.assertNotEqual(combined1, combined3)
    
    def test_encrypt_decrypt_password_only(self):
        """Test encryption/decryption with password only."""
        test_file = os.path.join(self.temp_dir, "test_pw.enc")
        
        # Encrypt
        encrypt_file(
            self.test_data, test_file, EncryptModeType.MODE_PASSWORD_ONLY,
            self.test_uuid, password=self.password
        )
        
        # Verify file exists and has correct structure
        self.assertTrue(os.path.exists(test_file))
        with open(test_file, "rb") as f:
            data = f.read()
        
        # Check minimum file size (settings + salt + uuid + nonce + tag + data)
        min_size = 16 + SALT_SIZE + 16 + NONCE_SIZE + 16 + len(self.test_data)
        self.assertGreaterEqual(len(data), min_size)

        # Check mode byte in settings
        self.assertEqual(data[2], EncryptModeType.MODE_PASSWORD_ONLY.value)
        
        # Decrypt
        decrypted = decrypt_file(test_file, password=self.password)
        self.assertEqual(decrypted, self.test_data)
    
    def test_encrypt_decrypt_key_only(self):
        """Test encryption/decryption with USB key only."""
        test_file = os.path.join(self.temp_dir, "test_key.enc")
        
        # Encrypt
        encrypt_file(
            self.test_data, test_file, EncryptModeType.MODE_KEY_ONLY,
            self.test_uuid, usb_key=self.usb_key
        )
        
        # Verify file structure
        self.assertTrue(os.path.exists(test_file))
        with open(test_file, "rb") as f:
            data = f.read()
        
        # Check mode byte in settings
        self.assertEqual(data[2], EncryptModeType.MODE_KEY_ONLY.value)
        
        # Decrypt
        decrypted = decrypt_file(test_file, usb_key=self.usb_key)
        self.assertEqual(decrypted, self.test_data)
    
    def test_encrypt_decrypt_password_plus_key(self):
        """Test encryption/decryption with password + USB key."""
        test_file = os.path.join(self.temp_dir, "test_both.enc")
        
        # Encrypt
        encrypt_file(
            self.test_data, test_file, EncryptModeType.MODE_PASSWORD_PLUS_KEY,
            self.test_uuid, password=self.password, usb_key=self.usb_key
        )
        
        # Verify file structure
        self.assertTrue(os.path.exists(test_file))
        with open(test_file, "rb") as f:
            data = f.read()
        
        # Check mode byte in settings
        self.assertEqual(data[2], EncryptModeType.MODE_PASSWORD_PLUS_KEY.value)
        
        # Decrypt
        decrypted = decrypt_file(test_file, password=self.password, usb_key=self.usb_key)
        self.assertEqual(decrypted, self.test_data)
    
    def test_decrypt_wrong_password(self):
        """Test decryption with wrong password fails."""
        test_file = os.path.join(self.temp_dir, "test_wrong_pw.enc")
        
        encrypt_file(
            self.test_data, test_file, EncryptModeType.MODE_PASSWORD_ONLY,
            self.test_uuid, password=self.password
        )
        
        with self.assertRaises(ValueError):
            decrypt_file(test_file, password="WrongPassword")
    
    def test_decrypt_wrong_key(self):
        """Test decryption with wrong USB key fails."""
        test_file = os.path.join(self.temp_dir, "test_wrong_key.enc")
        wrong_key = os.urandom(KEY_SIZE)
        
        encrypt_file(
            self.test_data, test_file, EncryptModeType.MODE_KEY_ONLY,
            self.test_uuid, usb_key=self.usb_key
        )
        
        with self.assertRaises(ValueError):
            decrypt_file(test_file, usb_key=wrong_key)
    
    def test_invalid_file_format(self):
        """Test handling of invalid file formats."""
        # Empty file
        empty_file = os.path.join(self.temp_dir, "empty.enc")
        with open(empty_file, "wb") as f:
            pass
        
        with self.assertRaises(ValueError):
            decrypt_file(empty_file, password=self.password)
        
        # File too short
        short_file = os.path.join(self.temp_dir, "short.enc")
        with open(short_file, "wb") as f:
            f.write(b"short")
        
        with self.assertRaises(ValueError):
            decrypt_file(short_file, password=self.password)
        
        # Invalid mode byte
        invalid_mode_file = os.path.join(self.temp_dir, "invalid_mode.enc")
        with open(invalid_mode_file, "wb") as f:
            f.write(b"\xFF" + b"0" * 100)  # Invalid mode byte
        
        with self.assertRaises(ValueError):
            decrypt_file(invalid_mode_file, password=self.password)
    
    def test_missing_parameters(self):
        """Test encryption with missing required parameters."""
        test_file = os.path.join(self.temp_dir, "test_missing.enc")
        
        # Password mode without password
        with self.assertRaises(ValueError):
            encrypt_file(
                self.test_data, test_file, EncryptModeType.MODE_PASSWORD_ONLY,
                self.test_uuid
            )
        
        # Key mode without key
        with self.assertRaises(ValueError):
            encrypt_file(
                self.test_data, test_file, EncryptModeType.MODE_KEY_ONLY,
                self.test_uuid
            )
        
        # Password+Key mode without password
        with self.assertRaises(ValueError):
            encrypt_file(
                self.test_data, test_file, EncryptModeType.MODE_PASSWORD_PLUS_KEY,
                self.test_uuid, usb_key=self.usb_key
            )
        
        # Password+Key mode without key
        with self.assertRaises(ValueError):
            encrypt_file(
                self.test_data, test_file, EncryptModeType.MODE_PASSWORD_PLUS_KEY,
                self.test_uuid, password=self.password
            )


class TestKeyManagement(unittest.TestCase):
    """Test USB key management functionality."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_uuid = uuid4()
        self.test_file = os.path.join(self.temp_dir, "test.enc")
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_secure_key(self):
        """Test secure key generation."""
        key1 = generate_secure_key()
        key2 = generate_secure_key()
        
        self.assertEqual(len(key1), KEY_SIZE)
        self.assertEqual(len(key2), KEY_SIZE)
        self.assertNotEqual(key1, key2)  # Should be random
    
    def test_encrypt_decrypt_random_key_with_hwid(self):
        """Test hardware ID-based key encryption/decryption."""
        random_key = generate_secure_key()
        hardware_id = b"test_hardware_id_12345678901234567890"
        
        # Encrypt
        drive_secret = os.urandom(KEY_SIZE)
        combined_key = encrypt_random_key(random_key, hardware_id, drive_secret)
        self.assertGreater(len(combined_key), len(random_key))
        
        # Decrypt
        decrypted_key = decrypt_random_key(combined_key, hardware_id, drive_secret)
        self.assertEqual(decrypted_key, random_key)
        
        # Wrong hardware ID should fail
        wrong_hwid = b"wrong_hardware_id_1234567890123456789"
        with self.assertRaises(ValueError):
            decrypt_random_key(combined_key, wrong_hwid, drive_secret)
    
    @patch('subprocess.run')
    def test_get_drive_hardware_id_windows(self, mock_run):
        """Test Windows drive hardware ID extraction."""
        with patch('platform.system', return_value='Windows'):
            # Mock successful wmic output
            mock_result = Mock()
            mock_result.stdout = "VolumeSerialNumber=ABCD1234\n"
            mock_result.returncode = 0
            mock_run.return_value = mock_result
            
            hwid = get_drive_hardware_id("F:\\")
            self.assertEqual(len(hwid), 32)  # SHA256 hash
    
    @patch('subprocess.run')
    def test_get_drive_hardware_id_linux(self, mock_run):
        """Test Linux drive hardware ID extraction."""
        if platform.system() != 'Linux':
            self.skipTest("Linux-specific test")
        
        with patch('platform.system', return_value='Linux'):
            # Mock successful blkid output
            mock_result = Mock()
            mock_result.stdout = "test-uuid-1234-5678\n"
            mock_result.returncode = 0
            mock_run.return_value = mock_result
            
            hwid = get_drive_hardware_id("/media/usb")
            self.assertEqual(len(hwid), 32)  # SHA256 hash
    
    def test_get_key_path(self):
        """Test key file path generation."""
        drive_root = self.temp_dir
        path = "test.enc"
        
        key_path = get_key_path(drive_root, path, self.test_uuid)
        
        expected_folder = os.path.join(drive_root, ".pangcrypt_keys")
        expected_file = os.path.join(expected_folder, f"{self.test_uuid.hex}.bin")
        
        self.assertEqual(key_path, expected_file)
        self.assertTrue(os.path.exists(expected_folder))
    
    def test_create_encrypted_file_for_get_file_id(self):
        """Create a test encrypted file to test get_file_id."""
        # Create a test encrypted file with known UUID
        test_data = b"test data"
        encrypt_file(
            test_data, self.test_file, EncryptModeType.MODE_PASSWORD_ONLY,
            self.test_uuid, password="test"
        )
        
        # Test get_file_id
        file_id = get_file_id(self.test_file)
        self.assertEqual(file_id, self.test_uuid.hex)
    
    def test_get_file_id_key_only_mode(self):
        """Test get_file_id with key-only mode (no salt)."""
        test_data = b"test data"
        encrypt_file(
            test_data, self.test_file, EncryptModeType.MODE_KEY_ONLY,
            self.test_uuid, usb_key=os.urandom(KEY_SIZE)
        )
        
        file_id = get_file_id(self.test_file)
        self.assertEqual(file_id, self.test_uuid.hex)
    
    @patch('pangcrypter.core.key.get_drive_hardware_id')
    @patch('pangcrypter.core.key._validate_drive_root')
    def test_create_or_load_key_create(self, mock_validate_root, mock_hwid):
        """Test creating a new key."""
        mock_validate_root.return_value = self.temp_dir
        mock_hwid.return_value = b"test_hwid" * 4  # 32 bytes
        
        # Create encrypted file first
        test_data = b"test data"
        encrypt_file(
            test_data, self.test_file, EncryptModeType.MODE_PASSWORD_ONLY,
            self.test_uuid, password="test"
        )
        
        key, returned_uuid = create_or_load_key(self.temp_dir, self.test_file, self.test_uuid)
        
        self.assertEqual(len(key), KEY_SIZE)
        self.assertEqual(returned_uuid, self.test_uuid)
        
        # Key file should exist
        key_path = get_key_path(self.temp_dir, self.test_file, self.test_uuid)
        self.assertTrue(os.path.exists(key_path))
    
    @patch('pangcrypter.core.key.get_drive_hardware_id')
    @patch('pangcrypter.core.key._validate_drive_root')
    def test_create_or_load_key_load(self, mock_validate_root, mock_hwid):
        """Test loading an existing key."""
        mock_validate_root.return_value = self.temp_dir
        mock_hwid.return_value = b"test_hwid" * 4  # 32 bytes
        
        # Create encrypted file first
        test_data = b"test data"
        encrypt_file(
            test_data, self.test_file, EncryptModeType.MODE_PASSWORD_ONLY,
            self.test_uuid, password="test"
        )
        
        # Create key first time
        key1, _ = create_or_load_key(self.temp_dir, self.test_file, self.test_uuid)
        
        # Load key second time
        key2, returned_uuid = create_or_load_key(self.temp_dir, self.test_file, self.test_uuid)
        
        self.assertEqual(key1, key2)
        self.assertEqual(returned_uuid, self.test_uuid)
    
    def test_create_or_load_key_no_create(self):
        """Test loading key when create=False and key doesn't exist."""
        # Create encrypted file first
        test_data = b"test data"
        encrypt_file(
            test_data, self.test_file, EncryptModeType.MODE_PASSWORD_ONLY,
            self.test_uuid, password="test"
        )
        
        with patch('pangcrypter.core.key._validate_drive_root', return_value=self.temp_dir):
            key, returned_uuid = create_or_load_key(self.temp_dir, self.test_file, create=False)
        
        # Should return None when key doesn't exist and create=False
        self.assertIsNone(key)
        self.assertIsNone(returned_uuid)

    def test_validate_drive_root_rejects_non_mount_without_override(self):
        from pangcrypter.core.key import _validate_drive_root
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('os.path.ismount', return_value=False), patch.dict(os.environ, {}, clear=False):
                with self.assertRaises(ValueError):
                    _validate_drive_root(temp_dir)

    def test_validate_drive_root_allows_override(self):
        from pangcrypter.core.key import _validate_drive_root
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('os.path.ismount', return_value=False), patch.dict(os.environ, {"PANGCRYPTER_ALLOW_NON_REMOVABLE": "1"}, clear=False):
                self.assertEqual(_validate_drive_root(temp_dir), os.path.abspath(temp_dir))


class TestPreferences(unittest.TestCase):
    """Test preferences management."""
    
    def setUp(self):
        self.temp_prefs_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.temp_prefs_file.close()
        self.original_prefs_file = preferences.PREFERENCES_FILE
        preferences.PREFERENCES_FILE = self.temp_prefs_file.name
        
    def tearDown(self):
        try:
            os.unlink(self.temp_prefs_file.name)
        except FileNotFoundError:
            pass  # File already deleted in test
        preferences.PREFERENCES_FILE = self.original_prefs_file
    
    def test_preferences_defaults(self):
        """Test default preferences values."""
        prefs = Preferences()
        
        self.assertEqual(prefs.recording_cooldown, 30)
        self.assertTrue(prefs.screen_recording_hide_enabled)
        self.assertTrue(prefs.tab_out_hide_enabled)
        self.assertEqual(prefs.tab_setting, "spaces4")
        self.assertTrue(prefs.session_cache_enabled)
        self.assertIn(prefs.mem_guard_mode, [m.value for m in MemGuardMode])
    
    def test_preferences_save_load(self):
        """Test saving and loading preferences."""
        prefs = Preferences()
        prefs.recording_cooldown = 60
        prefs.screen_recording_hide_enabled = False
        prefs.tab_setting = "spaces2"
        
        prefs.save_preferences()
        
        # Load into new instance
        new_prefs = Preferences()
        new_prefs.load_preferences()
        
        self.assertEqual(new_prefs.recording_cooldown, 60)
        self.assertFalse(new_prefs.screen_recording_hide_enabled)
        self.assertEqual(new_prefs.tab_setting, "spaces2")
    
    def test_preferences_load_invalid_file(self):
        """Test loading preferences from invalid/missing file."""
        # Remove the file
        os.unlink(self.temp_prefs_file.name)
        
        prefs = Preferences()
        prefs.load_preferences()  # Should not crash
        
        # Should have default values
        self.assertEqual(prefs.recording_cooldown, 30)
    
    def test_preferences_load_corrupted_json(self):
        """Test loading preferences from corrupted JSON file."""
        # Write invalid JSON
        with open(self.temp_prefs_file.name, 'w') as f:
            f.write("invalid json {")
        
        prefs = Preferences()
        prefs.load_preferences()  # Should not crash
        
        # Should have default values
        self.assertEqual(prefs.recording_cooldown, 30)

    def test_preferences_normalize_mem_guard_gating(self):
        prefs = Preferences(
            session_cache_enabled=False,
            mem_guard_mode=MemGuardMode.ULTRA_AGGRESSIVE.value,
            session_reauth_minutes=99,
            mem_guard_whitelist=["", 12, "C:/test/app.exe"],
        )
        prefs.normalize()
        self.assertEqual(prefs.mem_guard_mode, MemGuardMode.OFF.value)
        self.assertEqual(prefs.session_reauth_minutes, 5)
        self.assertEqual(len(prefs.mem_guard_whitelist), 1)


class TestGUIComponents(unittest.TestCase):
    """Test GUI components and dialogs."""
    
    @classmethod
    def setUpClass(cls):
        if not QApplication.instance():
            cls.app = QApplication([])
        else:
            cls.app = QApplication.instance()
    
    def test_editor_widget_creation(self):
        """Test EditorWidget creation and basic functionality."""
        editor = EditorWidget()
        
        # Test basic properties
        self.assertIsInstance(editor, EditorWidget)
        self.assertFalse(editor.acceptRichText())
        
        # Test text operations
        test_text = "Hello, World!"
        editor.setPlainText(test_text)
        self.assertEqual(editor.toPlainText(), test_text)
        
        # Test tab setting
        editor.set_tab_setting("spaces2")
        self.assertEqual(editor._tab_setting, "spaces2")
        self.assertEqual(editor.get_tab_str(), "  ")
        
        editor.set_tab_setting("tab")
        self.assertEqual(editor.get_tab_str(), "\t")
        
        editor.set_tab_setting("spaces8")
        self.assertEqual(editor.get_tab_str(), "        ")
    
    def test_editor_widget_formatting(self):
        """Test text formatting functions."""
        editor = EditorWidget()
        editor.setPlainText("Test text")
        
        # Select all text
        editor.selectAll()
        
        # Test bold toggle
        editor.toggle_bold()
        
        # Test italic toggle
        editor.toggle_italic()
        
        # Test font size change
        editor.change_font_size(2)
        editor.change_font_size(-1)
        
        # Test reset formatting
        editor.reset_formatting()
    
    def test_editor_widget_indentation(self):
        """Test indentation functionality."""
        editor = EditorWidget()
        editor.set_tab_setting("spaces4")
        
        # Test basic indentation
        editor.setPlainText("line1\nline2\nline3")
        editor.selectAll()
        
        # Test indent selection
        editor.indent_selection("    ")
        indented_text = editor.toPlainText()
        self.assertTrue(indented_text.startswith("    line1"))
        
        # Test unindent selection
        editor.selectAll()
        editor.unindent_selection("    ")
        unindented_text = editor.toPlainText()
        self.assertTrue(unindented_text.startswith("line1"))
    
    def test_encrypt_mode_dialog(self):
        """Test EncryptModeDialog."""
        dialog = EncryptModeDialog()
        
        # Test initial state
        self.assertIsNone(dialog.mode)
        
        # Test combo box has correct items
        self.assertEqual(dialog.combo.count(), 3)
        self.assertEqual(dialog.combo.itemText(0), "Password only")
        self.assertEqual(dialog.combo.itemText(1), "Password + USB key")
        self.assertEqual(dialog.combo.itemText(2), "USB key only")
        
        # Test mode selection
        dialog.combo.setCurrentIndex(1)
        self.assertEqual(dialog.combo.currentIndex(), 1)
    
    def test_password_dialog(self):
        """Test PasswordDialog."""
        dialog = PasswordDialog()
        
        # Test initial state
        self.assertIsNone(dialog.password)
        
        # Test password input
        test_password = "TestPassword123"
        dialog.edit.setText(test_password)
        self.assertEqual(dialog.edit.text(), test_password)
        
        # Test warning dialog
        warning_dialog = PasswordDialog(warning=True)
        self.assertIsNotNone(warning_dialog)
    
    def test_usb_select_dialog(self):
        """Test USBSelectDialog."""
        usb_list = ["F:\\", "G:\\", "H:\\"]
        dialog = USBSelectDialog(usb_list)
        
        # Test initial state
        self.assertIsNone(dialog.selected_usb)
        self.assertEqual(dialog.usb_list, usb_list)
        
        # Test combo box population
        self.assertEqual(dialog.combo.count(), len(usb_list))
        for i, usb in enumerate(usb_list):
            self.assertEqual(dialog.combo.itemText(i), usb)
    
    def test_pang_message_box(self):
        """Test PangMessageBox static methods."""
        # Test that methods exist and have correct signatures
        self.assertTrue(hasattr(PangMessageBox, 'information'))
        self.assertTrue(hasattr(PangMessageBox, 'warning'))
        self.assertTrue(hasattr(PangMessageBox, 'critical'))
        self.assertTrue(hasattr(PangMessageBox, 'question'))
        
        # Test message box creation (without showing)
        box = PangMessageBox()
        self.assertIsNotNone(box)


class TestMainApplication(unittest.TestCase):
    """Test main application functionality."""
    
    @classmethod
    def setUpClass(cls):
        if not QApplication.instance():
            cls.app = QApplication([])
        else:
            cls.app = QApplication.instance()
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('pangcrypter.main.list_usb_drives')
    def test_main_window_creation(self, mock_usb):
        """Test MainWindow creation."""
        mock_usb.return_value = []
        
        window = MainWindow()
        
        # Test basic properties
        self.assertIsInstance(window, MainWindow)
        self.assertEqual(window.windowTitle(), "PangCrypter Editor")
        self.assertIsNotNone(window.editor)
        
        # Test initial state
        self.assertIsNone(window.saved_file_path)
        self.assertIsNone(window.current_mode)
        self.assertIsNone(window.cached_password)
        self.assertIsNone(window.cached_usb_key)
    
    def test_window_title_update(self):
        """Test window title updates."""
        window = MainWindow()
        
        # Test with no file
        window.update_window_title(None)
        self.assertEqual(window.windowTitle(), "PangCrypter")

        # Test with file
        test_path = "C:/test.enc"
        window.update_window_title(test_path)
        self.assertEqual(window.windowTitle(), "Editing test - PangCrypter")
    
    @patch('pangcrypter.utils.usb.subprocess.run')
    def test_list_usb_drives_windows(self, mock_subprocess_run):
        """Test USB drive listing on Windows."""
        with patch('platform.system', return_value='Windows'):
            mock_result = Mock()
            mock_result.stdout = "DeviceID\nF:\nG:\n"
            mock_result.returncode = 0
            mock_subprocess_run.return_value = mock_result
            
            with patch('os.access', return_value=True):
                drives = list_usb_drives()
                self.assertIn("F:\\", drives)
                self.assertIn("G:\\", drives)

    @patch('pangcrypter.utils.usb.subprocess.run')
    def test_list_usb_drives_windows_subprocess_failure(self, mock_subprocess_run):
        with patch('platform.system', return_value='Windows'):
            mock_subprocess_run.side_effect = OSError("wmic missing")
            drives = list_usb_drives()
            self.assertEqual(drives, [])
    
    @patch('os.path.exists')
    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('os.path.ismount')
    @patch('os.access')
    def test_list_usb_drives_linux(self, mock_access, mock_ismount, mock_isdir, mock_listdir, mock_exists):
        """Test USB drive listing on Linux."""
        with patch('platform.system', return_value='Linux'):
            # Mock filesystem structure - need to handle multiple calls to listdir
            def listdir_side_effect(path):
                if path in ["/media", "/run/media"]:
                    return ['user']
                elif 'user' in path:
                    return ['usb1', 'usb2']
                return []
            
            mock_exists.return_value = True
            mock_listdir.side_effect = listdir_side_effect
            mock_isdir.return_value = True
            mock_ismount.return_value = True
            mock_access.return_value = True
            
            drives = list_usb_drives()
            self.assertGreater(len(drives), 0)
    
    def test_screen_recording_checker(self):
        """Test ScreenRecordingChecker functionality."""
        checker = ScreenRecordingChecker(check_interval=0.1)
        
        # Test initial state
        self.assertTrue(checker.running)
        self.assertFalse(checker._last_status)
        
        # Test stop
        checker.stop()
        self.assertFalse(checker.running)
    
    @patch('pangcrypter.main.PangMessageBox.warning')
    def test_autosave_without_cached_keys(self, mock_warning):
        """Test autosave behavior without cached keys."""
        window = MainWindow()
        
        # Should return early without cached keys
        window.autosave()
        mock_warning.assert_not_called()
    
    @patch('pangcrypter.main.PangMessageBox.warning')
    def test_autosave_without_saved_file(self, mock_warning):
        """Test autosave behavior without saved file path."""
        window = MainWindow()
        window.cached_password = "test"
        
        # Should return early without saved file path
        window.autosave()
        mock_warning.assert_not_called()


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions and edge cases."""
    
    def test_encryption_mode_enum(self):
        """Test EncryptModeType enum."""
        self.assertEqual(EncryptModeType.MODE_PASSWORD_ONLY.value, 0)
        self.assertEqual(EncryptModeType.MODE_PASSWORD_PLUS_KEY.value, 1)
        self.assertEqual(EncryptModeType.MODE_KEY_ONLY.value, 2)
        
        # Test enum conversion
        mode = EncryptModeType(0)
        self.assertEqual(mode, EncryptModeType.MODE_PASSWORD_ONLY)
    
    def test_constants(self):
        """Test that constants have expected values."""
        self.assertEqual(UUID_SIZE, 16)
        self.assertEqual(SALT_SIZE, 16)
        self.assertEqual(KEY_SIZE, 32)
        self.assertEqual(NONCE_SIZE, 24)
    
    def test_unicode_password_normalization(self):
        """Test Unicode password normalization."""
        # Test with Unicode characters
        password1 = "café"  # NFC form
        password2 = "cafe\u0301"  # NFD form (e + combining acute)
        
        salt = os.urandom(SALT_SIZE)
        key1 = derive_key_from_password(password1, salt)
        key2 = derive_key_from_password(password2, salt)
        
        # Should produce same key after normalization
        self.assertEqual(key1, key2)
    
    def test_file_operations_edge_cases(self):
        """Test edge cases in file operations."""
        temp_dir = tempfile.mkdtemp()
        try:
            # Test with non-existent file
            with self.assertRaises(FileNotFoundError):
                decrypt_file(os.path.join(temp_dir, "nonexistent.enc"))
            
            # Test with directory instead of file
            os.makedirs(os.path.join(temp_dir, "directory.enc"))
            with self.assertRaises((IsADirectoryError, PermissionError, OSError, ValueError)):
                decrypt_file(os.path.join(temp_dir, "directory.enc"))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2, buffer=True)
