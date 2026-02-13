import sys
import os
import logging
import argparse
import json
from datetime import datetime, timezone
from time import monotonic
from webbrowser import open as webopen
from typing import Optional, List
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QLabel, QProgressBar,
    QStatusBar, QMenu
)
from PyQt6.QtCore import QTimer, Qt, QEvent, QThread, QMutex
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QMessageBox
from .ui.main_ui import (
    EditorWidget, EncryptModeDialog, PasswordDialog, USBSelectDialog
)
from .core.encrypt import encrypt_file, decrypt_file, EncryptModeType
from .core.format_config import (
    SETTINGS_SIZE,
    CONTENT_MODE_OFFSET,
    CONTENT_MODE_PLAINTEXT,
    CONTENT_MODE_HTML,
    HEADER_VERSION,
    decode_version,
)
from .core.key import create_or_load_key
from .ui.messagebox import PangMessageBox

from .utils.preferences import PreferencesDialog, PangPreferences
from .utils.styles import TEXT_COLOR, DARKER_BG, PURPLE
from .ui.update_dialog import UpdateDialog
from .utils.logger import configure_logging
from .utils.usb import list_usb_drives
from .utils.screen_recording import ScreenRecordingChecker
from .utils.mem_guard import (
    MemGuardChecker,
    MemGuardMode,
    MemGuardFinding,
    file_sha256,
    is_mem_guard_supported,
)

from uuid import uuid4, UUID

logger = logging.getLogger(__name__)

MODE_PASSWORD_ONLY = EncryptModeType.MODE_PASSWORD_ONLY
MODE_PASSWORD_PLUS_KEY = EncryptModeType.MODE_PASSWORD_PLUS_KEY
MODE_KEY_ONLY = EncryptModeType.MODE_KEY_ONLY

class ValidationError(Exception):
    """Custom exception for input validation errors."""
    pass

class CryptographyError(Exception):
    """Custom exception for cryptography-related errors."""
    pass

class USBKeyError(Exception):
    """Custom exception for USB key-related errors."""
    pass

class MainWindow(QMainWindow):
    MAX_SECRET_CACHE_IDLE_MINUTES = 15
    DEFAULT_SECRET_CACHE_IDLE_MINUTES = 5

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PangCrypter Editor")
        self.setWindowIcon(QIcon("ui/logo.ico"))
        self.resize(800, 600)

        self.editor = EditorWidget()
        self.setCentralWidget(self.editor)
        self.editor.focusLost.connect(self.on_editor_focus_lost)

        self.saved_file_path = None
        self.current_mode = None
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.cached_password = None  # obfuscated bytearray
        self.cached_usb_key = None   # obfuscated bytearray
        self.cached_uuid = None
        self.header_version = HEADER_VERSION
        self._secret_mask = os.urandom(32)
        self._panic_recovery_path: Optional[str] = None
        self._mem_guard_handling = False
        self._pending_mem_guard_findings: list[MemGuardFinding] = []
        self._pending_mem_guard_keys: set[tuple[int, str, int, str]] = set()
        self._mem_guard_disabled_until_restart = False
        self._secret_cache_notice_logged = False
        self._focus_lost_at: Optional[float] = None
        self._last_editor_activity_at: float = monotonic()
        
        # Thread safety
        self.operation_mutex = QMutex()
        
        # Status bar with progress indicator
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        self.mode_label = QLabel("Plaintext mode")
        self.mode_label.setStyleSheet("color: #8b8b8b; padding-right: 10px;")
        self.mode_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.mode_label.customContextMenuRequested.connect(self.show_content_mode_menu)
        self.status_bar.addPermanentWidget(self.mode_label)

        self.file_info_label = QLabel("No file loaded")
        self.file_info_label.setStyleSheet("color: #8b8b8b; padding-right: 10px;")
        self.status_bar.addPermanentWidget(self.file_info_label)
        
        # USB drive cache for performance
        self.usb_cache = []
        self.usb_cache_timer = QTimer()
        self.usb_cache_timer.timeout.connect(self.refresh_usb_cache)
        self.usb_cache_timer.start(5000)  # Refresh every 5 seconds
        self.refresh_usb_cache()

        # Menus
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction("&Open", self.open_file).setShortcut("Ctrl+O")
        file_menu.addAction("&Save", self.on_save_triggered).setShortcut("Ctrl+S")
        file_menu.addAction("Save &As", self.save_file).setShortcut("Ctrl+Shift+S")
        file_menu.addAction("&Close", self.close_file).setShortcut("Ctrl+W")
        file_menu.addAction("&Preferences", self.open_preferences_dialog).setShortcut("Ctrl+,")

        edit_menu = self.menuBar().addMenu("&Edit")
        edit_menu.addAction("&Undo", self.editor.undo).setShortcut("Ctrl+Z")
        edit_menu.addAction("&Redo", self.editor.redo).setShortcut("Ctrl+Y")
        edit_menu.addSeparator()
        edit_menu.addAction("Cu&t", self.editor.cut).setShortcut("Ctrl+X")
        edit_menu.addAction("&Copy", self.editor.copy).setShortcut("Ctrl+C")
        edit_menu.addAction("&Paste", self.editor.paste).setShortcut("Ctrl+V")
        edit_menu.addSeparator()
        edit_menu.addAction("Select &All", self.editor.selectAll).setShortcut("Ctrl+A")
        edit_menu.addSeparator()
        edit_menu.addAction("Reset Formatting", self.editor.reset_formatting).setShortcut("Ctrl+Space")
        edit_menu.addAction("Increase Font Size", lambda: self.editor.change_font_size(1)).setShortcut("Ctrl+Shift+>")
        edit_menu.addAction("Decrease Font Size", lambda: self.editor.change_font_size(-1)).setShortcut("Ctrl+Shift+<")

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("&Help", self.open_help_page).setShortcut("F1")
        help_menu.addAction("&Check for Updates", self.open_update_dialog)

        # Style
        self.setStyleSheet("""
            QMainWindow {{ background-color: #121212; color: #eee; }}
            QTextEdit {{ background-color: #1e1e1e; color: #ddd; font-family: Consolas, monospace; font-size: 14px; }}
            QMenuBar {{ background-color: #222; color: #eee; }}
            QMenu {{ background-color: #222; color: #eee; }}
            QMenu::item:selected {{ background-color: #444; }}
            QPushButton {{ background-color: #333; color: #eee; border-radius: 5px; padding: 5px; }}
            QPushButton:hover {{ background-color: #555; }}
            QLineEdit, QComboBox {{ background-color: #222; color: #eee; border: 1px solid #555; border-radius: 3px; padding: 3px; }}
        """)

        self.editor.set_content_mode(False)

        # Hidden label when editor is hidden
        self.hidden_label = QLabel(
            "", self
        )
        self.hidden_label.setStyleSheet(f"""
            color: {TEXT_COLOR};
            background-color: {DARKER_BG};
            font-size: 13px;
            padding: 12px 14px;
            border: 1.5px solid {PURPLE};
            border-radius: 6px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        """)
        self.hidden_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hidden_label.hide()
        self.hidden_label.setGeometry(50, 50, 700, 100)
        self.hidden_label.mousePressEvent = self.on_hidden_label_clicked

        # Autosave timer
        self.autosave_timer = QTimer(singleShot=True)
        self.autosave_timer.setInterval(1000)
        self.autosave_timer.timeout.connect(self.autosave)
        self.editor.textChanged.connect(lambda: self.autosave_timer.start())
        self.editor.textChanged.connect(self._on_editor_activity)

        # Idle timer to clear secrets from memory
        self.secret_idle_timer = QTimer(singleShot=True)
        self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
        self.secret_idle_timer.timeout.connect(self._on_infocus_inactivity_timeout)

        # Focus cooldown timer for screen recording hide
        self.cooldown_timer = QTimer()
        self.cooldown_timer.setInterval(1000)
        self.cooldown_timer.timeout.connect(self.update_cooldown)
        self.cooldown_remaining = 0
        self.allow_editor_activation = True

        # Tab setting from preferences
        self.editor.tab_setting = PangPreferences.tab_setting

        # Screen recording checker in thread
        self.screen_recorder_thread = QThread()
        self.screen_recorder_checker = ScreenRecordingChecker()
        self.screen_recorder_checker.moveToThread(self.screen_recorder_thread)
        self.screen_recorder_thread.started.connect(self.screen_recorder_checker.run)
        self.screen_recorder_checker.screen_recording_changed.connect(self.on_screen_recording_changed)
        self.screen_recorder_thread.start()

        self.mem_guard_thread = None
        self.mem_guard_checker = None
        self._configure_mem_guard()
        self._warn_secret_cache_limit()

        # Track window focus
        self.installEventFilter(self)
    
    def open_help_page(self):
        webopen("https://www.panghq.com/tools/pangcrypter/help")

    def open_update_dialog(self):
        """Open the update dialog."""
        try:
            dialog = UpdateDialog(self)
            dialog.exec()
        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to open update dialog: {e}")
            PangMessageBox.critical(self, "Update Error", f"Failed to open update dialog:\n{e}")
    
    def on_save_triggered(self):
        if self.saved_file_path is None:
            # No file open: prompt Save As
            self.save_file()
        else:
            # File is open: autosave instead
            self.autosave()

    def open_preferences_dialog(self):
        dlg = PreferencesDialog(self)
        if dlg.exec():
            # Preferences were saved by dlg.accept()
            # Just update the editor with the new setting
            self.editor.set_tab_setting(PangPreferences.tab_setting)
            self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
            self._configure_mem_guard()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.WindowActivate:
            self._apply_focus_reauth_policy()
            if PangPreferences.screen_recording_hide_enabled and not self.allow_editor_activation:
                self.cooldown_remaining = PangPreferences.recording_cooldown
                self.update_hidden_label_for_cooldown()
                self.cooldown_timer.start()
            return False
        elif event.type() == QEvent.Type.WindowDeactivate:
            if PangPreferences.screen_recording_hide_enabled:
                self.cooldown_timer.stop()
            if PangPreferences.session_cache_enabled and PangPreferences.session_reauth_on_focus_loss:
                self._focus_lost_at = monotonic()
            return False
        return super().eventFilter(obj, event)
    
    def update_cooldown(self):
        self.cooldown_remaining -= 1
        if self.cooldown_remaining <= 0:
            self.allow_editor_activation = True
            self.cooldown_timer.stop()
            self.hidden_label.setText(
                "Screen recording program detected.\n"
                "Make sure to close this window before recording.\n"
                "Click here to restore editor."
            )
        else:
            self.update_hidden_label_for_cooldown()
    
    def update_hidden_label_for_cooldown(self):
        self.hidden_label.setText(
            f"Screen recording program detected.\n"
            f"Make sure to close this window before recording.\n"
            f"Keep this window focused for {self.cooldown_remaining} seconds to restore editor."
        )
    
    def on_screen_recording_changed(self, is_recording):
        self.allow_editor_activation = not is_recording
        if is_recording:
            self.hide_editor_and_show_label()
        elif self.hidden_label.isVisible():
            self.try_restore_editor()
    
    def on_editor_focus_lost(self):
        if not PangPreferences.tab_out_hide_enabled:
            return
        
        active_window = QApplication.activeWindow()

        if active_window is None or not (active_window == self or self.isAncestorOf(active_window)):
            self.hidden_label.setText("Editor hidden due to focus loss. Click here to restore editor.")
            self.hide_editor_and_show_label()

        self._apply_focus_reauth_policy()
    
    def hide_editor_and_show_label(self):
        self.editor.hide()
        self.editor.setDisabled(True)
        self.hidden_label.show()
    
    def try_restore_editor(self):
        if not self.allow_editor_activation:
            return False

        self.editor.setDisabled(False)        
        self.hidden_label.hide()
        self.editor.show()
        self.editor.setFocus()
        return True

    def on_hidden_label_clicked(self, event):
        self.try_restore_editor()

    def check_focus_time(self):
        if not hasattr(self, "focus_timer"):
            return
        if self.focus_timer.isValid():
            elapsed_sec = self.focus_timer.elapsed() / 1000
            if elapsed_sec >= PangPreferences.recording_cooldown:
                self.allow_editor_activation = True
                self.try_restore_editor()

    def refresh_usb_cache(self):
        """Refresh the USB drive cache for better performance."""
        try:
            self.usb_cache = list_usb_drives()
            logger.debug(f"USB cache refreshed: {len(self.usb_cache)} drives found")
        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Failed to refresh USB cache: {e}")
            self.usb_cache = []

    def validate_file_path(self, path: str) -> bool:
        """Validate file path for security and correctness."""
        if not path:
            raise ValidationError("File path cannot be empty")
        
        if not isinstance(path, str):
            raise ValidationError("File path must be a string")
        
        normalized = os.path.abspath(path)
        if os.path.isdir(normalized):
            raise ValidationError("Path points to a directory, expected an .enc file")
        
        # Check file extension
        if not normalized.lower().endswith('.enc'):
            raise ValidationError("File must have .enc extension")
        
        return True

    def validate_password(self, password: str) -> bool:
        """Validate password strength and format."""
        if not password:
            raise ValidationError("Password cannot be empty")
        
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        
        # Check for basic complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        if not (has_upper and has_lower and has_digit):
            logger.warning("Password does not meet complexity requirements")
            return False

        return True

    def confirm_weak_password(self) -> bool:
        ret = PangMessageBox.question(
            self,
            "Weak Password",
            "The password does not meet complexity requirements. Continue anyway?",
            buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
            default=PangMessageBox.StandardButton.No,
        )
        return ret == PangMessageBox.StandardButton.Yes

    def show_progress(self, message: str, maximum: int = 0):
        """Show progress bar with message."""
        self.status_bar.showMessage(message)
        self.progress_bar.setVisible(True)
        if maximum > 0:
            self.progress_bar.setMaximum(maximum)
            self.progress_bar.setValue(0)
        else:
            self.progress_bar.setRange(0, 0)  # Indeterminate progress

    def hide_progress(self):
        """Hide progress bar and clear status message."""
        self.progress_bar.setVisible(False)
        self.status_bar.clearMessage()

    def update_progress(self, value: int):
        """Update progress bar value."""
        self.progress_bar.setValue(value)

    def on_text_changed(self):
        self.autosave_timer.start()  # reset timer on each key press

    def _on_editor_activity(self):
        self._last_editor_activity_at = monotonic()
        if PangPreferences.session_cache_enabled and (self.cached_password is not None or self.cached_usb_key is not None):
            self.reset_secret_idle_timer()

    def _effective_secret_cache_idle_minutes(self) -> int:
        configured = int(getattr(PangPreferences, "session_infocus_inactivity_minutes", self.DEFAULT_SECRET_CACHE_IDLE_MINUTES))
        return max(1, min(configured, self.MAX_SECRET_CACHE_IDLE_MINUTES))

    def _warn_secret_cache_limit(self) -> None:
        if not PangPreferences.session_cache_enabled or self._secret_cache_notice_logged:
            return
        logger.warning(
            "Session secret caching uses best-effort obfuscation only and is limited to %s minutes of in-focus inactivity.",
            self._effective_secret_cache_idle_minutes(),
        )
        self._secret_cache_notice_logged = True

    def _on_infocus_inactivity_timeout(self):
        if not PangPreferences.session_cache_enabled:
            return
        if not PangPreferences.session_infocus_inactivity_reauth_enabled:
            return
        self.clear_cached_secrets()

    def autosave(self):
        """Autosave with improved error handling and logging."""
        if not self.operation_mutex.tryLock():
            logger.debug("Autosave skipped - operation in progress")
            return
        
        try:
            # To avoid lag, autosave only if we have keys cached:
            if self.cached_password is None and self.cached_usb_key is None:
                return
            
            # Only autosave if file is already saved
            if not self.saved_file_path:
                return
            
            if self.cached_uuid is None:
                logger.error("Autosave failed - no UUID cached")
                return
            
            logger.debug(f"Autosaving to {self.saved_file_path}")
            
            # Encrypt current editor content
            password_bytes = self._get_cached_password_bytes()
            usb_key = self._get_cached_usb_key()
            encrypt_file(
                self._serialize_editor_content(),
                self.saved_file_path,
                self.current_mode,
                self.cached_uuid,
                password=password_bytes,
                usb_key=bytes(usb_key) if usb_key else None,
                content_mode=self.current_content_mode,
            )
            self._clear_temporary_bytes(password_bytes)
            self._clear_temporary_bytes(usb_key)
            self.reset_secret_idle_timer()
            logger.info(f"Autosaved encrypted file to {self.saved_file_path}")
            
        except CryptographyError as e:
            logger.error(f"Cryptography error during autosave: {e}")
            PangMessageBox.warning(self, "Autosave failed", f"Encryption error: {e}")
        except (ValueError, TypeError, OSError, RuntimeError) as e:
            logger.error(f"Unexpected error during autosave: {e}")
            PangMessageBox.warning(self, "Autosave failed", f"Could not autosave encrypted file:\n{e}")
        finally:
            self.operation_mutex.unlock()

    def check_usb_present(self) -> Optional[List[str]]:
        """Check for USB drives with caching and better error handling."""
        try:
            # Use cached USB drives if available and recent
            if self.usb_cache:
                return self.usb_cache
            
            # Fallback to direct detection
            usbs = list_usb_drives()
            if not usbs:
                PangMessageBox.warning(
                    self, 
                    "No USB Drives", 
                    "No USB drives detected. Please plug in your USB key and try again."
                )
                return None
            return usbs
            
        except (OSError, RuntimeError, ValueError) as e:
            logger.error(f"Error detecting USB drives: {e}")
            PangMessageBox.critical(
                self,
                "USB Detection Error",
                f"Failed to detect USB drives: {e}"
            )
            return None

    def save_file(self):
        """Save file with enhanced validation and progress indication."""
        if not self.operation_mutex.tryLock():
            PangMessageBox.warning(self, "Operation in Progress", "Another operation is in progress. Please wait.")
            return
        
        try:
            self.show_progress("Preparing to save file...")
            
            # Check USB drives
            usbs = self.check_usb_present()

            # Get encryption mode
            dlg = EncryptModeDialog(self)
            if not dlg.exec_():
                return

            mode = EncryptModeType(dlg.mode)
            logger.info(f"Selected encryption mode: {mode}")

            # Get password if needed
            password_bytes = None
            if mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
                pwd_dlg = PasswordDialog(self, warning=False)
                if not pwd_dlg.exec_():
                    return
                password_text = pwd_dlg.password
                
                # Validate password
                try:
                    is_strong = self.validate_password(password_text)
                except ValidationError as e:
                    PangMessageBox.warning(self, "Password Validation", str(e))
                    return

                if not is_strong and not self.confirm_weak_password():
                    return

                password_bytes = bytearray(password_text.encode("utf-8"))
                password_text = None

            # Get USB key if needed
            random_key = None
            selected_usb_path = None
            if mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                if not usbs:
                    return

                usb_dlg = USBSelectDialog(usbs, self)
                if not usb_dlg.exec_():
                    return

                selected_usb_path = usb_dlg.selected_usb
                logger.info(f"Selected USB drive: {selected_usb_path}")

            # Get save path
            path, _ = QFileDialog.getSaveFileName(
                self, 
                "Save encrypted file", 
                filter="Encrypted Files (*.enc)"
            )
            if not path:
                return
            
            # Validate file path
            try:
                self.validate_file_path(path)
            except ValidationError as e:
                PangMessageBox.critical(self, "Invalid File Path", str(e))
                return
            
            # Check if file exists
            if os.path.exists(path):
                ret = PangMessageBox.question(
                    self,
                    "File Exists",
                    f"The file '{os.path.basename(path)}' already exists. Do you want to overwrite it?",
                    buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                    default=PangMessageBox.StandardButton.No
                )
                if ret == PangMessageBox.StandardButton.No:
                    return
            
            self.update_progress(25)
            self.status_bar.showMessage("Generating encryption keys...")
            
            # Generate UUID
            file_uuid = uuid4()

            # Create or load USB key if needed
            if mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                try:
                    random_key, _ = create_or_load_key(selected_usb_path, path, file_uuid)
                    logger.info("USB key created/loaded successfully")
                except (ValueError, OSError, RuntimeError) as e:
                    logger.error(f"Failed to create/load USB key: {e}")
                    raise USBKeyError(f"Failed to create USB key: {e}")

            self.update_progress(50)
            self.status_bar.showMessage("Encrypting file...")

            # Encrypt and save
            try:
                content = self._serialize_editor_content()
                encrypt_file(
                    content,
                    path,
                    mode,
                    file_uuid,
                    password=password_bytes,
                    usb_key=random_key,
                    content_mode=self.current_content_mode
                )
                logger.info(f"File encrypted and saved to {path}")
                
            except (ValueError, TypeError, OSError, RuntimeError) as e:
                logger.error(f"Encryption failed: {e}")
                raise CryptographyError(f"Failed to encrypt file: {e}")

            self.update_progress(100)
            
            # Update application state
            self.saved_file_path = path
            self.update_window_title(self.saved_file_path)
            self.current_mode = mode
            self.header_version = HEADER_VERSION
            self.cached_uuid = file_uuid
            if PangPreferences.session_cache_enabled:
                if password_bytes:
                    self.cached_password = self._obfuscate_secret(password_bytes)
                    self._clear_temporary_bytes(password_bytes)
                else:
                    self.cached_password = None

                if random_key:
                    key_bytes = bytearray(random_key)
                    self.cached_usb_key = self._obfuscate_secret(key_bytes)
                    self._clear_temporary_bytes(key_bytes)
                    random_key = None
                else:
                    self.cached_usb_key = None
                self.reset_secret_idle_timer()
            else:
                self.clear_cached_secrets()
            self._clear_temporary_bytes(password_bytes)

            self.status_bar.showMessage("File saved successfully", 3000)
            PangMessageBox.information(self, "Success", "File saved successfully.")
            
        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            PangMessageBox.critical(self, "Validation Error", str(e))
        except CryptographyError as e:
            logger.error(f"Cryptography error: {e}")
            PangMessageBox.critical(self, "Encryption Error", str(e))
        except USBKeyError as e:
            logger.error(f"USB key error: {e}")
            PangMessageBox.critical(self, "USB Key Error", str(e))
        except (OSError, RuntimeError, ValueError, TypeError) as e:
            logger.error(f"Unexpected error during save: {e}")
            PangMessageBox.critical(self, "Save Failed", f"An unexpected error occurred:\n{e}")
        finally:
            self.hide_progress()
            self.operation_mutex.unlock()

    def best_effort_clear_memory(self, data: bytes | bytearray | None) -> None:
        """Best-effort clearing for sensitive data in memory.

        Note: immutable bytes/str values cannot be reliably wiped in CPython.
        """
        if data is None:
            return

        try:
            if isinstance(data, bytearray):
                for i in range(len(data)):
                    data[i] = 0
                return

            logger.debug("Best-effort clear requested for immutable object; cannot guarantee wipe")
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to securely clear memory: {e}")

    def open_file(self, path: str | None = None):
        """Open file with enhanced validation, progress indication, and security."""
        if not self.operation_mutex.tryLock():
            PangMessageBox.warning(self, "Operation in Progress", "Another operation is in progress. Please wait.")
            return
        
        try:
            self.show_progress("Opening file...")
            
            # Get file path if not provided
            if not path:
                path, _ = QFileDialog.getOpenFileName(
                    self, 
                    "Open encrypted file", 
                    filter="Encrypted Files (*.enc)"
                )
                if not path:
                    return

            # Validate file path
            try:
                self.validate_file_path(path)
            except ValidationError as e:
                PangMessageBox.critical(self, "Invalid File Path", str(e))
                return

            # Check file exists and is readable
            if not os.path.exists(path):
                PangMessageBox.critical(self, "File Not Found", f"The file '{path}' does not exist.")
                return
            
            if not os.access(path, os.R_OK):
                PangMessageBox.critical(self, "Access Denied", f"Cannot read file '{path}'. Check permissions.")
                return

            self.update_progress(10)
            self.status_bar.showMessage("Reading file header...")

            # Read and validate file header
            file_uuid = None
            try:
                with open(path, "rb") as f:
                    settings = f.read(SETTINGS_SIZE)
                    if len(settings) != SETTINGS_SIZE:
                        raise ValidationError("File is empty or invalid")

                    _salt = f.read(16)
                    file_uuid_bytes = f.read(16)
                    if len(file_uuid_bytes) != 16:
                        raise ValidationError("Invalid file UUID in header")
                    file_uuid = UUID(bytes=file_uuid_bytes)

                    header_version = decode_version(settings[0:2])
                    if header_version != HEADER_VERSION:
                        raise ValidationError(f"Unsupported file version: {header_version}")

                    mode_byte = settings[2]
                    try:
                        mode = EncryptModeType(mode_byte)
                    except ValueError:
                        raise ValidationError(f"Unknown encryption mode: {mode_byte}")

                    if mode not in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                        raise ValidationError(f"Unsupported encryption mode: {mode}")

                    content_mode = settings[CONTENT_MODE_OFFSET]
                    if content_mode not in (CONTENT_MODE_PLAINTEXT, CONTENT_MODE_HTML):
                        raise ValidationError("Unsupported content mode in file header")

                    self.header_version = header_version
                    self.current_content_mode = content_mode
                    self.editor.set_content_mode(content_mode == CONTENT_MODE_HTML)
                    logger.info(f"File uses encryption mode: {mode}")
                    
            except ValidationError as e:
                PangMessageBox.critical(self, "Invalid File Format", str(e))
                return
            except (OSError, ValueError, RuntimeError) as e:
                logger.error(f"Failed to read file header: {e}")
                PangMessageBox.critical(self, "File Read Error", f"Failed to read file: {e}")
                return

            self.update_progress(25)
            
            # Get credentials based on encryption mode
            password_bytes = None
            random_key = None
            opened_header_uuid = file_uuid

            # Get password if needed
            if mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
                self.status_bar.showMessage("Waiting for password...")
                pwd_dlg = PasswordDialog(self, warning=False)
                if not pwd_dlg.exec_():
                    return
                password_text = pwd_dlg.password
                password_bytes = bytearray(password_text.encode("utf-8"))
                password_text = None
                logger.debug("Password provided for decryption")

            self.update_progress(40)

            # Get USB key if needed
            if mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                self.status_bar.showMessage("Loading USB key...")
                usbs = self.check_usb_present()
                if not usbs:
                    return
                    
                usb_dlg = USBSelectDialog(usbs, self)
                if not usb_dlg.exec_():
                    return

                selected_usb_path = usb_dlg.selected_usb
                logger.info(f"Selected USB drive: {selected_usb_path}")

                try:
                    random_key, loaded_uuid = create_or_load_key(selected_usb_path, path, create=False)
                    if loaded_uuid is not None:
                        file_uuid = loaded_uuid
                    logger.info("USB key loaded successfully")
                except (ValueError, OSError, RuntimeError) as e:
                    logger.error(f"Failed to load USB key: {e}")
                    raise USBKeyError(f"Failed to load USB key: {e}")

            if file_uuid is None:
                file_uuid = opened_header_uuid

            self.update_progress(60)
            self.status_bar.showMessage("Decrypting file...")

            # Decrypt file
            try:
                plaintext = decrypt_file(path, password=password_bytes, usb_key=random_key)
                logger.info(f"File decrypted successfully: {len(plaintext)} bytes")
                
            except (ValueError, TypeError, OSError, RuntimeError) as e:
                logger.error(f"Decryption failed: {e}")
                raise CryptographyError(f"Failed to decrypt file: {e}")

            self.update_progress(80)
            self.status_bar.showMessage("Loading content...")

            # Load content into editor
            try:
                content_str = plaintext.decode("utf-8")
                self._load_editor_content(content_str)
                
                # Securely clear plaintext from memory
                self.best_effort_clear_memory(plaintext)
                
            except UnicodeDecodeError as e:
                logger.error(f"Failed to decode file content: {e}")
                PangMessageBox.critical(
                    self, 
                    "Content Error", 
                    "Failed to decode file content. The file may be corrupted or use an unsupported encoding."
                )
                return

            self.update_progress(100)

            # Update application state
            self.saved_file_path = path
            self.update_window_title(self.saved_file_path)
            self.current_mode = mode
            self.cached_uuid = file_uuid
            if PangPreferences.session_cache_enabled:
                if password_bytes:
                    self.cached_password = self._obfuscate_secret(password_bytes)
                    self._clear_temporary_bytes(password_bytes)
                else:
                    self.cached_password = None

                if random_key:
                    key_bytes = bytearray(random_key)
                    self.cached_usb_key = self._obfuscate_secret(key_bytes)
                    self._clear_temporary_bytes(key_bytes)
                    random_key = None
                else:
                    self.cached_usb_key = None
                self.reset_secret_idle_timer()
            else:
                self.clear_cached_secrets()
            self._clear_temporary_bytes(password_bytes)

            self.status_bar.showMessage("File opened successfully", 3000)
            PangMessageBox.information(self, "Success", "File opened successfully.")
            logger.info(f"File opened successfully: {path}")
            self.update_file_info_label()
            
        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            PangMessageBox.critical(self, "Validation Error", str(e))
        except CryptographyError as e:
            logger.error(f"Cryptography error: {e}")
            PangMessageBox.critical(self, "Decryption Error", str(e))
        except USBKeyError as e:
            logger.error(f"USB key error: {e}")
            PangMessageBox.critical(self, "USB Key Error", str(e))
        except (OSError, RuntimeError, ValueError, TypeError) as e:
            logger.error(f"Unexpected error during file open: {e}")
            PangMessageBox.critical(self, "Open Failed", f"An unexpected error occurred:\n{e}")
        finally:
            self.hide_progress()
            self.operation_mutex.unlock()
    
    def close_file(self):
        content_empty = self.editor.toPlainText().strip() == ""
        if self.saved_file_path is None and content_empty:
            # Nothing to close or clear
            return

        if not content_empty:
            ret = PangMessageBox.question(
                self,
                "Close File",
                "Are you sure you want to close the current file? Unsaved changes will be lost.",
                buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                default=PangMessageBox.StandardButton.No
            )

            if ret == PangMessageBox.StandardButton.No:
                return

        # Clear state and editor
        self.saved_file_path = None
        self.update_window_title(self.saved_file_path)
        self.current_mode = None
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.header_version = HEADER_VERSION
        self.editor.set_content_mode(False)
        self.clear_cached_secrets()
        self.editor.clear()
        self.update_file_info_label()

    def _xor_with_mask(self, data: bytes | bytearray) -> bytearray:
        mask = self._secret_mask
        return bytearray(b ^ mask[i % len(mask)] for i, b in enumerate(bytes(data)))

    def _obfuscate_secret(self, secret: bytes | bytearray) -> bytearray:
        return self._xor_with_mask(secret)

    def _deobfuscate_secret(self, secret: bytearray) -> bytearray:
        return self._xor_with_mask(bytes(secret))

    def _get_cached_password_bytes(self) -> Optional[bytearray]:
        if self.cached_password is None:
            return None
        self.reset_secret_idle_timer()
        secret = self._deobfuscate_secret(self.cached_password)
        return secret

    def _get_cached_usb_key(self) -> Optional[bytearray]:
        if self.cached_usb_key is None:
            return None
        self.reset_secret_idle_timer()
        secret = self._deobfuscate_secret(self.cached_usb_key)
        return secret

    def _clear_temporary_bytes(self, data: Optional[bytearray]) -> None:
        if data is None:
            return
        try:
            self.best_effort_clear_memory(data)
        except (TypeError, ValueError) as e:
            logger.debug(f"Temporary bytes clear failed: {e}")

    def clear_cached_secrets(self):
        self.best_effort_clear_memory(self.cached_password)
        self.best_effort_clear_memory(self.cached_usb_key)
        self.cached_password = None
        self.cached_usb_key = None
        self.cached_uuid = None
        self.secret_idle_timer.stop()

    def _read_file_uuid(self, path: str) -> Optional[UUID]:
        try:
            with open(path, "rb") as f:
                if len(f.read(SETTINGS_SIZE)) != SETTINGS_SIZE:
                    return None
                if len(f.read(16)) != 16:  # salt
                    return None
                uid = f.read(16)
                if len(uid) != 16:
                    return None
                return UUID(bytes=uid)
        except (OSError, ValueError):
            return None

    def reset_secret_idle_timer(self):
        if PangPreferences.session_cache_enabled and PangPreferences.session_infocus_inactivity_reauth_enabled:
            self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
            self.secret_idle_timer.start()
        else:
            self.secret_idle_timer.stop()

    def _apply_focus_reauth_policy(self):
        if not PangPreferences.session_cache_enabled:
            return
        if not PangPreferences.session_reauth_on_focus_loss:
            self._focus_lost_at = None
            return
        if self._focus_lost_at is None:
            return
        elapsed = monotonic() - self._focus_lost_at
        timeout_sec = PangPreferences.session_reauth_minutes * 60
        if elapsed >= timeout_sec:
            self.clear_cached_secrets()
        self._focus_lost_at = None

    def _ensure_mem_guard_self_whitelist(self) -> None:
        """Auto-whitelist the frozen executable to avoid self-detection noise."""
        if not getattr(sys, "frozen", False):
            return

        exe_path = os.path.abspath(sys.executable)
        if not exe_path or not os.path.exists(exe_path):
            return

        digest = file_sha256(exe_path)
        entries = PangPreferences.mem_guard_whitelist
        changed = False

        for item in entries:
            if not isinstance(item, dict):
                continue
            if os.path.normcase(os.path.abspath(str(item.get("path", "")))) != os.path.normcase(exe_path):
                continue

            existing_sha = str(item.get("sha256", "")).strip().lower()
            if digest and existing_sha != digest.lower():
                item["sha256"] = digest.lower()
                changed = True
            return

        entries.append({"path": exe_path, "sha256": digest.lower() if digest else ""})
        changed = True

        if changed:
            PangPreferences.save_preferences()

    def _configure_mem_guard(self):
        if self._mem_guard_disabled_until_restart:
            return
        if not self._stop_mem_guard():
            logger.error("Skipping mem guard reconfiguration because previous worker is still shutting down")
            self._mem_guard_disabled_until_restart = True
            self.status_bar.showMessage("Memory guard disabled until restart (worker did not stop cleanly)", 8000)
            return
        if not PangPreferences.session_cache_enabled:
            return
        if not is_mem_guard_supported():
            return
        mode_value = PangPreferences.mem_guard_mode
        if mode_value == MemGuardMode.OFF.value:
            return

        try:
            mode = MemGuardMode(mode_value)
        except ValueError:
            return

        self._ensure_mem_guard_self_whitelist()

        self.mem_guard_thread = QThread()
        self.mem_guard_checker = MemGuardChecker(
            mode=mode,
            whitelist=PangPreferences.mem_guard_whitelist,
            check_interval_ms=PangPreferences.mem_guard_scan_interval_ms,
            pid_handle_cache_cap=PangPreferences.mem_guard_pid_cache_cap,
        )
        self.mem_guard_checker.moveToThread(self.mem_guard_thread)
        self.mem_guard_thread.started.connect(self.mem_guard_checker.run)
        self.mem_guard_checker.memory_probe_detected.connect(self.on_memory_probe_detected)
        self.mem_guard_thread.start()

    def _stop_mem_guard(self) -> bool:
        if self.mem_guard_checker is not None:
            self.mem_guard_checker.stop()
        if self.mem_guard_thread is not None:
            self.mem_guard_thread.quit()
            if not self.mem_guard_thread.wait(5000):
                logger.error("Mem guard thread did not stop gracefully; terminate() is disabled for safety")
                return False
        self.mem_guard_checker = None
        self.mem_guard_thread = None
        return True

    def _panic_path(self) -> Optional[str]:
        if not self.saved_file_path:
            return None
        return f"{self.saved_file_path}.panic.enc"

    def _panic_meta_path(self) -> Optional[str]:
        panic = self._panic_path()
        if not panic:
            return None
        return f"{panic}.meta"

    def _create_panic_snapshot(self) -> bool:
        panic_path = self._panic_path()
        if not panic_path or self.cached_uuid is None or self.current_mode is None:
            return False

        password_bytes = self._get_cached_password_bytes()
        usb_key = self._get_cached_usb_key()
        try:
            content = self._serialize_editor_content()
            encrypt_file(
                content,
                panic_path,
                self.current_mode,
                self.cached_uuid,
                password=password_bytes,
                usb_key=bytes(usb_key) if usb_key else None,
                content_mode=self.current_content_mode,
            )
            meta_path = self._panic_meta_path()
            if meta_path:
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump({"saved_at": datetime.now(timezone.utc).isoformat()}, f, indent=2)
            self._panic_recovery_path = panic_path
            return True
        except (ValueError, TypeError, OSError, RuntimeError):
            # Offer save-as fallback for panic snapshot
            fallback_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save panic snapshot as...",
                filter="Encrypted Files (*.enc)",
            )
            if not fallback_path:
                return False
            try:
                encrypt_file(
                    content,
                    fallback_path,
                    self.current_mode,
                    self.cached_uuid,
                    password=password_bytes,
                    usb_key=bytes(usb_key) if usb_key else None,
                    content_mode=self.current_content_mode,
                )
                self._panic_recovery_path = fallback_path
                return True
            except (ValueError, TypeError, OSError, RuntimeError):
                return False
        finally:
            self._clear_temporary_bytes(password_bytes)
            self._clear_temporary_bytes(usb_key)

    def _restore_from_panic_snapshot(self) -> bool:
        path = self._panic_recovery_path or self._panic_path()
        if not path or not os.path.exists(path) or self.current_mode is None:
            return False

        password_bytes = None
        usb_key = None
        try:
            if self.current_mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
                pwd_dlg = PasswordDialog(self)
                if not pwd_dlg.exec_():
                    return False
                password_bytes = bytearray(pwd_dlg.password.encode("utf-8"))

            if self.current_mode in [MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                usbs = self.check_usb_present()
                if not usbs:
                    return False
                usb_dlg = USBSelectDialog(usbs, self)
                if not usb_dlg.exec_():
                    return False
                selected_usb_path = usb_dlg.selected_usb
                usb_key, _ = create_or_load_key(selected_usb_path, self.saved_file_path or path, create=False)

            plaintext = decrypt_file(path, password=password_bytes, usb_key=usb_key)
            content_str = plaintext.decode("utf-8")
            self._load_editor_content(content_str)
            self.best_effort_clear_memory(plaintext)

            panic_uuid = self._read_file_uuid(path)
            if panic_uuid is not None:
                self.cached_uuid = panic_uuid

            if PangPreferences.session_cache_enabled:
                self.cached_password = self._obfuscate_secret(password_bytes) if password_bytes else None
                if usb_key:
                    key_bytes = bytearray(usb_key)
                    self.cached_usb_key = self._obfuscate_secret(key_bytes)
                    self._clear_temporary_bytes(key_bytes)
                else:
                    self.cached_usb_key = None
                self.reset_secret_idle_timer()

            if PangPreferences.auto_delete_panic_files:
                try:
                    os.remove(path)
                except OSError:
                    pass
                meta_path = self._panic_meta_path()
                if meta_path:
                    try:
                        os.remove(meta_path)
                    except OSError:
                        pass
            return True
        except (ValueError, TypeError, OSError, RuntimeError, UnicodeDecodeError):
            return False
        finally:
            self._clear_temporary_bytes(password_bytes)
            if isinstance(usb_key, bytearray):
                self._clear_temporary_bytes(usb_key)

    def _enqueue_mem_guard_finding(self, finding: MemGuardFinding) -> None:
        key = (
            int(finding.pid),
            finding.severity.value,
            int(finding.access_mask),
            finding.process_path or "",
        )
        if key in self._pending_mem_guard_keys:
            return
        self._pending_mem_guard_keys.add(key)
        self._pending_mem_guard_findings.append(finding)

    def _process_next_mem_guard_finding(self) -> None:
        if self._mem_guard_handling or not self._pending_mem_guard_findings:
            return

        finding = self._pending_mem_guard_findings.pop(0)
        key = (
            int(finding.pid),
            finding.severity.value,
            int(finding.access_mask),
            finding.process_path or "",
        )
        self._pending_mem_guard_keys.discard(key)

        self._mem_guard_handling = True
        try:
            panic_saved = self._create_panic_snapshot()
            self.clear_cached_secrets()
            self.editor.clear()
            self.hide_editor_and_show_label()

            msg = PangMessageBox(self)
            msg.setWindowTitle("Memory Access Warning")
            details = (
                f"Process \"{finding.process_name}\" (PID {finding.pid}) appears to be reading process memory.\n\n"
                "If this is expected behaviour (for example anti-cheat/EDR), you can continue.\n"
            )
            if not panic_saved:
                details += "\nWarning: could not save panic snapshot, unsaved work may be lost."
            msg.setText(details)
            msg.addButton("Continue", QMessageBox.ButtonRole.AcceptRole)
            whitelist_btn = msg.addButton("Continue + whitelist application", QMessageBox.ButtonRole.AcceptRole)
            exit_btn = msg.addButton("Exit program", QMessageBox.ButtonRole.DestructiveRole)
            msg.setMinimumWidth(640)
            msg.adjustSize()
            for btn in msg.buttons():
                btn.setMinimumWidth(190)
            msg.exec()

            clicked = msg.clickedButton()
            if clicked == exit_btn:
                self.close()
                return

            confirm = PangMessageBox.question(
                self,
                "Risk Confirmation",
                "I understand the risks and want to continue.",
                buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                default=PangMessageBox.StandardButton.No,
            )
            if confirm != PangMessageBox.StandardButton.Yes:
                self.close()
                return

            if clicked == whitelist_btn and finding.process_path:
                current_entries = PangPreferences.mem_guard_whitelist
                exists = False
                for item in current_entries:
                    if isinstance(item, dict) and item.get("path") == finding.process_path and str(item.get("sha256", "")).lower() == finding.sha256.lower():
                        exists = True
                        break
                if not exists:
                    PangPreferences.mem_guard_whitelist.append(
                        {
                            "path": finding.process_path,
                            "sha256": finding.sha256,
                        }
                    )
                    PangPreferences.save_preferences()
                    self._configure_mem_guard()

            if panic_saved:
                restored = self._restore_from_panic_snapshot()
                if not restored:
                    PangMessageBox.warning(self, "Restore Failed", "Could not restore panic snapshot. Re-open file manually.")
            self.try_restore_editor()
        finally:
            self._mem_guard_handling = False
            if self._pending_mem_guard_findings:
                QTimer.singleShot(0, self._process_next_mem_guard_finding)

    def on_memory_probe_detected(self, finding: MemGuardFinding):
        self._enqueue_mem_guard_finding(finding)
        self._process_next_mem_guard_finding()

    def closeEvent(self, event):
        self._stop_mem_guard()
        if self.screen_recorder_checker is not None:
            self.screen_recorder_checker.stop()
        if self.screen_recorder_thread is not None:
            self.screen_recorder_thread.quit()
            self.screen_recorder_thread.wait(1500)
        super().closeEvent(event)

    def show_content_mode_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu { background-color: #222; color: #eee; border: 1px solid #6B21A8; }
            QMenu::item:selected { background-color: #581C87; }
        """)

        if self.current_content_mode == CONTENT_MODE_PLAINTEXT:
            menu.addAction("Convert to HTML", self.convert_plaintext_to_html)
        else:
            menu.addAction("Convert to plaintext + keep HTML", self.convert_html_to_plaintext_keep_html)
            menu.addAction("Convert to plaintext (discard HTML)", self.convert_html_to_plaintext_discard_html)

        menu.exec(self.mode_label.mapToGlobal(pos))

    def convert_plaintext_to_html(self):
        plaintext = self.editor.toPlainText()
        self.editor.setHtml(plaintext)
        # Reformat/normalize through Qt's document pipeline
        normalized = self.editor.toHtml()
        self.editor.setHtml(normalized)
        self.current_content_mode = CONTENT_MODE_HTML
        self.editor.set_content_mode(True)
        self.update_file_info_label()

    def convert_html_to_plaintext_keep_html(self):
        html = self.editor.toHtml()
        normalized = html.replace("\r\n", "\n").replace("\r", "\n")
        self.editor.setPlainText(normalized)
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.editor.set_content_mode(False)
        self.update_file_info_label()

    def convert_html_to_plaintext_discard_html(self):
        text = self.editor.toPlainText()
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        self.editor.setPlainText(normalized)
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.editor.set_content_mode(False)
        self.update_file_info_label()

    def _serialize_editor_content(self) -> bytes:
        if self.current_content_mode == CONTENT_MODE_HTML:
            return self.editor.toHtml().encode("utf-8")
        return self.editor.toPlainText().encode("utf-8")

    def _load_editor_content(self, content: str) -> None:
        if self.current_content_mode == CONTENT_MODE_HTML:
            self.editor.setHtml(content)
            self.editor.set_content_mode(True)
        else:
            self.editor.setPlainText(content)
            self.editor.set_content_mode(False)

    def update_file_info_label(self):
        mode_label = "Plaintext" if self.current_content_mode == CONTENT_MODE_PLAINTEXT else "HTML"
        self.mode_label.setText(f"{mode_label} mode")
        if not self.saved_file_path:
            self.file_info_label.setText("No file loaded")
            return
        enc_mode = self.current_mode.name if self.current_mode else "Unknown"
        self.file_info_label.setText(
            f"Format v{self.header_version} | {enc_mode} | {mode_label}"
        )
    
    def update_window_title(self, filename: str | None):
        base_title = "PangCrypter"
        if filename:
            # Remove .enc extension if present
            name_without_ext = os.path.splitext(os.path.basename(filename))[0]
            self.setWindowTitle(f"Editing {name_without_ext} - {base_title}")
        else:
            self.setWindowTitle(base_title)

        self.update_file_info_label()

def main():
    parser = argparse.ArgumentParser(description="PangCrypter")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args, remaining = parser.parse_known_args()

    configure_logging(args.debug)

    app = QApplication([sys.argv[0]] + remaining)
    app.setStyle("Fusion")
    win = MainWindow()

    # If there's an argument, try opening it
    if len(sys.argv) > 1:
        file_arg = sys.argv[1]
        if os.path.isfile(file_arg) and file_arg.lower().endswith(".enc"):
            try:
                win.open_file(file_arg)
            except (OSError, RuntimeError, ValueError) as e:
                print(f"Failed to open {file_arg}: {e}")

    win.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
