import sys
import os
import logging
import argparse
from time import monotonic
from typing import Optional, List, Any
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
from .core.format_config import (
    SETTINGS_SIZE,
    CONTENT_MODE_OFFSET,
    CONTENT_MODE_PLAINTEXT,
    CONTENT_MODE_HTML,
    HEADER_VERSION,
    decode_version,
)
from .core.document_service import DocumentService
from .core.session_state import SessionState
from .core.preferences_proxy import PreferencesDialog, PangPreferences
from .core.update_dialog_loader import update_dialog_loader
from .core.privacy_guard_controller import PrivacyGuardController
from .ui.messagebox import PangMessageBox

from .utils.app_style import apply_app_stylesheet
from .utils.logger import configure_logging, enable_deferred_file_logging

from uuid import uuid4, UUID

logger = logging.getLogger(__name__)


def is_mem_guard_supported() -> bool:
    """Compatibility shim for legacy tests/patch points."""
    try:
        from .utils.mem_guard import is_mem_guard_supported as _is_supported
        return bool(_is_supported())
    except (ImportError, OSError, RuntimeError, ValueError):
        return False

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
        self._init_window_shell()
        self._init_state_and_services()
        self._init_editor()
        self._init_status_bar()
        self._init_hidden_label()
        self._init_timer_placeholders()
        self._init_runtime_threads()
        self._init_deferred_startup()
        self.installEventFilter(self)

    def _init_window_shell(self):
        self.setWindowTitle("PangCrypter Editor")
        self.setWindowIcon(QIcon("ui/logo.ico"))
        self.resize(800, 600)

    def _init_state_and_services(self):
        self.session_state = SessionState()
        self.document_service = DocumentService()
        self.privacy_guard = PrivacyGuardController(self, PangPreferences)
        self.panic_recovery = None
        self.saved_file_path = None
        self.current_mode = None
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.header_version = HEADER_VERSION
        self._mem_guard_handling = False
        self._pending_mem_guard_findings: list[Any] = []
        self._pending_mem_guard_keys: set[tuple[int, str, int, str]] = set()
        self._last_editor_activity_at: float = monotonic()
        self.operation_mutex = QMutex()
        self.mem_guard_controller = None

    def _ensure_mem_guard_controller(self):
        if self.mem_guard_controller is None:
            from .core.mem_guard_controller import MemGuardController
            self.mem_guard_controller = MemGuardController(self, PangPreferences, logger)
        return self.mem_guard_controller

    def _ensure_panic_recovery_service(self):
        if self.panic_recovery is not None:
            return self.panic_recovery
        from .core.panic_recovery_service import PanicRecoveryService
        self.panic_recovery = PanicRecoveryService(self, PangPreferences)
        return self.panic_recovery

    # Legacy compatibility methods retained for tests.
    def _stop_mem_guard(self) -> bool:
        checker = getattr(self, "mem_guard_checker", None)
        thread = getattr(self, "mem_guard_thread", None)

        if checker is not None:
            checker.stop()
        if thread is not None:
            thread.quit()
            if not thread.wait(5000):
                return False

        self.mem_guard_checker = None
        self.mem_guard_thread = None
        return True

    def _configure_mem_guard(self):
        disabled = bool(getattr(self, "_mem_guard_disabled_until_restart", False))
        if disabled:
            return
        if not getattr(PangPreferences, "session_cache_enabled", False):
            return
        if not is_mem_guard_supported():
            return
        if str(getattr(PangPreferences, "mem_guard_mode", "off")).lower() == "off":
            return

        if not self._stop_mem_guard():
            self._mem_guard_disabled_until_restart = True
            if getattr(self, "status_bar", None) is not None:
                self.status_bar.showMessage("Memory guard disabled until restart (worker did not stop cleanly)", 8000)

    def _init_editor(self):
        self.editor = EditorWidget(tab_setting=PangPreferences.tab_setting)
        self.setCentralWidget(self.editor)
        self.editor.focusLost.connect(self.privacy_guard.on_editor_focus_lost)
        self.editor.set_content_mode(False)

    def _init_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        self.mode_label = QLabel("Plaintext mode")
        self.mode_label.setObjectName("StatusMetaLabel")
        self.mode_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.mode_label.customContextMenuRequested.connect(self.show_content_mode_menu)
        self.status_bar.addPermanentWidget(self.mode_label)

        self.file_info_label = QLabel("No file loaded")
        self.file_info_label.setObjectName("StatusMetaLabel")
        self.status_bar.addPermanentWidget(self.file_info_label)

    def _init_hidden_label(self):
        self.hidden_label = QLabel("", self)
        self.hidden_label.setObjectName("HiddenNoticeLabel")
        self.hidden_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hidden_label.setWordWrap(True)
        self.hidden_label.hide()
        self._layout_hidden_label()
        self.hidden_label.mousePressEvent = self.privacy_guard.on_hidden_label_clicked

    def _layout_hidden_label(self):
        rect = self.contentsRect()
        margin_x = 40
        margin_y = 40
        width = max(280, rect.width() - (margin_x * 2))
        height = max(96, min(180, rect.height() // 3))
        x = rect.x() + (rect.width() - width) // 2
        y = rect.y() + (rect.height() - height) // 2
        self.hidden_label.setGeometry(x, y, width, height)

    def _init_timer_placeholders(self):
        self._menus_built = False
        self.autosave_timer = None
        self.secret_idle_timer = None
        self.cooldown_timer = None
        self.usb_cache_timer = None
        self.usb_cache = []
        self.cooldown_remaining = 0
        self.allow_editor_activation = True

    def _init_timers(self):
        self.autosave_timer = QTimer(singleShot=True)
        self.autosave_timer.setInterval(1000)
        self.autosave_timer.timeout.connect(self.autosave)
        self.editor.textChanged.connect(lambda: self.autosave_timer.start())
        self.editor.textChanged.connect(self._on_editor_activity)

        self.secret_idle_timer = QTimer(singleShot=True)
        self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
        self.secret_idle_timer.timeout.connect(self._on_infocus_inactivity_timeout)

        self.cooldown_timer = QTimer()
        self.cooldown_timer.setInterval(1000)
        self.cooldown_timer.timeout.connect(self.privacy_guard.update_cooldown)
        self.usb_cache_timer = QTimer()
        self.usb_cache_timer.timeout.connect(self.refresh_usb_cache)

    def _init_runtime_threads(self):
        self.screen_recorder_thread = None
        self.screen_recorder_checker = None

    def _init_deferred_startup(self):
        self.menuBar().setEnabled(False)
        QTimer.singleShot(0, self._after_first_paint_init)
        QTimer.singleShot(50, PangPreferences.preload_async)
        QTimer.singleShot(150, update_dialog_loader.preload_async)

    def _after_first_paint_init(self):
        self._init_timers()
        self._build_menus()
        self._warn_secret_cache_limit()
        self.menuBar().setEnabled(True)
        QTimer.singleShot(50, self._start_deferred_runtime_services)

    def _build_menus(self):
        if self._menus_built:
            return
        self._menus_built = True

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

    def _start_deferred_runtime_services(self):
        """Start non-critical services after initial UI show for faster startup."""
        if self.usb_cache_timer is None:
            return
        self.usb_cache_timer.start(5000)  # Refresh every 5 seconds
        self.refresh_usb_cache()

        if self.screen_recorder_thread is None:
            from .utils.screen_recording import ScreenRecordingChecker
            self.screen_recorder_thread = QThread()
            self.screen_recorder_checker = ScreenRecordingChecker()
            self.screen_recorder_checker.moveToThread(self.screen_recorder_thread)
            self.screen_recorder_thread.started.connect(self.screen_recorder_checker.run)
            self.screen_recorder_checker.screen_recording_changed.connect(self.privacy_guard.on_screen_recording_changed)
            self.screen_recorder_thread.start()

        self._ensure_mem_guard_controller().start()

    def open_help_page(self):
        from webbrowser import open as webopen
        webopen("https://www.panghq.com/tools/pangcrypter/help")

    def open_update_dialog(self):
        """Open the update dialog."""
        try:
            if not update_dialog_loader.is_ready():
                self.status_bar.showMessage("Preparing updater…", 1500)
            dialog = update_dialog_loader.create_dialog(self)
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
        PangPreferences.ensure_loaded()
        dlg = PreferencesDialog(self)
        if dlg.exec():
            # Preferences were saved by dlg.accept()
            # Just update the editor with the new setting
            self.editor.set_tab_setting(PangPreferences.tab_setting)
            if self.secret_idle_timer is not None:
                self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
            self._ensure_mem_guard_controller().configure()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.WindowActivate:
            self.privacy_guard.on_window_activate()
            return False
        elif event.type() == QEvent.Type.WindowDeactivate:
            self.privacy_guard.on_window_deactivate()
            return False
        return super().eventFilter(obj, event)
    
    def refresh_usb_cache(self):
        """Refresh the USB drive cache for better performance."""
        try:
            from .utils.usb import list_usb_drives
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

    def _on_editor_activity(self):
        self._last_editor_activity_at = monotonic()
        if PangPreferences.session_cache_enabled and (
            self.session_state.cached_password is not None or self.session_state.cached_usb_key is not None
        ):
            self.reset_secret_idle_timer()

    def _effective_secret_cache_idle_minutes(self) -> int:
        return self.session_state.effective_secret_cache_idle_minutes(
            PangPreferences,
            self.DEFAULT_SECRET_CACHE_IDLE_MINUTES,
            self.MAX_SECRET_CACHE_IDLE_MINUTES,
        )

    def _warn_secret_cache_limit(self) -> None:
        if not self.session_state.should_warn_secret_cache_limit(PangPreferences):
            return
        logger.warning(
            "Session secret caching uses best-effort obfuscation only and is limited to %s minutes of in-focus inactivity.",
            self._effective_secret_cache_idle_minutes(),
        )
        self.session_state.mark_secret_cache_notice_logged()

    def _on_infocus_inactivity_timeout(self):
        if not PangPreferences.session_cache_enabled:
            return
        if not PangPreferences.session_infocus_inactivity_reauth_enabled:
            return
        self.clear_cached_secrets()

    def autosave(self):
        if not self.operation_mutex.tryLock():
            logger.debug("Autosave skipped - operation in progress")
            return
        
        try:
            # To avoid lag, autosave only if we have keys cached:
            if self.session_state.cached_password is None and self.session_state.cached_usb_key is None:
                return
            
            # Only autosave if file is already saved
            if not self.saved_file_path:
                return
            
            if self.session_state.cached_uuid is None:
                logger.error("Autosave failed - no UUID cached")
                return
            
            logger.debug(f"Autosaving to {self.saved_file_path}")
            encrypt_file = self.document_service.encrypt_file
            
            # Encrypt current editor content
            password_bytes = self.session_state.get_cached_password_bytes()
            usb_key = self.session_state.get_cached_usb_key()
            self.reset_secret_idle_timer()
            encrypt_file(
                self._serialize_editor_content(),
                self.saved_file_path,
                self.current_mode,
                self.session_state.cached_uuid,
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
            from .utils.usb import list_usb_drives
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

    def _prompt_password(self, validate_strength: bool) -> Optional[bytearray]:
        pwd_dlg = PasswordDialog(self, warning=False)
        if not pwd_dlg.exec_():
            return None
        password_text = pwd_dlg.password

        if validate_strength:
            try:
                is_strong = self.validate_password(password_text)
            except ValidationError as e:
                PangMessageBox.warning(self, "Password Validation", str(e))
                return None

            if not is_strong and not self.confirm_weak_password():
                return None

        password_bytes = bytearray(password_text.encode("utf-8"))
        password_text = None
        return password_bytes

    def _select_usb_path(self) -> Optional[str]:
        usbs = self.check_usb_present()
        if not usbs:
            return None

        usb_dlg = USBSelectDialog(usbs, self)
        if not usb_dlg.exec_():
            return None

        selected_usb_path = usb_dlg.selected_usb
        logger.info(f"Selected USB drive: {selected_usb_path}")
        return selected_usb_path

    def save_file(self):
        """Save file with enhanced validation and progress indication."""
        mem_guard_controller = self._ensure_mem_guard_controller()
        if not mem_guard_controller.ensure_ready_for_sensitive_action("saving"):
            return
        if not self.operation_mutex.tryLock():
            PangMessageBox.warning(self, "Operation in Progress", "Another operation is in progress. Please wait.")
            return
        
        try:
            self.show_progress("Preparing to save file...")
            EncryptModeType = self.document_service.get_encrypt_mode_type()
            encrypt_file = self.document_service.encrypt_file
            create_or_load_key = self.document_service.create_or_load_key

            # Get encryption mode
            dlg = EncryptModeDialog(self)
            if not dlg.exec_():
                return

            mode = EncryptModeType(dlg.mode)
            logger.info(f"Selected encryption mode: {mode}")

            # Get password if needed
            password_bytes = None
            if mode in [EncryptModeType.MODE_PASSWORD_ONLY, EncryptModeType.MODE_PASSWORD_PLUS_KEY]:
                password_bytes = self._prompt_password(validate_strength=True)
                if password_bytes is None:
                    return

            # Get USB key if needed
            random_key = None
            selected_usb_path = None
            if mode in [EncryptModeType.MODE_PASSWORD_PLUS_KEY, EncryptModeType.MODE_KEY_ONLY]:
                selected_usb_path = self._select_usb_path()
                if selected_usb_path is None:
                    return

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
            if mode in [EncryptModeType.MODE_PASSWORD_PLUS_KEY, EncryptModeType.MODE_KEY_ONLY]:
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
            self.session_state.cached_uuid = file_uuid
            if PangPreferences.session_cache_enabled:
                if password_bytes:
                    self.session_state.cached_password = self.session_state.obfuscate_secret(password_bytes)
                    self._clear_temporary_bytes(password_bytes)
                else:
                    self.session_state.cached_password = None

                if random_key:
                    key_bytes = bytearray(random_key)
                    self.session_state.cached_usb_key = self.session_state.obfuscate_secret(key_bytes)
                    self._clear_temporary_bytes(key_bytes)
                    random_key = None
                else:
                    self.session_state.cached_usb_key = None
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
        mem_guard_controller = self._ensure_mem_guard_controller()
        if not mem_guard_controller.ensure_ready_for_sensitive_action("opening"):
            return
        if not self.operation_mutex.tryLock():
            PangMessageBox.warning(self, "Operation in Progress", "Another operation is in progress. Please wait.")
            return
        
        try:
            self.show_progress("Opening file...")
            EncryptModeType = self.document_service.get_encrypt_mode_type()
            decrypt_file = self.document_service.decrypt_file
            create_or_load_key = self.document_service.create_or_load_key
            
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

                    if mode not in [EncryptModeType.MODE_PASSWORD_ONLY, EncryptModeType.MODE_PASSWORD_PLUS_KEY, EncryptModeType.MODE_KEY_ONLY]:
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
            if mode in [EncryptModeType.MODE_PASSWORD_ONLY, EncryptModeType.MODE_PASSWORD_PLUS_KEY]:
                self.status_bar.showMessage("Waiting for password...")
                password_bytes = self._prompt_password(validate_strength=False)
                if password_bytes is None:
                    return
                logger.debug("Password provided for decryption")

            self.update_progress(40)

            # Get USB key if needed
            if mode in [EncryptModeType.MODE_PASSWORD_PLUS_KEY, EncryptModeType.MODE_KEY_ONLY]:
                self.status_bar.showMessage("Loading USB key...")
                selected_usb_path = self._select_usb_path()
                if selected_usb_path is None:
                    return

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
            self.session_state.cached_uuid = file_uuid
            if PangPreferences.session_cache_enabled:
                if password_bytes:
                    self.session_state.cached_password = self.session_state.obfuscate_secret(password_bytes)
                    self._clear_temporary_bytes(password_bytes)
                else:
                    self.session_state.cached_password = None

                if random_key:
                    key_bytes = bytearray(random_key)
                    self.session_state.cached_usb_key = self.session_state.obfuscate_secret(key_bytes)
                    self._clear_temporary_bytes(key_bytes)
                    random_key = None
                else:
                    self.session_state.cached_usb_key = None
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

    def _clear_temporary_bytes(self, data: Optional[bytearray]) -> None:
        if data is None:
            return
        try:
            self.best_effort_clear_memory(data)
        except (TypeError, ValueError) as e:
            logger.debug(f"Temporary bytes clear failed: {e}")

    def clear_cached_secrets(self):
        self.session_state.clear_cached_secrets(self.best_effort_clear_memory)
        if self.secret_idle_timer is not None:
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
        if self.secret_idle_timer is None:
            return
        if PangPreferences.session_cache_enabled and PangPreferences.session_infocus_inactivity_reauth_enabled:
            self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
            self.secret_idle_timer.start()
        else:
            self.secret_idle_timer.stop()

    def _apply_focus_reauth_policy(self):
        if self.session_state.should_reauth_after_focus(PangPreferences):
            self.clear_cached_secrets()

    def _enqueue_mem_guard_finding(self, finding: Any) -> None:
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
            panic_recovery = self._ensure_panic_recovery_service()
            panic_saved = panic_recovery.create_snapshot()
            self.clear_cached_secrets()
            self.editor.clear()
            self.privacy_guard.hide_editor_and_show_label()

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
                    self.mem_guard_controller.configure()

            if panic_saved:
                restored = panic_recovery.restore_snapshot()
                if not restored:
                    PangMessageBox.warning(self, "Restore Failed", "Could not restore panic snapshot. Re-open file manually.")
            self.privacy_guard.try_restore_editor()
        finally:
            self._mem_guard_handling = False
            if self._pending_mem_guard_findings:
                QTimer.singleShot(0, self._process_next_mem_guard_finding)

    def on_memory_probe_detected(self, finding: Any):
        self._enqueue_mem_guard_finding(finding)
        self._process_next_mem_guard_finding()

    def closeEvent(self, event):
        if self.mem_guard_controller is not None:
            self.mem_guard_controller.stop()
        if self.screen_recorder_checker is not None:
            self.screen_recorder_checker.stop()
        if self.screen_recorder_thread is not None:
            self.screen_recorder_thread.quit()
            self.screen_recorder_thread.wait(1500)
        super().closeEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._layout_hidden_label()

    def show_content_mode_menu(self, pos):
        menu = QMenu(self)

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

    configure_logging(args.debug, defer_file_logging=True)

    app = QApplication([sys.argv[0]] + remaining)
    app.setStyle("Fusion")
    apply_app_stylesheet(app)
    win = MainWindow()

    # If there's a path argument, try opening it
    file_arg = next(
        (arg for arg in remaining if os.path.isfile(arg) and arg.lower().endswith(".enc")),
        None,
    )
    if file_arg:
        try:
            win.open_file(file_arg)
        except (OSError, RuntimeError, ValueError) as e:
            print(f"Failed to open {file_arg}: {e}")

    win.show()
    if args.debug:
        QTimer.singleShot(0, enable_deferred_file_logging)
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
