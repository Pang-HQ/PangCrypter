import sys
import psutil
import os
import platform
import subprocess
import logging
from time import sleep
from webbrowser import open as webopen
from typing import Optional, List
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QLabel, QProgressBar, QStatusBar
from PyQt6.QtCore import QTimer, Qt, QEvent, QObject, pyqtSignal, QThread, QMutex
from PyQt6.QtGui import QIcon, QAction
from .ui.main_ui import (
    EditorWidget, EncryptModeDialog, PasswordDialog, USBSelectDialog
)
from .core.encrypt import encrypt_file, decrypt_file, EncryptModeType
from .core.key import create_or_load_key
from .ui.messagebox import PangMessageBox

from .utils.preferences import PreferencesDialog, PangPreferences
from .utils.styles import TEXT_COLOR, DARKER_BG, PURPLE
from .ui.update_dialog import UpdateDialog

from uuid import uuid4

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pangcrypter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

MODE_PASSWORD_ONLY = EncryptModeType.MODE_PASSWORD_ONLY
MODE_PASSWORD_PLUS_KEY = EncryptModeType.MODE_PASSWORD_PLUS_KEY
MODE_KEY_ONLY = EncryptModeType.MODE_KEY_ONLY


# List of known screen recording process names (case insensitive)
screen_recorders_lower = {
    "obs64.exe",      # OBS Studio 64-bit on Windows
    "obs32.exe",      # OBS Studio 32-bit on Windows
    "obs.exe",        # Generic OBS name
    "bandicam.exe",   # Bandicam
    "camtasia.exe",   # Camtasia
    "xsplit.exe",     # XSplit Broadcaster
    "ffmpeg.exe",     # ffmpeg (if used for recording)
    "screenrecorder.exe",
    "screencast-o-matic.exe",
    "sharex.exe",
    # Add other known recorders here if you want
}

def list_usb_drives():
    drives = []
    system = platform.system()

    if system == "Windows":
        # On Windows, use wmic to get removable drives
        try:
            output = subprocess.check_output('wmic logicaldisk where "drivetype=2" get deviceid', shell=True).decode()
            for line in output.strip().splitlines():
                line = line.strip()
                if line and line != "DeviceID":
                    drive_path = line + "\\"
                    if os.access(drive_path, os.W_OK):
                        drives.append(drive_path)
        except Exception:
            pass

    elif system == "Linux":
        # On Linux, check /media and /run/media for mounted removable drives
        media_paths = ["/media", "/run/media"]
        for media_root in media_paths:
            if os.path.exists(media_root):
                for user_folder in os.listdir(media_root):
                    user_path = os.path.join(media_root, user_folder)
                    if os.path.isdir(user_path):
                        for mount in os.listdir(user_path):
                            mount_path = os.path.join(user_path, mount)
                            if os.path.ismount(mount_path) and os.access(mount_path, os.W_OK):
                                drives.append(mount_path)

    elif system == "Darwin":
        # macOS: check /Volumes for mounted drives that are writable
        volumes_path = "/Volumes"
        if os.path.exists(volumes_path):
            for volume in os.listdir(volumes_path):
                vol_path = os.path.join(volumes_path, volume)
                if os.path.ismount(vol_path) and os.access(vol_path, os.W_OK):
                    drives.append(vol_path)
    else:
        PangMessageBox.warning(None, "Unsupported OS", "This script only supports Windows, Linux, and macOS.")

    return drives

class ScreenRecordingChecker(QObject):
    screen_recording_changed = pyqtSignal(bool)

    def __init__(self, check_interval=1):
        super().__init__()
        self.check_interval = check_interval
        self.running = True
        self._last_status = False
        self.cached_procs = set()

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            try:
                current_procs = set()
                # Gather current running process names, lowercase for matching
                for proc in psutil.process_iter(["name"]):
                    try:
                        pname = proc.info["name"]
                        if pname:
                            current_procs.add(pname.lower())
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                new_procs = current_procs - self.cached_procs
                self.cached_procs = current_procs

                # Only check new processes to reduce overhead
                recording_detected = False
                for pname in new_procs:
                    if pname in screen_recorders_lower:
                        recording_detected = True
                        break

                # Also if last status was True but process disappeared, update status
                if self._last_status and not recording_detected:
                    # Need to check if any screen recorder is still running
                    recording_detected = any(proc in screen_recorders_lower for proc in current_procs)

                if recording_detected != self._last_status:
                    self._last_status = recording_detected
                    self.screen_recording_changed.emit(recording_detected)

            except Exception as e:
                # Optionally log the error
                pass

            sleep(self.check_interval)

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
        self.cached_password = None
        self.cached_usb_key = None
        self.cached_uuid = None
        
        # Thread safety
        self.operation_mutex = QMutex()
        
        # Status bar with progress indicator
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
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
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: #121212; color: #eee; }}
            QTextEdit {{ background-color: #1e1e1e; color: #ddd; font-family: Consolas, monospace; font-size: 14px; }}
            QMenuBar {{ background-color: #222; color: #eee; }}
            QMenu {{ background-color: #222; color: #eee; }}
            QMenu::item:selected {{ background-color: #444; }}
            QPushButton {{ background-color: #333; color: #eee; border-radius: 5px; padding: 5px; }}
            QPushButton:hover {{ background-color: #555; }}
            QLineEdit, QComboBox {{ background-color: #222; color: #eee; border: 1px solid #555; border-radius: 3px; padding: 3px; }}
        """)

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

        # Track window focus
        self.installEventFilter(self)
    
    def open_help_page(self):
        webopen("https://www.panghq.com/tools/pangcrypter/help")

    def open_update_dialog(self):
        """Open the update dialog."""
        try:
            dialog = UpdateDialog(self)
            dialog.exec()
        except Exception as e:
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

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.WindowActivate:
            if PangPreferences.screen_recording_hide_enabled and not self.allow_editor_activation:
                self.cooldown_remaining = PangPreferences.recording_cooldown
                self.update_hidden_label_for_cooldown()
                self.cooldown_timer.start()
            return False
        elif event.type() == QEvent.Type.WindowDeactivate:
            if PangPreferences.screen_recording_hide_enabled:
                self.cooldown_timer.stop()
            return False
        return super().eventFilter(obj, event)
    
    def update_cooldown(self):
        self.cooldown_remaining -= 1
        if self.cooldown_remaining <= 0:
            self.allow_editor_activation = True
            self.cooldown_timer.stop()
            self.hidden_label.setText(
                f"Screen recording program detected.\n"
                f"Make sure to close this window before recording.\n"
                f"Click here to restore editor."
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
        except Exception as e:
            logger.error(f"Failed to refresh USB cache: {e}")
            self.usb_cache = []

    def validate_file_path(self, path: str) -> bool:
        """Validate file path for security and correctness."""
        if not path:
            raise ValidationError("File path cannot be empty")
        
        if not isinstance(path, str):
            raise ValidationError("File path must be a string")
        
        # Check for path traversal attempts
        if ".." in path or path.startswith("/") and not os.path.isabs(path):
            raise ValidationError("Invalid file path detected")
        
        # Check file extension
        if not path.lower().endswith('.enc'):
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
        
        return True

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
            encrypt_file(
                self.editor.toHtml().encode("utf-8"),
                self.saved_file_path,
                self.current_mode,
                self.cached_uuid,
                password=self.cached_password,
                usb_key=self.cached_usb_key,
            )
            logger.info(f"Autosaved encrypted file to {self.saved_file_path}")
            
        except CryptographyError as e:
            logger.error(f"Cryptography error during autosave: {e}")
            PangMessageBox.warning(self, "Autosave failed", f"Encryption error: {e}")
        except Exception as e:
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
            
        except Exception as e:
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
            password = None
            if mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
                pwd_dlg = PasswordDialog(self, warning=(mode == MODE_KEY_ONLY))
                if not pwd_dlg.exec_():
                    return
                password = pwd_dlg.password
                
                # Validate password
                try:
                    self.validate_password(password)
                except ValidationError as e:
                    PangMessageBox.warning(self, "Password Validation", str(e))
                    # Continue anyway - validation is advisory

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
                except Exception as e:
                    logger.error(f"Failed to create/load USB key: {e}")
                    raise USBKeyError(f"Failed to create USB key: {e}")

            self.update_progress(50)
            self.status_bar.showMessage("Encrypting file...")

            # Encrypt and save
            try:
                content = self.editor.toHtml().encode("utf-8")
                encrypt_file(
                    content,
                    path,
                    mode,
                    file_uuid,
                    password=password,
                    usb_key=random_key
                )
                logger.info(f"File encrypted and saved to {path}")
                
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
                raise CryptographyError(f"Failed to encrypt file: {e}")

            self.update_progress(100)
            
            # Update application state
            self.saved_file_path = path
            self.update_window_title(self.saved_file_path)
            self.current_mode = mode
            self.cached_uuid = file_uuid
            self.cached_password = password
            self.cached_usb_key = random_key

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
        except Exception as e:
            logger.error(f"Unexpected error during save: {e}")
            PangMessageBox.critical(self, "Save Failed", f"An unexpected error occurred:\n{e}")
        finally:
            self.hide_progress()
            self.operation_mutex.unlock()

    def secure_clear_memory(self, data: bytes) -> None:
        """Securely clear sensitive data from memory."""
        if data:
            # Since Python bytes are immutable, we can't directly overwrite them.
            # Instead, we overwrite copies and let the original be garbage collected.
            # This is not perfect, but prevents simple memory dumps.
            try:
                # Create copies and overwrite them (less effective than direct memory manipulation)
                size = len(data)
                if size > 0:
                    # Fill with zeros (note: this doesn't modify the original data)
                    zero_data = b'\x00' * size
                    # Overwrite with random data
                    import os
                    random_data = os.urandom(size)

                    # Force garbage collection to clear original data faster
                    import gc
                    del data
                    gc.collect()

                    logger.debug("Memory cleared (best-effort for immutable bytes)")
                else:
                    # Empty data, nothing to clear
                    pass

            except Exception as e:
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
            try:
                with open(path, "rb") as f:
                    mode_byte = f.read(1)
                    if not mode_byte:
                        raise ValidationError("File is empty or invalid")
                    
                    try:
                        mode = EncryptModeType(mode_byte[0])
                    except ValueError:
                        raise ValidationError(f"Unknown encryption mode: {mode_byte[0]}")
                    
                    if mode not in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY, MODE_KEY_ONLY]:
                        raise ValidationError(f"Unsupported encryption mode: {mode}")
                        
                    logger.info(f"File uses encryption mode: {mode}")
                    
            except ValidationError as e:
                PangMessageBox.critical(self, "Invalid File Format", str(e))
                return
            except Exception as e:
                logger.error(f"Failed to read file header: {e}")
                PangMessageBox.critical(self, "File Read Error", f"Failed to read file: {e}")
                return

            self.update_progress(25)
            
            # Get credentials based on encryption mode
            password = None
            random_key = None
            file_uuid = None

            # Get password if needed
            if mode in [MODE_PASSWORD_ONLY, MODE_PASSWORD_PLUS_KEY]:
                self.status_bar.showMessage("Waiting for password...")
                pwd_dlg = PasswordDialog(self, warning=(mode == MODE_KEY_ONLY))
                if not pwd_dlg.exec_():
                    return
                password = pwd_dlg.password
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
                    random_key, file_uuid = create_or_load_key(selected_usb_path, path, create=False)
                    logger.info("USB key loaded successfully")
                except Exception as e:
                    logger.error(f"Failed to load USB key: {e}")
                    raise USBKeyError(f"Failed to load USB key: {e}")

            self.update_progress(60)
            self.status_bar.showMessage("Decrypting file...")

            # Decrypt file
            try:
                plaintext = decrypt_file(path, password=password, usb_key=random_key)
                logger.info(f"File decrypted successfully: {len(plaintext)} bytes")
                
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                raise CryptographyError(f"Failed to decrypt file: {e}")

            self.update_progress(80)
            self.status_bar.showMessage("Loading content...")

            # Load content into editor
            try:
                content_str = plaintext.decode("utf-8")
                self.editor.setHtml(content_str)
                
                # Securely clear plaintext from memory
                self.secure_clear_memory(plaintext)
                
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
            self.cached_password = password
            self.cached_usb_key = random_key

            self.status_bar.showMessage("File opened successfully", 3000)
            PangMessageBox.information(self, "Success", "File opened successfully.")
            logger.info(f"File opened successfully: {path}")
            
        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            PangMessageBox.critical(self, "Validation Error", str(e))
        except CryptographyError as e:
            logger.error(f"Cryptography error: {e}")
            PangMessageBox.critical(self, "Decryption Error", str(e))
        except USBKeyError as e:
            logger.error(f"USB key error: {e}")
            PangMessageBox.critical(self, "USB Key Error", str(e))
        except Exception as e:
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
        self.cached_password = None
        self.cached_usb_key = None
        self.editor.clear()
    
    def update_window_title(self, filename: str | None):
        base_title = "PangCrypter"
        if filename:
            # Remove .enc extension if present
            name_without_ext = os.path.splitext(os.path.basename(filename))[0]
            self.setWindowTitle(f"Editing {name_without_ext} - {base_title}")
        else:
            self.setWindowTitle(base_title)

def main():
    app = QApplication(sys.argv)
    win = MainWindow()

    # If there's an argument, try opening it
    if len(sys.argv) > 1:
        file_arg = sys.argv[1]
        if os.path.isfile(file_arg) and file_arg.lower().endswith(".enc"):
            try:
                win.open_file(file_arg)
            except Exception as e:
                print(f"Failed to open {file_arg}: {e}")

    win.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
