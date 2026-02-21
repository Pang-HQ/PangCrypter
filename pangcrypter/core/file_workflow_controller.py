from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from uuid import UUID, uuid4
from typing import Optional

from PyQt6.QtWidgets import QFileDialog
from nacl.exceptions import CryptoError as NaClCryptoError

from .errors import ValidationError, CryptographyError, USBKeyError
from .format_config import (
    SETTINGS_SIZE,
    CONTENT_MODE_OFFSET,
    CONTENT_MODE_PLAINTEXT,
    CONTENT_MODE_HTML,
    HEADER_VERSION,
    decode_version,
)
from .mode_rules import mode_uses_password, mode_uses_usb
from ..ui.messagebox import PangMessageBox

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HeaderInfo:
    file_uuid: UUID
    mode: object
    version: int
    content_mode: int


class FileWorkflowController:
    def __init__(self, host):
        self.host = host

    def validate_file_path(self, path: str) -> bool:
        if not path:
            raise ValidationError("File path cannot be empty")
        if not isinstance(path, str):
            raise ValidationError("File path must be a string")
        normalized = os.path.abspath(path)
        if os.path.isdir(normalized):
            raise ValidationError("Path points to a directory, expected an .enc file")
        if not normalized.lower().endswith('.enc'):
            raise ValidationError("File must have .enc extension")
        return True

    def validate_password(self, password: str) -> bool:
        if not password:
            raise ValidationError("Password cannot be empty")
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        if not (has_upper and has_lower and has_digit):
            logger.warning("Password does not meet complexity requirements")
            return False
        return True

    def confirm_weak_password(self) -> bool:
        ret = PangMessageBox.question(
            self.host,
            "Weak Password",
            "The password does not meet complexity requirements. Continue anyway?",
            buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
            default=PangMessageBox.StandardButton.No,
        )
        return ret == PangMessageBox.StandardButton.Yes

    def _prompt_password(self, validate_strength: bool) -> Optional[bytearray]:
        from ..ui.main_ui import PasswordDialog

        pwd_dlg = PasswordDialog(self.host, warning=False)
        if not pwd_dlg.exec_():
            return None
        password_text = pwd_dlg.password

        if validate_strength:
            try:
                is_strong = self.validate_password(password_text)
            except ValidationError as e:
                PangMessageBox.warning(self.host, "Password Validation", str(e))
                return None
            if not is_strong and not self.confirm_weak_password():
                return None

        password_bytes = bytearray(password_text.encode("utf-8"))
        password_text = None
        return password_bytes

    def _select_usb_path(self) -> Optional[str]:
        from ..ui.main_ui import USBSelectDialog

        usbs = self.host.check_usb_present()
        if not usbs:
            return None
        usb_dlg = USBSelectDialog(usbs, self.host)
        if not usb_dlg.exec_():
            return None
        selected_usb_path = usb_dlg.selected_usb
        logger.info(f"Selected USB drive: {selected_usb_path}")
        return selected_usb_path

    def autosave(self):
        if not self.host.operation_mutex.tryLock():
            logger.debug("Autosave skipped - operation in progress")
            return

        try:
            if self.host.session_state.cached_password is None and self.host.session_state.cached_usb_key is None:
                return
            if not self.host.saved_file_path:
                return
            if self.host.session_state.cached_uuid is None:
                logger.error("Autosave failed - no UUID cached")
                return

            encrypt_file = self.host.document_service.encrypt_file
            password_bytes = self.host.session_state.get_cached_password_bytes()
            usb_key = self.host.session_state.get_cached_usb_key()
            self.host.reset_secret_idle_timer()
            encrypt_file(
                self.host._serialize_editor_content(),
                self.host.saved_file_path,
                self.host.current_mode,
                self.host.session_state.cached_uuid,
                password=password_bytes,
                usb_key=bytes(usb_key) if usb_key else None,
                content_mode=self.host.current_content_mode,
            )
            self.host._clear_temporary_bytes(password_bytes)
            self.host._clear_temporary_bytes(usb_key)
            self.host.reset_secret_idle_timer()
            logger.info(f"Autosaved encrypted file to {self.host.saved_file_path}")
        except CryptographyError as e:
            logger.error(f"Cryptography error during autosave: {e}")
            PangMessageBox.warning(self.host, "Autosave failed", f"Encryption error: {e}")
        except (ValueError, TypeError, OSError, RuntimeError) as e:
            logger.error(f"Unexpected error during autosave: {e}")
            PangMessageBox.warning(self.host, "Autosave failed", f"Could not autosave encrypted file:\n{e}")
        finally:
            self.host.operation_mutex.unlock()

    def _read_header(self, path: str, EncryptModeType) -> HeaderInfo:
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

            mode = EncryptModeType(settings[2])
            if mode not in [
                EncryptModeType.MODE_PASSWORD_ONLY,
                EncryptModeType.MODE_PASSWORD_PLUS_KEY,
                EncryptModeType.MODE_KEY_ONLY,
            ]:
                raise ValidationError(f"Unsupported encryption mode: {mode}")

            content_mode = settings[CONTENT_MODE_OFFSET]
            if content_mode not in (CONTENT_MODE_PLAINTEXT, CONTENT_MODE_HTML):
                raise ValidationError("Unsupported content mode in file header")

            return HeaderInfo(
                file_uuid=file_uuid,
                mode=mode,
                version=header_version,
                content_mode=content_mode,
            )

    def save_file(self):
        mem_guard_controller = self.host._ensure_mem_guard_controller()
        if not mem_guard_controller.ensure_ready_for_sensitive_action("saving"):
            return
        if not self.host.operation_mutex.tryLock():
            PangMessageBox.warning(self.host, "Operation in Progress", "Another operation is in progress. Please wait.")
            return

        try:
            self.host.show_progress("Preparing to save file...")
            EncryptModeType = self.host.document_service.get_encrypt_mode_type()
            encrypt_file = self.host.document_service.encrypt_file
            create_or_load_key = self.host.document_service.create_or_load_key
            from ..ui.main_ui import EncryptModeDialog

            dlg = EncryptModeDialog(self.host)
            if not dlg.exec_():
                return
            mode = EncryptModeType(dlg.mode)

            password_bytes = None
            if mode_uses_password(mode, EncryptModeType):
                password_bytes = self._prompt_password(validate_strength=True)
                if password_bytes is None:
                    return

            random_key = None
            selected_usb_path = None
            if mode_uses_usb(mode, EncryptModeType):
                selected_usb_path = self._select_usb_path()
                if selected_usb_path is None:
                    return

            path, _ = QFileDialog.getSaveFileName(self.host, "Save encrypted file", filter="Encrypted Files (*.enc)")
            if not path:
                return

            self.validate_file_path(path)
            if os.path.exists(path):
                ret = PangMessageBox.question(
                    self.host,
                    "File Exists",
                    f"The file '{os.path.basename(path)}' already exists. Do you want to overwrite it?",
                    buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                    default=PangMessageBox.StandardButton.No,
                )
                if ret == PangMessageBox.StandardButton.No:
                    return

            self.host.update_progress(25)
            file_uuid = uuid4()
            if mode_uses_usb(mode, EncryptModeType):
                random_key, _ = create_or_load_key(selected_usb_path, path, file_uuid)

            self.host.update_progress(50)
            content = self.host._serialize_editor_content()
            encrypt_file(
                content,
                path,
                mode,
                file_uuid,
                password=password_bytes,
                usb_key=random_key,
                content_mode=self.host.current_content_mode,
            )

            self.host.update_progress(100)
            self.host.saved_file_path = path
            self.host.update_window_title(self.host.saved_file_path)
            self.host.current_mode = mode
            self.host.header_version = HEADER_VERSION
            self.host._update_session_cache_after_auth(
                file_uuid=file_uuid,
                password_bytes=password_bytes,
                usb_key=random_key,
            )
            self.host.status_bar.showMessage("File saved successfully", 3000)
            PangMessageBox.information(self.host, "Success", "File saved successfully.")

        except ValidationError as e:
            PangMessageBox.critical(self.host, "Validation Error", str(e))
        except CryptographyError as e:
            PangMessageBox.critical(self.host, "Encryption Error", str(e))
        except USBKeyError as e:
            PangMessageBox.critical(self.host, "USB Key Error", str(e))
        except (OSError, RuntimeError, ValueError, TypeError) as e:
            PangMessageBox.critical(self.host, "Save Failed", f"An unexpected error occurred:\n{e}")
        finally:
            self.host.hide_progress()
            self.host.operation_mutex.unlock()

    def open_file(self, path: str | None = None):
        mem_guard_controller = self.host._ensure_mem_guard_controller()
        if not mem_guard_controller.ensure_ready_for_sensitive_action("opening"):
            return
        if not self.host.operation_mutex.tryLock():
            PangMessageBox.warning(self.host, "Operation in Progress", "Another operation is in progress. Please wait.")
            return

        try:
            self.host.show_progress("Opening file...")
            EncryptModeType = self.host.document_service.get_encrypt_mode_type()
            decrypt_file = self.host.document_service.decrypt_file
            create_or_load_key = self.host.document_service.create_or_load_key

            if not path:
                path, _ = QFileDialog.getOpenFileName(self.host, "Open encrypted file", filter="Encrypted Files (*.enc)")
                if not path:
                    return

            self.validate_file_path(path)
            if not os.path.exists(path):
                PangMessageBox.critical(self.host, "File Not Found", f"The file '{path}' does not exist.")
                return
            if not os.access(path, os.R_OK):
                PangMessageBox.critical(self.host, "Access Denied", f"Cannot read file '{path}'. Check permissions.")
                return

            self.host.update_progress(10)
            header = self._read_header(path, EncryptModeType)
            file_uuid = header.file_uuid
            mode = header.mode
            self.host.header_version = header.version
            self.host.current_content_mode = header.content_mode
            self.host.editor.set_content_mode(header.content_mode == CONTENT_MODE_HTML)

            self.host.update_progress(25)

            password_bytes = None
            random_key = None
            opened_header_uuid = file_uuid

            if mode_uses_password(mode, EncryptModeType):
                password_bytes = self._prompt_password(validate_strength=False)
                if password_bytes is None:
                    return

            self.host.update_progress(40)

            if mode_uses_usb(mode, EncryptModeType):
                selected_usb_path = self._select_usb_path()
                if selected_usb_path is None:
                    return
                random_key, loaded_uuid = create_or_load_key(selected_usb_path, path, create=False)
                if loaded_uuid is not None:
                    file_uuid = loaded_uuid

            if file_uuid is None:
                file_uuid = opened_header_uuid

            self.host.update_progress(60)
            plaintext = decrypt_file(path, password=password_bytes, usb_key=random_key)

            self.host.update_progress(80)
            content_str = plaintext.decode("utf-8")
            self.host._load_editor_content(content_str)
            self.host.best_effort_clear_memory(plaintext)

            self.host.update_progress(100)
            self.host.saved_file_path = path
            self.host.update_window_title(self.host.saved_file_path)
            self.host.current_mode = mode
            if file_uuid is not None:
                self.host._update_session_cache_after_auth(
                    file_uuid=file_uuid,
                    password_bytes=password_bytes,
                    usb_key=random_key,
                )

            self.host.status_bar.showMessage("File opened successfully", 3000)
            PangMessageBox.information(self.host, "Success", "File opened successfully.")
            self.host.update_file_info_label()

        except ValidationError as e:
            PangMessageBox.critical(self.host, "Validation Error", str(e))
        except CryptographyError as e:
            PangMessageBox.critical(self.host, "Decryption Error", str(e))
        except USBKeyError as e:
            PangMessageBox.critical(self.host, "USB Key Error", str(e))
        except (NaClCryptoError, OSError, RuntimeError, ValueError, TypeError, UnicodeDecodeError) as e:
            PangMessageBox.critical(self.host, "Open Failed", f"An unexpected error occurred:\n{e}")
        finally:
            self.host.hide_progress()
            self.host.operation_mutex.unlock()
