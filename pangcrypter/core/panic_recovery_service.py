from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from PyQt6.QtWidgets import QFileDialog


class PanicRecoveryService:
    def __init__(self, host, preferences):
        self.host = host
        self.preferences = preferences
        self._panic_recovery_path: str | None = None

    def panic_path(self) -> str | None:
        if not self.host.saved_file_path:
            return None
        return f"{self.host.saved_file_path}.panic.enc"

    def panic_meta_path(self) -> str | None:
        panic = self.panic_path()
        if not panic:
            return None
        return f"{panic}.meta"

    def create_snapshot(self) -> bool:
        panic_path = self.panic_path()
        if not panic_path or self.host.session_state.cached_uuid is None or self.host.current_mode is None:
            return False

        encrypt_file = self.host.document_service.encrypt_file
        password_bytes = self.host.session_state.get_cached_password_bytes()
        usb_key = self.host.session_state.get_cached_usb_key()
        self.host.reset_secret_idle_timer()

        try:
            content = self.host._serialize_editor_content()
            encrypt_file(
                content,
                panic_path,
                self.host.current_mode,
                self.host.session_state.cached_uuid,
                password=password_bytes,
                usb_key=bytes(usb_key) if usb_key else None,
                content_mode=self.host.current_content_mode,
            )
            meta_path = self.panic_meta_path()
            if meta_path:
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump({"saved_at": datetime.now(timezone.utc).isoformat()}, f, indent=2)
            self._panic_recovery_path = panic_path
            return True
        except (ValueError, TypeError, OSError, RuntimeError):
            fallback_path, _ = QFileDialog.getSaveFileName(
                self.host,
                "Save panic snapshot as...",
                filter="Encrypted Files (*.enc)",
            )
            if not fallback_path:
                return False
            try:
                encrypt_file(
                    content,
                    fallback_path,
                    self.host.current_mode,
                    self.host.session_state.cached_uuid,
                    password=password_bytes,
                    usb_key=bytes(usb_key) if usb_key else None,
                    content_mode=self.host.current_content_mode,
                )
                self._panic_recovery_path = fallback_path
                return True
            except (ValueError, TypeError, OSError, RuntimeError):
                return False
        finally:
            self.host._clear_temporary_bytes(password_bytes)
            self.host._clear_temporary_bytes(usb_key)

    def restore_snapshot(self) -> bool:
        path = self._panic_recovery_path or self.panic_path()
        if not path or not os.path.exists(path) or self.host.current_mode is None:
            return False

        EncryptModeType = self.host.document_service.get_encrypt_mode_type()
        decrypt_file = self.host.document_service.decrypt_file
        create_or_load_key = self.host.document_service.create_or_load_key

        password_bytes = None
        usb_key = None
        try:
            if self.host.current_mode in [EncryptModeType.MODE_PASSWORD_ONLY, EncryptModeType.MODE_PASSWORD_PLUS_KEY]:
                from ..ui.main_ui import PasswordDialog
                pwd_dlg = PasswordDialog(self.host)
                if not pwd_dlg.exec_():
                    return False
                password_bytes = bytearray(pwd_dlg.password.encode("utf-8"))

            if self.host.current_mode in [EncryptModeType.MODE_PASSWORD_PLUS_KEY, EncryptModeType.MODE_KEY_ONLY]:
                from ..ui.main_ui import USBSelectDialog
                usbs = self.host.check_usb_present()
                if not usbs:
                    return False
                usb_dlg = USBSelectDialog(usbs, self.host)
                if not usb_dlg.exec_():
                    return False
                selected_usb_path = usb_dlg.selected_usb
                usb_key, _ = create_or_load_key(selected_usb_path, self.host.saved_file_path or path, create=False)

            plaintext = decrypt_file(path, password=password_bytes, usb_key=usb_key)
            content_str = plaintext.decode("utf-8")
            self.host._load_editor_content(content_str)
            self.host.best_effort_clear_memory(plaintext)

            panic_uuid = self.host._read_file_uuid(path)
            if panic_uuid is not None:
                self.host.session_state.cached_uuid = panic_uuid

            if self.preferences.session_cache_enabled:
                self.host.session_state.cached_password = (
                    self.host.session_state.obfuscate_secret(password_bytes) if password_bytes else None
                )
                if usb_key:
                    key_bytes = bytearray(usb_key)
                    self.host.session_state.cached_usb_key = self.host.session_state.obfuscate_secret(key_bytes)
                    self.host._clear_temporary_bytes(key_bytes)
                else:
                    self.host.session_state.cached_usb_key = None
                self.host.reset_secret_idle_timer()

            if self.preferences.auto_delete_panic_files:
                try:
                    os.remove(path)
                except OSError:
                    pass
                meta_path = self.panic_meta_path()
                if meta_path:
                    try:
                        os.remove(meta_path)
                    except OSError:
                        pass
            return True
        except (ValueError, TypeError, OSError, RuntimeError, UnicodeDecodeError):
            return False
        finally:
            self.host._clear_temporary_bytes(password_bytes)
            if isinstance(usb_key, bytearray):
                self.host._clear_temporary_bytes(usb_key)
