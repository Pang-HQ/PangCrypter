import os
from time import monotonic
from typing import Optional


class SessionState:
    def __init__(self):
        self.cached_password: Optional[bytearray] = None
        self.cached_usb_key: Optional[bytearray] = None
        self.cached_uuid = None
        self._secret_mask = os.urandom(32)
        self._focus_lost_at: Optional[float] = None
        self._secret_cache_notice_logged = False

    def _xor_with_mask(self, data: bytes | bytearray) -> bytearray:
        mask = self._secret_mask
        return bytearray(b ^ mask[i % len(mask)] for i, b in enumerate(bytes(data)))

    def obfuscate_secret(self, secret: bytes | bytearray) -> bytearray:
        return self._xor_with_mask(secret)

    def deobfuscate_secret(self, secret: bytearray) -> bytearray:
        return self._xor_with_mask(bytes(secret))

    def get_cached_password_bytes(self) -> Optional[bytearray]:
        if self.cached_password is None:
            return None
        return self.deobfuscate_secret(self.cached_password)

    def get_cached_usb_key(self) -> Optional[bytearray]:
        if self.cached_usb_key is None:
            return None
        return self.deobfuscate_secret(self.cached_usb_key)

    def clear_cached_secrets(self, memory_clearer) -> None:
        memory_clearer(self.cached_password)
        memory_clearer(self.cached_usb_key)
        self.cached_password = None
        self.cached_usb_key = None
        self.cached_uuid = None

    def effective_secret_cache_idle_minutes(self, preferences, default_minutes: int, max_minutes: int) -> int:
        configured = int(getattr(preferences, "session_infocus_inactivity_minutes", default_minutes))
        return max(1, min(configured, max_minutes))

    def should_warn_secret_cache_limit(self, preferences) -> bool:
        return bool(getattr(preferences, "session_cache_enabled", False)) and not self._secret_cache_notice_logged

    def mark_secret_cache_notice_logged(self) -> None:
        self._secret_cache_notice_logged = True

    def note_focus_lost(self) -> None:
        self._focus_lost_at = monotonic()

    def clear_focus_lost_marker(self) -> None:
        self._focus_lost_at = None

    def should_reauth_after_focus(self, preferences) -> bool:
        if not getattr(preferences, "session_cache_enabled", False):
            return False
        if not getattr(preferences, "session_reauth_on_focus_loss", False):
            self._focus_lost_at = None
            return False
        if self._focus_lost_at is None:
            return False

        elapsed = monotonic() - self._focus_lost_at
        timeout_sec = int(getattr(preferences, "session_reauth_minutes", 0)) * 60
        self._focus_lost_at = None
        return elapsed >= timeout_sec
