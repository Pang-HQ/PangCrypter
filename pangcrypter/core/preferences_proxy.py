from __future__ import annotations

import threading
from types import SimpleNamespace


_DEFAULTS = {
    "recording_cooldown": 30,
    "screen_recording_hide_enabled": True,
    "tab_out_hide_enabled": True,
    "tab_setting": "spaces4",
    "session_cache_enabled": True,
    "session_reauth_on_focus_loss": True,
    "session_reauth_minutes": 2,
    "session_infocus_inactivity_reauth_enabled": True,
    "session_infocus_inactivity_minutes": 5,
    "mem_guard_mode": "off",
    "mem_guard_whitelist": [],
    "auto_delete_panic_files": True,
    "mem_guard_scan_interval_ms": 50,
    "mem_guard_pid_cache_cap": 128,
}


class PreferencesProxy:
    def __init__(self):
        object.__setattr__(self, "_target", SimpleNamespace(**_DEFAULTS))
        object.__setattr__(self, "_loaded", False)
        object.__setattr__(self, "_loading", False)
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_pending", {})

    def _load_real_preferences(self):
        with self._lock:
            if self._loaded or self._loading:
                return
            self._loading = True
        try:
            from ..utils.preferences import PangPreferences as real
            with self._lock:
                for key, value in self._pending.items():
                    setattr(real, key, value)
                self._pending.clear()
                self._target = real
                self._loaded = True
        finally:
            with self._lock:
                self._loading = False

    def preload_async(self):
        with self._lock:
            if self._loaded or self._loading:
                return
        threading.Thread(target=self._load_real_preferences, daemon=True).start()

    def is_loaded(self) -> bool:
        with self._lock:
            return self._loaded

    def ensure_loaded(self):
        self._load_real_preferences()

    def __getattr__(self, name):
        return getattr(self._target, name)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        setattr(self._target, name, value)
        with self._lock:
            if not self._loaded:
                self._pending[name] = value

    def save_preferences(self):
        if hasattr(self._target, "save_preferences"):
            self._target.save_preferences()


class PreferencesDialogFactory:
    def __call__(self, *args, **kwargs):
        from ..utils.preferences import PreferencesDialog as _PreferencesDialog
        return _PreferencesDialog(*args, **kwargs)


PangPreferences = PreferencesProxy()
PreferencesDialog = PreferencesDialogFactory()
