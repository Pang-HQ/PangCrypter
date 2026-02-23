from __future__ import annotations

import os
import sys
import threading
from time import monotonic, sleep
from typing import Any, Optional

from PyQt6.QtCore import QTimer, QThread


class MemGuardController:
    def __init__(self, host, preferences, logger):
        self.host = host
        self.preferences = preferences
        self.logger = logger

        self.mem_guard_thread: Optional[QThread] = None
        self.mem_guard_checker = None
        self._disabled_until_restart = False

        self._module_ready = os.name != "nt"
        self._api: dict[str, Any] = {}
        self._load_error: Optional[str] = None
        self._loader_thread: Optional[threading.Thread] = None
        self._bootstrap_timer: Optional[QTimer] = None
        self._started = False
        self._etw_status_notice_shown = False

    def start(self):
        if self._started:
            return
        self._started = True
        self._start_async_load()
        self._start_bootstrap_timer()
        self.configure()

    def is_protection_required(self) -> bool:
        if os.name != "nt":
            return False
        if not getattr(self.preferences, "session_cache_enabled", False):
            return False
        mode_name = str(getattr(self.preferences, "mem_guard_mode", "off")).strip().replace("-", "_").upper()
        return mode_name != "OFF"

    @staticmethod
    def _parse_mode(mode_raw: str, MemGuardMode):
        normalized = str(mode_raw or "").strip().replace("-", "_").upper()
        if not normalized:
            normalized = "OFF"
        if normalized in {"ULTRA", "ULTRAAGGRESSIVE"}:
            normalized = "ULTRA_AGGRESSIVE"
        return MemGuardMode[normalized]

    def _wait_for_module_ready(self, timeout_ms: int = 6000) -> bool:
        if os.name != "nt":
            return True
        if self._module_ready:
            return True

        deadline = monotonic() + (max(1, int(timeout_ms)) / 1000.0)
        while monotonic() < deadline:
            if self._module_ready:
                return True
            if self._load_error:
                return False
            sleep(0.01)

        return self._module_ready

    def ensure_ready_for_sensitive_action(self, action_name: str) -> bool:
        if not self.is_protection_required():
            return True

        self.start()

        # IMPORTANT: keep this path non-blocking to avoid UI freezes when users
        # trigger file operations from the main thread.
        if self._load_error:
            self.host.status_bar.showMessage(
                f"Security module failed to load — cannot continue {action_name}.",
                4000,
            )
            return False
        if not self._module_ready:
            self.host.status_bar.showMessage(
                f"Security module still initializing — please retry {action_name} in a moment.",
                3000,
            )
            return False

        self.configure()
        if self.mem_guard_checker is not None and self.mem_guard_thread is not None:
            return True

        self.host.status_bar.showMessage(
            f"Security module still initializing — please wait before {action_name}.",
            3000,
        )
        return False

    def _start_async_load(self):
        if os.name != "nt" or self._loader_thread is not None:
            return

        def _loader():
            try:
                from ..utils import mem_guard as mg
                self._api = {
                    "MemGuardChecker": mg.MemGuardChecker,
                    "MemGuardMode": mg.MemGuardMode,
                    "is_mem_guard_supported": mg.is_mem_guard_supported,
                    "file_sha256": mg.file_sha256,
                }
                self._module_ready = True
            except (ImportError, OSError, RuntimeError, ValueError) as e:
                self._load_error = str(e)

        self._loader_thread = threading.Thread(target=_loader, daemon=True)
        self._loader_thread.start()

    def _start_bootstrap_timer(self):
        if os.name != "nt" or self._bootstrap_timer is not None:
            return

        self._bootstrap_timer = QTimer(self.host)
        self._bootstrap_timer.setInterval(150)
        self._bootstrap_timer.timeout.connect(self._on_bootstrap_tick)
        self._bootstrap_timer.start()

    def _on_bootstrap_tick(self):
        if self._load_error:
            if self._bootstrap_timer is not None:
                self._bootstrap_timer.stop()
            self.logger.warning("Memory guard module failed to load asynchronously: %s", self._load_error)
            return

        if self._module_ready:
            if self._bootstrap_timer is not None:
                self._bootstrap_timer.stop()
            self.configure()

    def _ensure_self_whitelist(self):
        if not self._module_ready or not getattr(sys, "frozen", False):
            return

        exe_path = os.path.abspath(sys.executable)
        if not exe_path or not os.path.exists(exe_path):
            return

        digest = self._api.get("file_sha256", lambda _p: "")(exe_path)
        entries = self.preferences.mem_guard_whitelist
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
            if changed:
                self.preferences.save_preferences()
            return

        entries.append({"path": exe_path, "sha256": digest.lower() if digest else ""})
        self.preferences.save_preferences()

    def configure(self):
        if self._disabled_until_restart or not self._module_ready:
            return

        if not self.stop():
            self.logger.error("Skipping mem guard reconfiguration because previous worker is still shutting down")
            self._disabled_until_restart = True
            self.host.status_bar.showMessage("Memory guard disabled until restart (worker did not stop cleanly)", 8000)
            return

        if not self.preferences.session_cache_enabled:
            return

        is_supported = self._api.get("is_mem_guard_supported", lambda: False)
        if not is_supported():
            return

        MemGuardMode = self._api["MemGuardMode"]
        MemGuardChecker = self._api["MemGuardChecker"]
        try:
            mode = self._parse_mode(self.preferences.mem_guard_mode, MemGuardMode)
        except (KeyError, ValueError):
            return
        if mode == MemGuardMode.OFF:
            return

        self._ensure_self_whitelist()

        self.mem_guard_thread = QThread()
        self.mem_guard_checker = MemGuardChecker(
            mode=mode,
            whitelist=self.preferences.mem_guard_whitelist,
            check_interval_ms=self.preferences.mem_guard_scan_interval_ms,
            pid_handle_cache_cap=self.preferences.mem_guard_pid_cache_cap,
            enhanced_detection_enabled=bool(getattr(self.preferences, "mem_guard_etw_enabled", False)),
        )
        self.mem_guard_checker.moveToThread(self.mem_guard_thread)
        self.mem_guard_thread.started.connect(self.mem_guard_checker.run)
        self.mem_guard_checker.memory_probe_detected.connect(self.host.on_memory_probe_detected)
        if hasattr(self.mem_guard_checker, "process_watcher_status_changed"):
            self.mem_guard_checker.process_watcher_status_changed.connect(self._on_process_watcher_status_changed)
            self._on_process_watcher_status_changed(getattr(self.mem_guard_checker, "process_watcher_status", None))
        self.mem_guard_thread.start()

    def _on_process_watcher_status_changed(self, status) -> None:
        if status is None:
            return
        enabled = bool(getattr(self.preferences, "mem_guard_etw_enabled", False))
        reason = str(getattr(status, "reason", "") or "")
        permission_denied = bool(getattr(status, "permission_denied", False))
        available = bool(getattr(status, "available", False))

        changed = False
        if str(getattr(self.preferences, "mem_guard_etw_last_error", "") or "") != reason:
            self.preferences.mem_guard_etw_last_error = reason
            changed = True
        if bool(getattr(self.preferences, "mem_guard_etw_permission_denied", False)) != permission_denied:
            self.preferences.mem_guard_etw_permission_denied = permission_denied
            changed = True
        if changed and hasattr(self.preferences, "save_preferences"):
            self.preferences.save_preferences()

        if not enabled or available or self._etw_status_notice_shown:
            return

        if permission_denied:
            self.host.status_bar.showMessage(
                "Enhanced detection unavailable without Administrator privileges. Using polling mode.",
                6000,
            )
        else:
            self.host.status_bar.showMessage(
                "Process watcher unavailable on this system. Using polling mode.",
                6000,
            )
        self._etw_status_notice_shown = True

    def stop(self) -> bool:
        if self.mem_guard_checker is not None:
            self.mem_guard_checker.stop()
        if self.mem_guard_thread is not None:
            self.mem_guard_thread.quit()
            if not self.mem_guard_thread.wait(5000):
                self.logger.error("Mem guard thread did not stop gracefully; terminate() is disabled for safety")
                return False
        self.mem_guard_checker = None
        self.mem_guard_thread = None
        return True
