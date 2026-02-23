from __future__ import annotations

import os
from collections import deque
from typing import Any

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

from ..preferences.proxy import PangPreferences
from ..ui.messagebox import PangMessageBox


class MemGuardAlertController:
    def __init__(self, host):
        self.host = host
        self._handling = False
        self._pending_findings: deque[Any] = deque()
        self._pending_keys: set[tuple[int, str, int, str]] = set()

    def enqueue(self, finding: Any) -> None:
        key = (
            int(finding.pid),
            finding.severity.value,
            int(finding.access_mask),
            finding.process_path or "",
        )
        if key in self._pending_keys:
            return
        self._pending_keys.add(key)
        self._pending_findings.append(finding)

    def handle(self, finding: Any) -> None:
        self.enqueue(finding)
        self._process_next()

    def _process_next(self) -> None:
        if self._handling or not self._pending_findings:
            return

        finding = self._pending_findings.popleft()
        key = (
            int(finding.pid),
            finding.severity.value,
            int(finding.access_mask),
            finding.process_path or "",
        )
        self._pending_keys.discard(key)

        self._handling = True
        try:
            panic_recovery = self.host._ensure_panic_recovery_service()
            panic_saved = panic_recovery.create_snapshot()
            self.host.clear_cached_secrets()
            self.host.editor.clear()
            self.host.privacy_guard.hide_editor_and_show_label()

            msg = PangMessageBox(self.host)
            msg.setWindowTitle("Potential Memory Access")
            details = (
                f"Process \"{finding.process_name}\" (PID {finding.pid}) has permissions that allow it to read PangCrypter's memory.\n\n"
                "This does not confirm that memory was read; it only indicates this process could read it.\n\n"
                "If this is expected behaviour (for example anti-cheat, EDR, or overlays), you can continue or whitelist this application."
            )
            if not panic_saved:
                details += "\nWarning: could not save panic snapshot, unsaved work may be lost."
            msg.setText(details)
            continue_btn = msg.addButton("Continue", QMessageBox.ButtonRole.AcceptRole)
            remember_btn = msg.addButton("Continue and remember this app hash", QMessageBox.ButtonRole.AcceptRole)
            whitelist_btn = msg.addButton("Whitelist this application", QMessageBox.ButtonRole.AcceptRole)
            exit_btn = msg.addButton("Exit program", QMessageBox.ButtonRole.DestructiveRole)
            msg.setMinimumWidth(640)
            msg.adjustSize()
            for btn in msg.buttons():
                btn.setMinimumWidth(190)
            msg.exec()

            clicked = msg.clickedButton()
            if clicked == exit_btn:
                self.host.close()
                return

            should_remember = clicked in (remember_btn, whitelist_btn)
            if clicked == continue_btn:
                should_remember = False

            if should_remember and finding.process_path:
                current_entries = PangPreferences.mem_guard_whitelist
                candidate_path = os.path.normcase(os.path.abspath(str(finding.process_path)))
                candidate_sha = str(finding.sha256 or "").lower()
                exists = False
                for item in current_entries:
                    if not isinstance(item, dict):
                        continue
                    existing_path = os.path.normcase(os.path.abspath(str(item.get("path", ""))))
                    existing_sha = str(item.get("sha256", "")).lower()
                    if existing_path == candidate_path and existing_sha == candidate_sha:
                        exists = True
                        break
                if not exists:
                    PangPreferences.mem_guard_whitelist.append({"path": os.path.abspath(str(finding.process_path)), "sha256": candidate_sha})
                    PangPreferences.save_preferences()
                    self.host.mem_guard_controller.configure()

            if panic_saved:
                restored = panic_recovery.restore_snapshot()
                if not restored:
                    PangMessageBox.warning(self.host, "Restore Failed", "Could not restore panic snapshot. Re-open file manually.")
            self.host.privacy_guard.try_restore_editor()
        finally:
            self._handling = False
            if self._pending_findings:
                QTimer.singleShot(0, self._process_next)
