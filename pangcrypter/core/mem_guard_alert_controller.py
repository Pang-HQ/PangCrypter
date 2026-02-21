from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

from ..core.preferences_proxy import PangPreferences
from ..ui.messagebox import PangMessageBox


class MemGuardAlertController:
    def __init__(self, host):
        self.host = host
        self._handling = False
        self._pending_findings: list[Any] = []
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

        finding = self._pending_findings.pop(0)
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
                self.host.close()
                return

            confirm = PangMessageBox.question(
                self.host,
                "Risk Confirmation",
                "I understand the risks and want to continue.",
                buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                default=PangMessageBox.StandardButton.No,
            )
            if confirm != PangMessageBox.StandardButton.Yes:
                self.host.close()
                return

            if clicked == whitelist_btn and finding.process_path:
                current_entries = PangPreferences.mem_guard_whitelist
                exists = False
                for item in current_entries:
                    if isinstance(item, dict) and item.get("path") == finding.process_path and str(item.get("sha256", "")).lower() == finding.sha256.lower():
                        exists = True
                        break
                if not exists:
                    PangPreferences.mem_guard_whitelist.append({"path": finding.process_path, "sha256": finding.sha256})
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
