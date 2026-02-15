from __future__ import annotations

from PyQt6.QtWidgets import QApplication


class PrivacyGuardController:
    def __init__(self, host, preferences):
        self.host = host
        self.preferences = preferences

    def on_window_activate(self):
        self.host._apply_focus_reauth_policy()
        if self.preferences.screen_recording_hide_enabled and not self.host.allow_editor_activation:
            self.host.cooldown_remaining = self.preferences.recording_cooldown
            self.update_hidden_label_for_cooldown()
            self.host.cooldown_timer.start()

    def on_window_deactivate(self):
        if self.preferences.screen_recording_hide_enabled:
            self.host.cooldown_timer.stop()
        if self.preferences.session_cache_enabled and self.preferences.session_reauth_on_focus_loss:
            self.host.session_state.note_focus_lost()

    def update_cooldown(self):
        self.host.cooldown_remaining -= 1
        if self.host.cooldown_remaining <= 0:
            self.host.allow_editor_activation = True
            self.host.cooldown_timer.stop()
            self.host.hidden_label.setText(
                "Screen recording program detected.\n"
                "Make sure to close this window before recording.\n"
                "Click here to restore editor."
            )
        else:
            self.update_hidden_label_for_cooldown()

    def update_hidden_label_for_cooldown(self):
        self.host.hidden_label.setText(
            f"Screen recording program detected.\n"
            f"Make sure to close this window before recording.\n"
            f"Keep this window focused for {self.host.cooldown_remaining} seconds to restore editor."
        )

    def on_screen_recording_changed(self, is_recording: bool):
        self.host.allow_editor_activation = not is_recording
        if is_recording:
            self.hide_editor_and_show_label()
        elif self.host.hidden_label.isVisible():
            self.try_restore_editor()

    def on_editor_focus_lost(self):
        if not self.preferences.tab_out_hide_enabled:
            return

        active_window = QApplication.activeWindow()
        if active_window is None or not (active_window == self.host or self.host.isAncestorOf(active_window)):
            self.host.hidden_label.setText("Editor hidden due to focus loss. Click here to restore editor.")
            self.hide_editor_and_show_label()

        self.host._apply_focus_reauth_policy()

    def hide_editor_and_show_label(self):
        self.host.editor.hide()
        self.host.editor.setDisabled(True)
        self.host.hidden_label.show()

    def try_restore_editor(self) -> bool:
        if not self.host.allow_editor_activation:
            return False
        self.host.editor.setDisabled(False)
        self.host.hidden_label.hide()
        self.host.editor.show()
        self.host.editor.setFocus()
        return True

    def on_hidden_label_clicked(self, _event):
        self.try_restore_editor()
