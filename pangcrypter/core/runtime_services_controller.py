from __future__ import annotations

from PyQt6.QtCore import QThread

from ..preferences.proxy import PangPreferences


class RuntimeServicesController:
    def __init__(self, host):
        self.host = host

    def start_deferred_services(self):
        if self.host.usb_cache_timer is None:
            return
        self.host.usb_cache_timer.start(5000)
        self.host.refresh_usb_cache()

        if self.host.screen_recorder_thread is None:
            from ..utils.screen_recording import ScreenRecordingChecker
            self.host.screen_recorder_thread = QThread()
            self.host.screen_recorder_checker = ScreenRecordingChecker(
                allowlist=set(getattr(PangPreferences, "screen_recording_allowlist", []) or [])
            )
            self.host.screen_recorder_checker.moveToThread(self.host.screen_recorder_thread)
            self.host.screen_recorder_thread.started.connect(self.host.screen_recorder_checker.run)
            self.host.screen_recorder_checker.screen_recording_changed.connect(self.host.privacy_guard.on_screen_recording_changed)
            self.host.screen_recorder_thread.start()

        self.host._ensure_mem_guard_controller().start()

    def stop_all(self):
        if self.host.mem_guard_controller is not None:
            self.host.mem_guard_controller.stop()
        if self.host.screen_recorder_checker is not None:
            self.host.screen_recorder_checker.stop()
        if self.host.screen_recorder_thread is not None:
            self.host.screen_recorder_thread.quit()
            self.host.screen_recorder_thread.wait(1500)
