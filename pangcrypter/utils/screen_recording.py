import logging
from time import sleep
from threading import Event

import psutil
from PyQt6.QtCore import QObject, pyqtSignal

logger = logging.getLogger(__name__)


SCREEN_RECORDERS_LOWER = {
    "obs64.exe",
    "obs32.exe",
    "obs.exe",
    "bandicam.exe",
    "camtasia.exe",
    "xsplit.exe",
    "ffmpeg.exe",
    "screenrecorder.exe",
    "screencast-o-matic.exe",
    "sharex.exe",
}


class ScreenRecordingChecker(QObject):
    screen_recording_changed = pyqtSignal(bool)

    def __init__(self, check_interval=1, allowlist: set[str] | None = None):
        super().__init__()
        self.check_interval = check_interval
        self.running = True
        self._stop_event = Event()
        self._last_status = False
        self.cached_procs: set[str] = set()
        self._allowlist = {str(item).strip().lower() for item in (allowlist or set()) if str(item).strip()}

    def set_allowlist(self, process_names):
        self._allowlist = {str(item).strip().lower() for item in (process_names or []) if str(item).strip()}

    def stop(self):
        self.running = False
        self._stop_event.set()

    def run(self):
        while self.running:
            try:
                current_procs = set()
                for proc in psutil.process_iter(["name"]):
                    try:
                        pname = proc.info["name"]
                        if pname:
                            current_procs.add(pname.lower())
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                new_procs = current_procs - self.cached_procs
                self.cached_procs = current_procs

                recording_detected = any(
                    pname in SCREEN_RECORDERS_LOWER and pname not in self._allowlist
                    for pname in new_procs
                )
                if self._last_status and not recording_detected:
                    recording_detected = any(
                        proc in SCREEN_RECORDERS_LOWER and proc not in self._allowlist
                        for proc in current_procs
                    )

                if recording_detected != self._last_status:
                    self._last_status = recording_detected
                    self.screen_recording_changed.emit(recording_detected)

            except (psutil.Error, OSError, RuntimeError) as e:
                logger.debug("Screen recorder process scan failed: %s", e)

            if self._stop_event.wait(self.check_interval):
                break
