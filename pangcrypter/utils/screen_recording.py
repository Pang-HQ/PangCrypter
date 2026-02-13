import logging
from time import sleep

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

    def __init__(self, check_interval=1):
        super().__init__()
        self.check_interval = check_interval
        self.running = True
        self._last_status = False
        self.cached_procs = set()

    def stop(self):
        self.running = False

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

                recording_detected = any(pname in SCREEN_RECORDERS_LOWER for pname in new_procs)
                if self._last_status and not recording_detected:
                    recording_detected = any(proc in SCREEN_RECORDERS_LOWER for proc in current_procs)

                if recording_detected != self._last_status:
                    self._last_status = recording_detected
                    self.screen_recording_changed.emit(recording_detected)

            except (psutil.Error, OSError, RuntimeError) as e:
                logger.debug("Screen recorder process scan failed: %s", e)

            sleep(self.check_interval)
