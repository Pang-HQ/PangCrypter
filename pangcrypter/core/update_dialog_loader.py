from __future__ import annotations

from types import ModuleType
from typing import Optional


class UpdateDialogLoader:
    def __init__(self):
        self._module: Optional[ModuleType] = None

    def _load(self):
        if self._module is not None:
            return
        # Use a normal import statement so freezing tools (PyInstaller) can
        # statically detect and include this module.
        from ..ui import update_dialog as module

        self._module = module

    def preload_async(self):
        # NOTE:
        # Importing PyQt modules from a Python background thread can trigger
        # native Qt instability/crashes in frozen builds. Keep this preload on
        # the GUI/main thread (the caller already schedules it via QTimer).
        self._load()

    def is_ready(self) -> bool:
        return self._module is not None

    def create_dialog(self, parent=None):
        if self._module is None:
            self._load()
        return self._module.UpdateDialog(parent)


update_dialog_loader = UpdateDialogLoader()
