from __future__ import annotations

import importlib
import threading
from types import ModuleType
from typing import Optional


class UpdateDialogLoader:
    def __init__(self):
        self._lock = threading.Lock()
        self._module: Optional[ModuleType] = None
        self._loading = False

    def _load(self):
        with self._lock:
            if self._module is not None or self._loading:
                return
            self._loading = True
        try:
            module = importlib.import_module("pangcrypter.ui.update_dialog")
            with self._lock:
                self._module = module
        finally:
            with self._lock:
                self._loading = False

    def preload_async(self):
        with self._lock:
            if self._module is not None or self._loading:
                return
        threading.Thread(target=self._load, daemon=True).start()

    def is_ready(self) -> bool:
        with self._lock:
            return self._module is not None

    def create_dialog(self, parent=None):
        if self._module is None:
            self._load()
        return self._module.UpdateDialog(parent)


update_dialog_loader = UpdateDialogLoader()
