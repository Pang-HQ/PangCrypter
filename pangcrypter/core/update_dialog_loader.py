from __future__ import annotations

import threading
from types import ModuleType
from typing import Optional


class UpdateDialogLoader:
    def __init__(self):
        self._module: Optional[ModuleType] = None
        self._backend_prewarm_started = False
        self._backend_prewarm_lock = threading.Lock()

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

    def preload_backend_async(self):
        """Pre-warm non-Qt updater dependencies in a background thread.

        This intentionally avoids importing any PyQt modules/widgets off-thread.
        """
        with self._backend_prewarm_lock:
            if self._backend_prewarm_started:
                return
            self._backend_prewarm_started = True

        def _worker():
            try:
                import requests  # type: ignore[import-untyped]  # noqa: F401
                from packaging import version as _version  # noqa: F401
                from ..updater import service as _updater  # noqa: F401
            except (ImportError, OSError, RuntimeError, ValueError):
                # Best-effort warmup only.
                return

        threading.Thread(target=_worker, daemon=True).start()

    def is_ready(self) -> bool:
        return self._module is not None

    def create_dialog(self, parent=None):
        if self._module is None:
            self._load()
        assert self._module is not None
        return self._module.UpdateDialog(parent)


update_dialog_loader = UpdateDialogLoader()
