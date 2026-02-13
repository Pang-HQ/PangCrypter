import ctypes
import logging
import sys
import os

logger = logging.getLogger(__name__)

def run_as_admin():
    if os.name != "nt":
        return False  # Only relevant for Windows

    try:
        # ShellExecuteEx to request elevation
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        if ret <= 32:
            raise OSError(f"Failed to elevate, error code {ret}")
        sys.exit(0)  # Relaunched with admin, exit current process
    except (OSError, AttributeError) as e:
        logger.error("Failed to run as admin: %s", e)
        return False
