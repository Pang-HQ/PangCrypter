import ctypes
import logging
import sys
import os
import subprocess

logger = logging.getLogger(__name__)


def is_running_as_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

def run_as_admin():
    if os.name != "nt":
        return False  # Only relevant for Windows

    try:
        # For frozen builds, launch the app executable with user args (without argv[0]).
        # For source runs, launch python.exe with script path + args.
        if getattr(sys, "frozen", False):
            executable = sys.executable
            args = sys.argv[1:]
        else:
            executable = sys.executable
            args = sys.argv

        params = subprocess.list2cmdline(args)
        working_dir = os.path.dirname(executable) or None
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, working_dir, 1
        )
        if ret <= 32:
            raise OSError(f"Failed to elevate, error code {ret}")
        return True
    except (OSError, AttributeError) as e:
        logger.error("Failed to run as admin: %s", e)
        return False
