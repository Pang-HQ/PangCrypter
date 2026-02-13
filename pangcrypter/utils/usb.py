import logging
import os
import platform
import subprocess

from ..ui.messagebox import PangMessageBox
from .system_binaries import resolve_trusted_binary

logger = logging.getLogger(__name__)


def list_usb_drives() -> list[str]:
    drives: list[str] = []
    system = platform.system()

    if system == "Windows":
        try:
            wmic_binary = resolve_trusted_binary("wmic", [r"C:\Windows\System32\wbem\wmic.exe"])
            result = subprocess.run(
                [wmic_binary, "logicaldisk", "where", "drivetype=2", "get", "deviceid"],
                capture_output=True,
                text=True,
                check=True,
                shell=False,
            )
            output = result.stdout
            for line in output.strip().splitlines():
                line = line.strip()
                if line and line != "DeviceID":
                    drive_path = line + "\\"
                    if os.access(drive_path, os.W_OK):
                        drives.append(drive_path)
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            logger.warning("Windows USB detection failed: %s", e)

    elif system == "Linux":
        media_paths = ["/media", "/run/media"]
        for media_root in media_paths:
            if os.path.exists(media_root):
                for user_folder in os.listdir(media_root):
                    user_path = os.path.join(media_root, user_folder)
                    if os.path.isdir(user_path):
                        for mount in os.listdir(user_path):
                            mount_path = os.path.join(user_path, mount)
                            if os.path.ismount(mount_path) and os.access(mount_path, os.W_OK):
                                drives.append(mount_path)

    elif system == "Darwin":
        volumes_path = "/Volumes"
        if os.path.exists(volumes_path):
            for volume in os.listdir(volumes_path):
                vol_path = os.path.join(volumes_path, volume)
                if os.path.ismount(vol_path) and os.access(vol_path, os.W_OK):
                    drives.append(vol_path)
    else:
        PangMessageBox.warning(None, "Unsupported OS", "This script only supports Windows, Linux, and macOS.")

    return drives
