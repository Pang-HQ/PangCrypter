import logging
import os
import platform
import ctypes
from ctypes import wintypes

logger = logging.getLogger(__name__)


def list_usb_drives() -> list[str]:
    drives: list[str] = []
    system = platform.system()

    if system == "Windows":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            get_logical_drives = kernel32.GetLogicalDrives
            get_logical_drives.restype = wintypes.DWORD

            get_drive_type = kernel32.GetDriveTypeW
            get_drive_type.argtypes = [wintypes.LPCWSTR]
            get_drive_type.restype = wintypes.UINT

            DRIVE_REMOVABLE = 2

            mask = int(get_logical_drives())
            for idx in range(26):
                if not (mask & (1 << idx)):
                    continue

                drive_letter = chr(ord("A") + idx)
                drive_path = f"{drive_letter}:\\"
                drive_type = int(get_drive_type(drive_path))
                if drive_type == DRIVE_REMOVABLE and os.access(drive_path, os.W_OK):
                    drives.append(drive_path)
        except (OSError, ValueError) as e:
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
        logger.warning("Unsupported OS for USB detection: %s", system)

    return drives
