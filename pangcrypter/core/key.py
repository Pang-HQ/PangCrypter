import hashlib
import getpass
import logging
import os
import platform
import plistlib
import stat
import subprocess
import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encrypt import EncryptModeType
from .format_config import (
    SETTINGS_SIZE,
    SALT_SIZE,
    UUID_SIZE,
    MODE_OFFSET,
    HEADER_VERSION,
    decode_version,
)
from ..utils.system_binaries import resolve_trusted_binary
from uuid import UUID
from typing import Optional

logger = logging.getLogger(__name__)

KEY_SIZE = 32
KEY_FOLDER = ".pangcrypt_keys"
SECRET_FILE = f"{KEY_FOLDER}/secret.bin"
KEY_VERSION = 0x01

_HWID_CACHE: dict[str, bytes] = {}

try:
    import keyring
except ImportError:
    keyring = None

KEYRING_SERVICE = "PangCrypter"


def get_file_id(path: str) -> str:
    """
    Reads the UUID from the encrypted file header as the stable file ID.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "rb") as f:
        data = f.read()

    min_len = SETTINGS_SIZE + SALT_SIZE + UUID_SIZE
    if len(data) < min_len:
        raise ValueError("File too short to contain a UUID")

    settings = data[:SETTINGS_SIZE]
    version = decode_version(settings[0:2])
    if version != HEADER_VERSION:
        raise ValueError(f"Unsupported file version: {version}")

    mode_byte = settings[MODE_OFFSET]
    try:
        _ = EncryptModeType(mode_byte)
    except ValueError:
        raise ValueError(f"Invalid mode byte: {mode_byte}")

    uuid_start = SETTINGS_SIZE + SALT_SIZE
    uuid_end = uuid_start + UUID_SIZE
    uuid_bytes = data[uuid_start:uuid_end]

    return uuid_bytes.hex()


def _drive_keyring_id(drive_root: str) -> str:
    return f"drive_secret::{os.path.abspath(drive_root)}"


def _read_secret_from_file(secret_path: str) -> Optional[bytes]:
    if not os.path.exists(secret_path):
        return None
    with open(secret_path, "rb") as f:
        secret = f.read()
    if len(secret) != KEY_SIZE:
        raise ValueError("Invalid drive secret size")
    return secret


def _set_posix_permissions(path: str, is_dir: bool = False) -> None:
    if os.name == "nt":
        return
    mode = stat.S_IRUSR | stat.S_IWUSR
    if is_dir:
        mode |= stat.S_IXUSR
    try:
        os.chmod(path, mode)
    except OSError as e:
        logger.warning("Failed to set secure permissions on %s: %s", path, e)


def _set_hidden_windows_folder(folder: str) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        attrs = ctypes.windll.kernel32.GetFileAttributesW(folder)
        if attrs != -1 and not (attrs & FILE_ATTRIBUTE_HIDDEN):
            ctypes.windll.kernel32.SetFileAttributesW(folder, attrs | FILE_ATTRIBUTE_HIDDEN)
    except (OSError, AttributeError) as e:
        logger.warning("Could not hide folder %s: %s", folder, e)


def _set_windows_restrictive_acl(path: str, is_dir: bool = False) -> None:
    """Best-effort ACL hardening on Windows.

    Hidden attributes are not a security boundary; this attempts to reduce
    accidental exposure by removing inherited ACLs and granting only the
    current user and SYSTEM full control.
    """
    if os.name != "nt":
        return

    user = getpass.getuser()
    grants = [f"{user}:(F)", "SYSTEM:(F)"]
    if is_dir:
        grants = [f"{user}:(OI)(CI)(F)", "SYSTEM:(OI)(CI)(F)"]

    try:
        icacls_binary = resolve_trusted_binary("icacls", [r"C:\Windows\System32\icacls.exe"])
    except RuntimeError as e:
        logger.warning("Could not resolve trusted icacls binary: %s", e)
        return

    cmd = [icacls_binary, path, "/inheritance:r"]
    for grant in grants:
        cmd.extend(["/grant:r", grant])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            logger.warning(
                "Could not harden Windows ACL for %s (code=%s): %s",
                path,
                result.returncode,
                (result.stderr or result.stdout).strip(),
            )
    except OSError as e:
        logger.warning("Could not execute icacls for %s: %s", path, e)


def _validate_drive_root(drive_root: str) -> str:
    normalized = os.path.abspath(drive_root)
    if not os.path.exists(normalized):
        raise ValueError(f"Drive root does not exist: {normalized}")
    if not os.path.isdir(normalized):
        raise ValueError(f"Drive root is not a directory: {normalized}")

    allow_non_removable = os.getenv("PANGCRYPTER_ALLOW_NON_REMOVABLE", "0") == "1"
    is_mount = os.path.ismount(normalized)
    if not is_mount and not allow_non_removable:
        raise ValueError(
            f"Refusing to store key material on non-mounted path: {normalized}. "
            "Set PANGCRYPTER_ALLOW_NON_REMOVABLE=1 only for development/testing."
        )
    if not is_mount:
        logger.warning("Using non-mounted path for key storage due to override: %s", normalized)

    return normalized


def _write_secret_to_file(folder: str, secret_path: str, secret: bytes) -> None:
    os.makedirs(folder, exist_ok=True)
    _set_posix_permissions(folder, is_dir=True)
    with open(secret_path, "wb") as f:
        f.write(secret)
    _set_posix_permissions(secret_path, is_dir=False)
    _set_hidden_windows_folder(folder)
    _set_windows_restrictive_acl(folder, is_dir=True)
    _set_windows_restrictive_acl(secret_path, is_dir=False)


def get_or_create_drive_secret(drive_root: str) -> bytes:
    """
    Load or generate a per-drive secret stored in OS keychain when available.
    Falls back to .pangcrypt_keys/secret.bin on the USB drive.
    """
    folder = os.path.join(drive_root, KEY_FOLDER)
    secret_path = os.path.join(folder, "secret.bin")

    if keyring:
        try:
            stored = keyring.get_password(KEYRING_SERVICE, _drive_keyring_id(drive_root))
            if stored:
                return bytes.fromhex(stored)
        except (ValueError, RuntimeError) as e:
            logger.warning("Failed to load drive secret from keyring: %s", e)

    secret = _read_secret_from_file(secret_path)
    if secret:
        return secret

    secret = os.urandom(KEY_SIZE)

    if keyring:
        try:
            keyring.set_password(KEYRING_SERVICE, _drive_keyring_id(drive_root), secret.hex())
            return secret
        except RuntimeError as e:
            logger.warning("Failed to store drive secret in keyring: %s", e)

    _write_secret_to_file(folder, secret_path, secret)
    return secret

def encrypt_random_key(random_key: bytes, hardware_id: bytes, drive_secret: bytes) -> bytes:
    """
    Encrypt the random_key with AESGCM using HWID + drive secret, including version byte.
    """

    aes_key = hashlib.sha256(hardware_id + drive_secret).digest()  # 32 bytes
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(nonce, random_key, None)
    
    return bytes([KEY_VERSION]) + nonce + ciphertext


def decrypt_random_key(combined_key: bytes, hardware_id: bytes, drive_secret: bytes) -> bytes:
    """
    Decrypt the random_key using AESGCM with HWID + drive secret, handling version.
    """
    if len(combined_key) < 1 + 12 + KEY_SIZE:
        raise ValueError("Key file too short or corrupted")
    
    version = combined_key[0]

    if version != KEY_VERSION:
        raise ValueError(f"Unsupported key version: {version}")

    nonce = combined_key[1:13]
    ciphertext = combined_key[13:]
    aes_key = hashlib.sha256(hardware_id + drive_secret).digest()
    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(nonce, ciphertext, None)


def get_drive_hardware_id(drive_path: str) -> bytes:
    """
    Attempt to get a stable hardware ID for the drive, platform-dependent.
    Returns 32-byte hash to be used as HKDF salt.

    Improvements:
    - Windows: query volume serial via WinAPI (no subprocess/console spawn).
    - macOS: parse diskutil plist output.
    - Linux: use blkid.
    """
    normalized_drive = os.path.abspath(drive_path)
    cached = _HWID_CACHE.get(normalized_drive)
    if cached:
        return cached

    system = platform.system()
    if system == "Windows":
        # Prefer WinAPI volume serial query to avoid spawning console subprocesses
        try:
            drive_letter = drive_path.rstrip("\\/")[:2]  # e.g. "F:"
            if len(drive_letter) != 2 or drive_letter[1] != ":":
                raise ValueError(f"Invalid Windows drive path: {drive_path}")
            root_path = f"{drive_letter}\\"

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            get_volume_information = kernel32.GetVolumeInformationW
            get_volume_information.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPWSTR,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPWSTR,
                wintypes.DWORD,
            ]
            get_volume_information.restype = wintypes.BOOL

            serial_number = wintypes.DWORD(0)
            max_component_len = wintypes.DWORD(0)
            file_system_flags = wintypes.DWORD(0)
            # We only need serial_number, so keep volume/fs-name buffers null.
            ok = bool(
                get_volume_information(
                    root_path,
                    None,
                    0,
                    ctypes.byref(serial_number),
                    ctypes.byref(max_component_len),
                    ctypes.byref(file_system_flags),
                    None,
                    0,
                )
            )
            if not ok:
                err = ctypes.get_last_error()
                raise OSError(err, f"GetVolumeInformationW failed for {root_path}")

            serial_int = int(serial_number.value)
            if serial_int == 0:
                raise ValueError(f"Invalid volume serial for {root_path}")

            serial_bytes = serial_int.to_bytes(4, byteorder="little", signed=False)
            hwid = hashlib.sha256(serial_bytes).digest()
            _HWID_CACHE[normalized_drive] = hwid
            return hwid
        except (OSError, ValueError) as e:
            raise RuntimeError(f"Failed to get hardware ID for {drive_path} on Windows: {e}")

    elif system == "Linux":
        try:
            blkid_binary = resolve_trusted_binary("blkid", ["/usr/sbin/blkid", "/sbin/blkid", "/usr/bin/blkid"])
            result = subprocess.run([blkid_binary, "-s", "UUID", "-o", "value", drive_path], capture_output=True, text=True, check=True)
            uuid_str = result.stdout.strip()
            if uuid_str:
                hwid = hashlib.sha256(uuid_str.encode('utf-8')).digest()
                _HWID_CACHE[normalized_drive] = hwid
                return hwid
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            raise RuntimeError(f"Failed to get hardware ID for {drive_path} on Linux: {e}")

    elif system == "Darwin":
        # Use diskutil info -plist <drive> and parse plist for VolumeUUID
        try:
            diskutil_binary = resolve_trusted_binary("diskutil", ["/usr/sbin/diskutil", "/usr/bin/diskutil"])
            result = subprocess.run([diskutil_binary, "info", "-plist", drive_path], capture_output=True, check=True)
            plist = plistlib.loads(result.stdout)
            volume_uuid = plist.get("VolumeUUID", None)
            if volume_uuid:
                hwid = hashlib.sha256(volume_uuid.encode('utf-8')).digest()
                _HWID_CACHE[normalized_drive] = hwid
                return hwid
        except (OSError, subprocess.SubprocessError, ValueError, plistlib.InvalidFileException) as e:
            raise RuntimeError(f"Failed to get hardware ID for {drive_path} on macOS: {e}")

    raise RuntimeError(f"Unsupported system or could not get hardware ID for drive {drive_path}")


def get_drive_root_path(drive_name: str) -> str:
    """
    Returns the root path of the drive.
    """
    return _validate_drive_root(drive_name)


def generate_secure_key() -> bytes:
    """Generate a secure random 32-byte key."""
    return os.urandom(KEY_SIZE)


def get_key_path(drive_root: str, path: str, uuid: UUID) -> str:
    """Returns the full path to the key file inside the hidden folder."""
    folder = os.path.join(drive_root, KEY_FOLDER)
    os.makedirs(folder, exist_ok=True)
    _set_posix_permissions(folder, is_dir=True)
    _set_hidden_windows_folder(folder)
    _set_windows_restrictive_acl(folder, is_dir=True)

    if not uuid:
        raise ValueError("UUID must be provided to generate key path.")
    
    return os.path.join(folder, f"{uuid.hex}.bin")


def create_or_load_key(drive_name: str, path: str, uuid: Optional[UUID] = None, create: bool = True) -> tuple[Optional[bytes], Optional[UUID]]:
    drive_root = get_drive_root_path(drive_name)
    
    file_uuid = uuid
    if not file_uuid:
        try:
            file_id_hex = get_file_id(path)
            file_uuid = UUID(file_id_hex)
        except (ValueError, FileNotFoundError):
            if not create:
                raise ValueError(f"Could not derive UUID from {path}. Ensure it is in a valid format.")
    
    if not file_uuid:
        raise ValueError("No UUID provided and could not derive from file.")
    
    key_path = get_key_path(drive_root, path, file_uuid)
    hardware_id = get_drive_hardware_id(drive_root)
    drive_secret = get_or_create_drive_secret(drive_root)

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            combined_key = f.read()
        random_key = decrypt_random_key(combined_key, hardware_id, drive_secret)
    elif create:
        random_key = generate_secure_key()
        combined_key = encrypt_random_key(random_key, hardware_id, drive_secret)
        with open(key_path, "wb") as f:
            f.write(combined_key)
        _set_posix_permissions(key_path, is_dir=False)
        _set_windows_restrictive_acl(key_path, is_dir=False)
    else:
        return None, None

    return random_key, file_uuid







