import os, hashlib, platform, plistlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encrypt import EncryptModeType, SALT_SIZE, UUID_SIZE
from uuid import UUID
from typing import Optional

KEY_SIZE = 32
KEY_FOLDER = ".pangcrypt_keys"


def get_file_id(path: str) -> str:
    """
    Reads the UUID from the encrypted file header as the stable file ID.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 1 + SALT_SIZE + UUID_SIZE:
        # For key-only mode, salt might not exist; handle minimal length for each mode:
        # Minimal length with mode and UUID only is 1 + UUID_SIZE
        # So check minimum for key-only mode (no salt)
        if len(data) < 1 + UUID_SIZE:
            raise ValueError("File too short to contain a UUID")

    mode_byte = data[0]
    try:
        mode = EncryptModeType(mode_byte)
    except ValueError:
        raise ValueError(f"Invalid mode byte: {mode_byte}")

    # Extract UUID depending on mode
    if mode in (EncryptModeType.MODE_PASSWORD_ONLY, EncryptModeType.MODE_PASSWORD_PLUS_KEY):
        # mode(1) + salt(16) + uuid(16)
        uuid_bytes = data[1 + SALT_SIZE:1 + SALT_SIZE + UUID_SIZE]
    elif mode == EncryptModeType.MODE_KEY_ONLY:
        # mode(1) + uuid(16)
        uuid_bytes = data[1:1 + UUID_SIZE]
    else:
        raise ValueError("Unsupported mode")

    return uuid_bytes.hex()


def encrypt_random_key_with_hwid(random_key: bytes, hardware_id: bytes) -> bytes:
    """
    Encrypt the random_key with a key derived from hardware_id.
    Returns combined_key (encrypted random_key + nonce).
    """
    # Derive AES key from hardware_id using HKDF (or just hash)
    aes_key = hashlib.sha256(hardware_id).digest()  # 32 bytes

    # AESGCM requires 12-byte nonce
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted = aesgcm.encrypt(nonce, random_key, None)

    # Store nonce + ciphertext
    return nonce + encrypted

def decrypt_random_key_with_hwid(combined_key: bytes, hardware_id: bytes) -> bytes:
    """
    Decrypt the combined_key to retrieve the original random_key.
    """
    aes_key = hashlib.sha256(hardware_id).digest()
    nonce = combined_key[:12]
    ciphertext = combined_key[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def get_drive_hardware_id(drive_path: str) -> bytes:
    """
    Attempt to get a stable hardware ID for the drive, platform-dependent.
    Returns 32-byte hash to be used as HKDF salt.

    Improvements:
    - Windows: prefer WMI volume serial via 'wmic' or PowerShell.
    - macOS: parse diskutil plist output.
    - Linux: use blkid, fallback to hashing drive_path.
    """
    system = platform.system()
    if system == "Windows":
        # Prefer WMI query for volume serial number
        try:
            import subprocess
            drive_letter = drive_path.rstrip("\\/")[:2]  # e.g. "F:"
            # Use wmic logicaldisk get VolumeSerialNumber
            cmd = ['wmic', 'logicaldisk', 'where', f"DeviceID='{drive_letter}'", 'get', 'VolumeSerialNumber', '/value']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Output like: VolumeSerialNumber=XXXXXX
            for line in result.stdout.splitlines():
                if line.startswith("VolumeSerialNumber="):
                    serial = line.strip().split("=", 1)[1]
                    if serial:
                        serial_bytes = bytes.fromhex(serial)
                        return hashlib.sha256(serial_bytes).digest()
        except Exception:
            pass

        # Fallback to vol command as before
        try:
            drive_letter = drive_path.rstrip("\\/")[:2]
            result = subprocess.run(["vol", drive_letter], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "Serial Number is" in line:
                    serial_str = line.strip().split()[-1]
                    serial_bytes = bytes.fromhex(serial_str.replace("-", ""))
                    return hashlib.sha256(serial_bytes).digest()
        except Exception:
            pass

    elif system == "Linux":
        try:
            result = subprocess.run(["blkid", "-s", "UUID", "-o", "value", drive_path], capture_output=True, text=True, check=True)
            uuid_str = result.stdout.strip()
            if uuid_str:
                return hashlib.sha256(uuid_str.encode('utf-8')).digest()
        except Exception:
            pass

    elif system == "Darwin":
        # Use diskutil info -plist <drive> and parse plist for VolumeUUID
        try:
            result = subprocess.run(["diskutil", "info", "-plist", drive_path], capture_output=True, check=True)
            plist = plistlib.loads(result.stdout)
            volume_uuid = plist.get("VolumeUUID", None)
            if volume_uuid:
                return hashlib.sha256(volume_uuid.encode('utf-8')).digest()
        except Exception:
            pass

    # Fallback: hash drive path string (less secure)
    return hashlib.sha256(drive_path.encode("utf-8")).digest()


def get_drive_root_path(drive_name: str) -> str:
    """
    Returns the root path of the drive.
    """
    return drive_name


def generate_secure_key() -> bytes:
    """Generate a secure random 32-byte key."""
    return os.urandom(KEY_SIZE)


def get_key_path(drive_root: str, path: str, uuid: UUID) -> str:
    """Returns the full path to the key file inside the hidden folder."""
    folder = os.path.join(drive_root, KEY_FOLDER)
    os.makedirs(folder, exist_ok=True)

    if os.name == "nt":
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            attrs = ctypes.windll.kernel32.GetFileAttributesW(folder)
            if attrs != -1 and not (attrs & FILE_ATTRIBUTE_HIDDEN):
                ctypes.windll.kernel32.SetFileAttributesW(folder, attrs | FILE_ATTRIBUTE_HIDDEN)
        except Exception as e:
            print(f"Warning: Could not hide folder {folder}: {e}")

    if not uuid:
        raise ValueError("UUID must be provided to generate key path.")
    
    return os.path.join(folder, f"{uuid.hex}.bin")


def create_or_load_key(drive_name: str, path: str, uuid: Optional[UUID] = None, create: bool = True) -> tuple[bytes, UUID]:
    drive_root = get_drive_root_path(drive_name)
    
    # If UUID not provided, derive it from the file
    file_uuid = uuid
    if not file_uuid:
        try:
            file_id_hex = get_file_id(path)
            file_uuid = UUID(file_id_hex)
        except Exception:
            if not create:
                raise ValueError(f"Could not derive UUID from {path}. Ensure it is a valid encrypted file.")
    
    if not file_uuid:
        raise ValueError("No UUID provided and could not derive from file.")
    
    key_path = get_key_path(drive_root, path, file_uuid)
    hardware_id = get_drive_hardware_id(drive_root)

    if os.path.exists(key_path):
        # Load combined key (encrypted random_key)
        with open(key_path, "rb") as f:
            combined_key = f.read()
        random_key = decrypt_random_key_with_hwid(combined_key, hardware_id)
    elif create:
        # Generate new random key
        random_key = generate_secure_key()
        combined_key = encrypt_random_key_with_hwid(random_key, hardware_id)
        with open(key_path, "wb") as f:
            f.write(combined_key)
    else:
        return None, None

    return random_key, file_uuid


if __name__ == "__main__":
    drive = "F:/"
    filename = "mysecretfile"
    key = create_or_load_key(drive, filename)
    print(f"Derived key for {filename} on {drive}: {key.hex()}")
