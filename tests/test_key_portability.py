import os

from pangcrypter.core import key as key_module


def test_drive_secret_prefers_usb_file(tmp_path):
    drive_root = str(tmp_path)
    folder = tmp_path / key_module.KEY_FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    secret_path = folder / "secret.bin"

    file_secret = os.urandom(key_module.KEY_SIZE)
    secret_path.write_bytes(file_secret)

    resolved = key_module.get_or_create_drive_secret(drive_root)

    assert resolved == file_secret


def test_drive_secret_generates_when_missing(tmp_path):
    drive_root = str(tmp_path)
    secret_path = tmp_path / key_module.KEY_FOLDER / "secret.bin"
    assert not secret_path.exists()

    resolved = key_module.get_or_create_drive_secret(drive_root)

    assert secret_path.exists()
    assert secret_path.read_bytes() == resolved
    assert len(resolved) == key_module.KEY_SIZE
