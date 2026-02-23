import os

from pangcrypter.core import key as key_module


class _FakeKeyring:
    def __init__(self, stored_hex: str | None = None):
        self.stored_hex = stored_hex
        self.set_calls: list[tuple[str, str, str]] = []

    def get_password(self, _service: str, _username: str):
        return self.stored_hex

    def set_password(self, service: str, username: str, password: str):
        self.set_calls.append((service, username, password))
        self.stored_hex = password


def test_drive_secret_prefers_usb_file_and_syncs_keyring(tmp_path, monkeypatch):
    drive_root = str(tmp_path)
    folder = tmp_path / key_module.KEY_FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    secret_path = folder / "secret.bin"

    file_secret = os.urandom(key_module.KEY_SIZE)
    secret_path.write_bytes(file_secret)

    fake_keyring = _FakeKeyring(stored_hex=os.urandom(key_module.KEY_SIZE).hex())
    monkeypatch.setattr(key_module, "keyring_module", fake_keyring)

    resolved = key_module.get_or_create_drive_secret(drive_root)

    assert resolved == file_secret
    assert fake_keyring.set_calls
    assert fake_keyring.set_calls[-1][2] == file_secret.hex()


def test_drive_secret_migrates_from_keyring_to_usb_file(tmp_path, monkeypatch):
    drive_root = str(tmp_path)
    secret_path = tmp_path / key_module.KEY_FOLDER / "secret.bin"
    assert not secret_path.exists()

    keyring_secret = os.urandom(key_module.KEY_SIZE)
    fake_keyring = _FakeKeyring(stored_hex=keyring_secret.hex())
    monkeypatch.setattr(key_module, "keyring_module", fake_keyring)

    resolved = key_module.get_or_create_drive_secret(drive_root)

    assert resolved == keyring_secret
    assert secret_path.exists()
    assert secret_path.read_bytes() == keyring_secret
