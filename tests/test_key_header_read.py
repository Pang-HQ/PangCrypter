import builtins

from pangcrypter.core import key as key_module
from pangcrypter.core.format_config import MODE_OFFSET, SETTINGS_SIZE, SALT_SIZE, UUID_SIZE, encode_version


def test_get_file_id_reads_only_header_bytes(monkeypatch):
    class _FakeFile:
        def __init__(self, payload: bytes):
            self._payload = payload
            self._idx = 0
            self.read_calls = []

        def read(self, size=-1):
            self.read_calls.append(size)
            if size == -1:
                raise AssertionError("get_file_id() should not read entire file")
            start = self._idx
            end = min(len(self._payload), self._idx + size)
            self._idx = end
            return self._payload[start:end]

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    settings = bytearray(SETTINGS_SIZE)
    settings[0:2] = encode_version(1)
    settings[MODE_OFFSET] = 0
    salt = b"s" * SALT_SIZE
    uuid_bytes = bytes.fromhex("00112233445566778899aabbccddeeff")
    payload = bytes(settings) + salt + uuid_bytes + (b"x" * 1024)

    fake_file = _FakeFile(payload)

    monkeypatch.setattr(key_module.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(builtins, "open", lambda *_args, **_kwargs: fake_file)

    file_id = key_module.get_file_id("dummy.enc")

    assert file_id == uuid_bytes.hex()
    assert fake_file.read_calls == [SETTINGS_SIZE, SALT_SIZE + UUID_SIZE]
