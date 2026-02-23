import zipfile

import pytest

from pangcrypter.updater.service import AutoUpdater, UpdaterError


def test_safe_extract_rejects_path_traversal(tmp_path):
    updater = AutoUpdater()
    zip_path = tmp_path / "evil.zip"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../escape.txt", "owned")

    with zipfile.ZipFile(zip_path, "r") as zf:
        with pytest.raises(UpdaterError):
            updater._safe_extract(zf, str(tmp_path / "out"))


def test_safe_extract_rejects_windows_drive_letter(tmp_path):
    updater = AutoUpdater()
    zip_path = tmp_path / "driveletter.zip"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("C:evil.txt", "owned")

    with zipfile.ZipFile(zip_path, "r") as zf:
        with pytest.raises(UpdaterError):
            updater._safe_extract(zf, str(tmp_path / "out_drive"))


def test_safe_extract_rejects_symlink_entry(tmp_path):
    updater = AutoUpdater()
    zip_path = tmp_path / "symlink.zip"

    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (0o120777 << 16)

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(info, "target")

    with zipfile.ZipFile(zip_path, "r") as zf:
        with pytest.raises(UpdaterError):
            updater._safe_extract(zf, str(tmp_path / "out_symlink"))


def test_perform_update_fails_on_invalid_signature(tmp_path, monkeypatch):
    updater = AutoUpdater()
    updater.current_version = "1.0.0"

    zip_path = tmp_path / "PangCrypter.zip"
    sig_path = tmp_path / "PangCrypter.zip.minisig"
    zip_path.write_bytes(b"dummy zip bytes")
    sig_path.write_text("dummy signature", encoding="utf-8")

    monkeypatch.setattr(
        updater,
        "check_for_updates",
        lambda: (True, "9.9.9", "https://example.invalid/update.zip", "a" * 64, "https://example.invalid/update.zip.minisig"),
    )
    monkeypatch.setattr(updater, "download_zip", lambda *_args, **_kwargs: str(zip_path))
    monkeypatch.setattr(updater, "download_file", lambda *_args, **_kwargs: str(sig_path))
    monkeypatch.setattr(updater, "verify_sha256", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(updater, "verify_minisign", lambda *_args, **_kwargs: False)

    with pytest.raises(UpdaterError, match="minisign verification failed"):
        updater.perform_update()

    assert not zip_path.exists()
    assert not sig_path.exists()

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
