"""
Release automation script for PangCrypter.

Flow:
1) Prompt for version (IP-style, 4 parts, max 2 digits each)
2) Update version.txt and pangcrypter/__init__.py
3) Run scripts/build.py
4) Generate SHA-256 checksum for dist/PangCrypter.zip
5) Sign ZIP with minisign (detached .minisig)
6) Create release notes draft and open in VS Code
7) Publish GitHub release via gh (draft by default, --fullpublish for immediate)
8) Roll back version files if publishing is cancelled or fails
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "version.txt"
INIT_FILE = ROOT / "pangcrypter" / "__init__.py"
DIST_DIR = ROOT / "dist"
ZIP_NAME = "PangCrypter.zip"
CHECKSUM_SUFFIX = ".sha256"
MINISIG_SUFFIX = ".minisig"
RELEASE_NOTES_NAME = "release-notes.md"


@dataclass
class BackupFiles:
    version_text: str
    init_text: str


def read_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def backup_version_files() -> BackupFiles:
    return BackupFiles(
        version_text=read_file(VERSION_FILE),
        init_text=read_file(INIT_FILE),
    )


def restore_version_files(backup: BackupFiles) -> None:
    write_file(VERSION_FILE, backup.version_text)
    write_file(INIT_FILE, backup.init_text)


def parse_current_version() -> str:
    text = read_file(INIT_FILE)
    match = re.search(r"__version__\s*=\s*[\"']([0-9\.]+)[\"']", text)
    return match.group(1) if match else "0.0.0.0"


def prompt_version(current: str) -> str:
    print(f"Input version number (Current: {current}): __.__.__.__")
    while True:
        parts = []
        for i in range(4):
            while True:
                raw = input(f"Part {i + 1} (0-99): ").strip()
                if not raw.isdigit():
                    print("  ❌ Digits only.")
                    continue
                if len(raw) > 2:
                    print("  ❌ Max 2 digits.")
                    continue
                value = int(raw)
                if value < 0 or value > 99:
                    print("  ❌ Must be 0-99.")
                    continue
                parts.append(str(value))
                break
        version = ".".join(parts)
        confirm = input(f"Use version {version}? [y/N]: ").strip().lower()
        if confirm == "y":
            return version


def update_version_txt(content: str, version: str) -> str:
    parts = version.split(".")
    version_tuple = ", ".join(parts)
    content = re.sub(r"filevers=\([^\)]*\)", f"filevers=({version_tuple})", content)
    content = re.sub(r"prodvers=\([^\)]*\)", f"prodvers=({version_tuple})", content)
    content = re.sub(r"FileVersion',\s*'[^']*'", f"FileVersion', '{version}'", content)
    content = re.sub(r"ProductVersion',\s*'[^']*'", f"ProductVersion', '{version}'", content)
    return content


def update_init_version(content: str, version: str) -> str:
    if "__version__" not in content:
        raise RuntimeError("__version__ not found in pangcrypter/__init__.py")
    return re.sub(r"__version__\s*=\s*[\"'][^\"']+[\"']", f"__version__ = \"{version}\"", content)


def run_build() -> None:
    print("\n▶ Running build script...")
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "build.py")])
    if result.returncode != 0:
        raise RuntimeError("Build failed.")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_checksum(zip_path: Path) -> Path:
    checksum = sha256_file(zip_path)
    checksum_path = zip_path.with_suffix(zip_path.suffix + CHECKSUM_SUFFIX)
    checksum_path.write_text(f"{checksum}  {zip_path.name}\n", encoding="utf-8")
    return checksum_path


def sign_with_minisign(zip_path: Path, minisign_secret_key: Path) -> Path:
    signature_path = zip_path.with_suffix(zip_path.suffix + MINISIG_SUFFIX)
    cmd = [
        "minisign",
        "-S",
        "-s",
        str(minisign_secret_key),
        "-m",
        str(zip_path),
        "-x",
        str(signature_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            "minisign signing failed. Ensure minisign is installed and key is valid.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return signature_path


def write_release_notes(version: str, checksum: str) -> Path:
    notes_path = DIST_DIR / RELEASE_NOTES_NAME
    content = (
        f"# PangCrypter v{version}\n\n"
        f"## ✅ Checksums\n"
        f"{ZIP_NAME}  {checksum}\n\n"
        f"## 📝 Changes\n"
        f"- (write changes here)\n"
    )
    notes_path.write_text(content, encoding="utf-8")
    return notes_path


def open_in_vscode(path: Path) -> None:
    print(f"\n▶ Opening release notes in VS Code: {path}")
    subprocess.run(["code", str(path)])


def ensure_gh_cli() -> None:
    result = subprocess.run(["gh", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            "GitHub CLI (gh) not found. Install from https://cli.github.com/ and authenticate via 'gh auth login'."
        )


def publish_release(
    version: str,
    zip_path: Path,
    checksum_path: Path,
    minisig_path: Path,
    notes_path: Path,
    full_publish: bool,
) -> None:
    tag = f"v{version}"
    title = version
    cmd = [
        "gh", "release", "create", tag,
        str(zip_path),
        str(checksum_path),
        str(minisig_path),
        "--title", title,
        "--notes-file", str(notes_path),
    ]
    if not full_publish:
        cmd.append("--draft")

    print("\n▶ Publishing GitHub release...")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise RuntimeError("GitHub release publish failed.")


def confirm_publish() -> bool:
    confirm = input("\nPublish GitHub release now? [Y/N]: ").strip().lower()
    return confirm == "y"


def main() -> int:
    parser = argparse.ArgumentParser(description="PangCrypter release automation")
    parser.add_argument("--fullpublish", action="store_true", help="Publish immediately (default: draft)")
    parser.add_argument(
        "--minisign-key",
        help="Path to minisign secret key. If omitted, uses PANGCRYPTER_MINISIGN_SECRET_KEY env var.",
    )
    args = parser.parse_args()

    backup = backup_version_files()
    try:
        current_version = parse_current_version()
        version = prompt_version(current_version)

        print("\n▶ Updating version files...")
        version_txt = update_version_txt(backup.version_text, version)
        init_txt = update_init_version(backup.init_text, version)
        write_file(VERSION_FILE, version_txt)
        write_file(INIT_FILE, init_txt)

        run_build()

        zip_path = DIST_DIR / ZIP_NAME
        if not zip_path.exists():
            raise RuntimeError(f"Expected ZIP not found: {zip_path}")

        checksum_path = write_checksum(zip_path)
        checksum_value = sha256_file(zip_path)
        minisign_key = args.minisign_key or os.getenv("PANGCRYPTER_MINISIGN_SECRET_KEY")
        if not minisign_key:
            raise RuntimeError(
                "Missing minisign secret key. Pass --minisign-key or set PANGCRYPTER_MINISIGN_SECRET_KEY."
            )
        minisig_path = sign_with_minisign(zip_path, Path(minisign_key))
        notes_path = write_release_notes(version, checksum_value)

        open_in_vscode(notes_path)
        input("\nPress Enter to continue after editing release notes...")

        ensure_gh_cli()

        if not confirm_publish():
            raise RuntimeError("Publish cancelled by user.")

        publish_release(version, zip_path, checksum_path, minisig_path, notes_path, args.fullpublish)

        print("\n✅ Release published successfully.")
        return 0
    except Exception as exc:
        print(f"\n❌ {exc}")
        print("Rolling back version files...")
        restore_version_files(backup)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())