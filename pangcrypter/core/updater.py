"""ZIP updater with checksum + minisign verification.

Security notes:
- SHA-256 checksums alone are not sufficient for supply-chain trust.
- PangCrypter requires a pinned minisign public key to verify update payloads.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from packaging import version
from ..utils.system_binaries import resolve_trusted_binary

logger = logging.getLogger(__name__)


class UpdaterError(Exception):
    pass


@dataclass
class UpdateReport:
    checksum_verified: bool = False
    signature_verified: bool = False
    publisher_verified: bool = False
    backup_dir: Optional[str] = None


class AutoUpdater:
    """Handles automatic ZIP updates for PangCrypter."""

    GITHUB_API_URL = "https://api.github.com/repos/Pang-HQ/PangCrypter/releases/latest"
    GITHUB_RELEASES_URL = "https://api.github.com/repos/Pang-HQ/PangCrypter/releases"
    REQUIRE_CHECKSUM = True
    REQUIRE_MINISIGN = True
    MINISIGN_BINARY = "minisign"
    # Keep a pinned minisign key in-app (trust anchor).
    # This must be the raw key value only (no comments).
    TRUSTED_MINISIGN_PUBKEY = "RWRT41WQfq43N+sP5WjML1rUvI6EePQvMj9IFS7UulgkX85PCcfi5oI0"
    BACKUP_DIR_NAME = ".pangcrypter_backups"

    def __init__(self):
        self.current_version = self._get_current_version()
        self.last_update_report = UpdateReport()

    def _resolve_minisign_binary(self) -> str:
        env_path = os.getenv("PANGCRYPTER_MINISIGN_PATH", "").strip()
        candidates: list[str] = []

        # 1) Prefer a bundled minisign next to the running app (or cwd for local runs).
        local_candidates: list[Path] = []
        if os.name == "nt":
            local_names = ("minisign.exe",)
        else:
            local_names = ("minisign",)

        app_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd().resolve()
        for name in local_names:
            local_candidates.append(app_dir / name)
            local_candidates.append(Path.cwd().resolve() / name)

        for candidate in local_candidates:
            if candidate.exists() and candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

        if env_path:
            candidates.append(env_path)

        if os.name == "nt":
            candidates.extend([
                str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "minisign" / "minisign.exe"),
                str(Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "minisign" / "minisign.exe"),
            ])
        else:
            candidates.extend(["/usr/bin/minisign", "/usr/local/bin/minisign"])

        try:
            return resolve_trusted_binary(self.MINISIGN_BINARY, explicit_candidates=candidates)
        except RuntimeError as e:
            raise UpdaterError(
                "No minisign binary found. Bundle minisign next to PangCrypter.exe, place it in PATH/trusted location, "
                "or set PANGCRYPTER_MINISIGN_PATH to a valid absolute path."
            ) from e

    def _project_root(self) -> Path:
        return Path(__file__).resolve().parents[2]

    def _load_trusted_minisign_public_key(self) -> str:
        """Load trusted minisign public key with hardcoded pinning.

        Environment/file override is intentionally opt-in for development only.
        """
        if os.getenv("PANGCRYPTER_ALLOW_MINISIGN_PUBKEY_OVERRIDE") == "1":
            env_key = os.getenv("PANGCRYPTER_MINISIGN_PUBKEY", "").strip()
            if env_key:
                return env_key

            pubkey_file = self._project_root() / "minisign.pub"
            if pubkey_file.exists():
                return pubkey_file.read_text(encoding="utf-8").strip()

        return self.TRUSTED_MINISIGN_PUBKEY

    def get_last_update_report(self) -> UpdateReport:
        return self.last_update_report

    # --------------------------
    # Version
    # --------------------------
    def _get_current_version(self) -> str:
        try:
            version_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "version.txt",
            )
            with open(version_file, "r", encoding="utf-8") as f:
                content = f.read()
            for line in content.splitlines():
                if "filevers=" in line:
                    ver_tuple = line.split("filevers=(")[1].split(")")[0]
                    parts = [int(x) for x in ver_tuple.split(", ")]
                    return ".".join(map(str, parts))
        except (OSError, ValueError, IndexError) as e:
            logger.warning(f"Could not read version.txt: {e}")
            return "0.0.0.0"

    # --------------------------
    # Update check
    # --------------------------
    def check_for_updates(self) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str]]:
        try:
            headers = {
                "User-Agent": "PangCrypter-Updater/ZIP",
                "Accept": "application/vnd.github.v3+json",
            }
            r = requests.get(self.GITHUB_API_URL, headers=headers, timeout=15)
            r.raise_for_status()
            release = r.json()
            latest_version = release.get("tag_name", "").lstrip("v")
            if not latest_version:
                raise UpdaterError("No version tag in release.")
            update_available = version.parse(latest_version) > version.parse(self.current_version)
            zip_url, zip_name = self._get_zip_asset(release)
            minisig_url = self._get_minisig_asset(release, zip_name)
            checksum = self._get_release_checksum(release, zip_name)
            if self.REQUIRE_CHECKSUM and not checksum:
                raise UpdaterError("No SHA-256 checksum found in release metadata.")
            if self.REQUIRE_MINISIGN and not minisig_url:
                raise UpdaterError("No minisign signature asset found for release ZIP.")
            return update_available, latest_version, zip_url, checksum, minisig_url
        except requests.RequestException as e:
            raise UpdaterError(f"Network error: {e}")
        except (ValueError, TypeError, KeyError, UpdaterError) as e:
            raise UpdaterError(f"Update check failed: {e}")

    def get_available_versions(self) -> List[str]:
        releases = self._get_releases()
        versions = []
        for release in releases:
            tag = release.get("tag_name", "").lstrip("v")
            if tag and self._has_zip_asset(release):
                versions.append(tag)
        return versions

    def get_zip_url_for_version(self, target_version: str) -> Tuple[str, Optional[str], Optional[str]]:
        releases = self._get_releases()
        for release in releases:
            tag = release.get("tag_name", "").lstrip("v")
            if tag == target_version:
                zip_url, zip_name = self._get_zip_asset(release)
                checksum = self._get_release_checksum(release, zip_name)
                minisig_url = self._get_minisig_asset(release, zip_name)
                if self.REQUIRE_CHECKSUM and not checksum:
                    raise UpdaterError("No SHA-256 checksum found in release metadata.")
                if self.REQUIRE_MINISIGN and not minisig_url:
                    raise UpdaterError("No minisign signature asset found for release ZIP.")
                return zip_url, checksum, minisig_url
        raise UpdaterError(f"No release found for version {target_version}")

    # --------------------------
    # Download
    # --------------------------
    def _create_session_temp_file(self, temp_root: str, suffix: str) -> str:
        fd, temp_path = tempfile.mkstemp(prefix="pang_update_", suffix=suffix, dir=temp_root)
        os.close(fd)
        return temp_path

    def download_zip(self, url: str, temp_root: str, progress_callback=None) -> str:
        temp_zip = self._create_session_temp_file(temp_root=temp_root, suffix=".zip")
        headers = {"User-Agent": "PangCrypter-Updater/ZIP"}
        with requests.get(url, headers=headers, stream=True, timeout=60) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            downloaded = 0
            with open(temp_zip, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if progress_callback and total > 0:
                            progress_callback(int(downloaded / total * 100), "Downloading...")
        return temp_zip

    def download_file(self, url: str, suffix: str, temp_root: str) -> str:
        temp_path = self._create_session_temp_file(temp_root=temp_root, suffix=suffix)
        headers = {"User-Agent": "PangCrypter-Updater/ZIP"}
        with requests.get(url, headers=headers, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(temp_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return temp_path

    # --------------------------
    # Verify ZIP
    # --------------------------
    def verify_zip(self, zip_path: str) -> bool:
        if not os.path.exists(zip_path):
            return False
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                bad = z.testzip()
                return bad is None
        except zipfile.BadZipFile:
            return False

    def verify_sha256(self, file_path: str, expected_hash: str) -> bool:
        if not expected_hash:
            return False
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest().lower() == expected_hash.lower()

    def verify_minisign(self, file_path: str, sig_path: str) -> bool:
        try:
            minisign_binary = self._resolve_minisign_binary()
        except UpdaterError as e:
            logger.error("%s", e)
            return False

        trusted_pubkey = self._load_trusted_minisign_public_key()
        cmd = [
            minisign_binary,
            "-V",
            "-m",
            file_path,
            "-x",
            sig_path,
            "-P",
            trusted_pubkey,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            logger.error("minisign binary not found on system PATH")
            return False
        if result.returncode != 0:
            logger.error("minisign verification failed: %s", (result.stderr or result.stdout).strip())
            return False
        return True

    # --------------------------
    # Install
    # --------------------------
    def install_zip_update(self, zip_path: str, temp_root: str) -> bool:
        if getattr(sys, "frozen", False):
            install_dir = os.path.dirname(sys.executable)
        else:
            install_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        extract_root = tempfile.mkdtemp(prefix="pang_extract_", dir=temp_root)

        backup_root = os.path.join(install_dir, self.BACKUP_DIR_NAME)
        os.makedirs(backup_root, exist_ok=True)
        backup_dir = os.path.join(backup_root, f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(backup_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            self._safe_extract(zip_ref, extract_root)

        # Flatten if single root folder
        payload_root = extract_root
        root_items = os.listdir(extract_root)
        if len(root_items) == 1 and os.path.isdir(os.path.join(extract_root, root_items[0])):
            payload_root = os.path.join(extract_root, root_items[0])

        copied_files: list[tuple[str, str]] = []
        try:
            for root, _, files in os.walk(payload_root):
                rel_path = os.path.relpath(root, payload_root)
                dest_dir = os.path.join(install_dir, rel_path)
                os.makedirs(dest_dir, exist_ok=True)

                for file in files:
                    src = os.path.join(root, file)
                    dst = os.path.join(dest_dir, file)

                    if os.path.exists(dst):
                        backup_target = os.path.join(backup_dir, os.path.relpath(dst, install_dir))
                        os.makedirs(os.path.dirname(backup_target), exist_ok=True)
                        shutil.copy2(dst, backup_target)
                        copied_files.append((backup_target, dst))

                    temp_dst = f"{dst}.tmp"
                    shutil.copy2(src, temp_dst)
                    os.replace(temp_dst, dst)
            self.last_update_report.backup_dir = backup_dir
            return True
        except (OSError, shutil.Error) as e:
            logger.error("Update install failed, attempting rollback: %s", e)
            for backup_src, dst in copied_files:
                try:
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(backup_src, dst)
                except (OSError, shutil.Error) as rollback_error:
                    logger.error("Rollback copy failed for %s: %s", dst, rollback_error)
            raise UpdaterError(f"Install failed: {e}")
        finally:
            try:
                shutil.rmtree(extract_root)
            except OSError as cleanup_error:
                logger.debug("Updater cleanup could not remove extract root %s: %s", extract_root, cleanup_error)

    def restore_from_backup(self, backup_dir: str) -> bool:
        if not os.path.isdir(backup_dir):
            raise UpdaterError(f"Backup directory does not exist: {backup_dir}")

        if getattr(sys, "frozen", False):
            install_dir = os.path.dirname(sys.executable)
        else:
            install_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        for root, _, files in os.walk(backup_dir):
            rel_path = os.path.relpath(root, backup_dir)
            dest_dir = os.path.join(install_dir, rel_path)
            os.makedirs(dest_dir, exist_ok=True)
            for file in files:
                src = os.path.join(root, file)
                dst = os.path.join(dest_dir, file)
                tmp_dst = f"{dst}.tmp"
                shutil.copy2(src, tmp_dst)
                os.replace(tmp_dst, dst)
        return True

    # --------------------------
    # Full update
    # --------------------------
    def perform_update(self, progress_callback=None) -> bool:
        self.last_update_report = UpdateReport()
        if progress_callback:
            progress_callback(10, "Checking for updates...")
        update_available, latest_version, zip_url, checksum, minisig_url = self.check_for_updates()
        if not update_available:
            return False
        if progress_callback:
            progress_callback(30, f"Downloading {latest_version}...")
        temp_root = tempfile.mkdtemp(prefix="pang_update_session_")
        zip_path: Optional[str] = None
        sig_path: Optional[str] = None
        try:
            zip_path = self.download_zip(zip_url, temp_root=temp_root, progress_callback=progress_callback)
            if minisig_url:
                sig_path = self.download_file(minisig_url, ".minisig", temp_root=temp_root)
            if progress_callback:
                progress_callback(60, "Verifying SHA-256 checksum...")
            if checksum and not self.verify_sha256(zip_path, checksum):
                raise UpdaterError("SHA-256 checksum verification failed.")
            self.last_update_report.checksum_verified = bool(checksum)
            if progress_callback:
                progress_callback(70, "Verifying minisign signature...")
            if self.REQUIRE_MINISIGN:
                if not sig_path:
                    raise UpdaterError("Missing minisign signature for update package.")
                if not self.verify_minisign(zip_path, sig_path):
                    raise UpdaterError("minisign verification failed.")
                self.last_update_report.signature_verified = True
                self.last_update_report.publisher_verified = True
            if progress_callback:
                progress_callback(80, "Verifying ZIP...")
            if not self.verify_zip(zip_path):
                raise UpdaterError("ZIP verification failed.")
            if progress_callback:
                progress_callback(90, "Installing update...")
            success = self.install_zip_update(zip_path, temp_root=temp_root)
            if progress_callback:
                progress_callback(100, "Update complete!")
            return success
        finally:
            if zip_path and os.path.exists(zip_path):
                try:
                    os.remove(zip_path)
                except OSError:
                    logger.warning("Could not remove temporary ZIP file: %s", zip_path)
            if sig_path and os.path.exists(sig_path):
                try:
                    os.remove(sig_path)
                except OSError:
                    logger.warning("Could not remove temporary signature file: %s", sig_path)
            try:
                shutil.rmtree(temp_root)
            except OSError as cleanup_error:
                logger.debug("Updater cleanup could not remove session temp root %s: %s", temp_root, cleanup_error)

    # --------------------------
    # Restart
    # --------------------------
    def restart_application(self):
        exe = sys.executable
        args = sys.argv[:]
        subprocess.Popen([exe] + args)
        sys.exit(0)

    def _get_releases(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "PangCrypter-Updater/ZIP",
            "Accept": "application/vnd.github.v3+json",
        }
        r = requests.get(self.GITHUB_RELEASES_URL, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json()

    def _has_zip_asset(self, release: Dict[str, Any]) -> bool:
        assets = release.get("assets", [])
        return any(asset["name"].lower().endswith(".zip") for asset in assets)

    def _get_zip_asset(self, release: Dict[str, Any]) -> Tuple[str, str]:
        for asset in release.get("assets", []):
            name = asset["name"]
            if name.lower().endswith(".zip") and "pang" in name.lower():
                return asset["browser_download_url"], name
        raise UpdaterError("No ZIP asset found in release.")

    def _get_minisig_asset(self, release: Dict[str, Any], zip_name: str) -> Optional[str]:
        exact = f"{zip_name}.minisig".lower()
        for asset in release.get("assets", []):
            name = asset.get("name", "").lower()
            if name == exact:
                return asset["browser_download_url"]

        for asset in release.get("assets", []):
            name = asset.get("name", "").lower()
            if name.endswith(".minisig") and zip_name.lower() in name:
                return asset["browser_download_url"]
        return None

    def _get_release_checksum(self, release: Dict[str, Any], zip_name: str) -> Optional[str]:
        checksum = self._find_checksum_in_text(release.get("body", ""), zip_name)
        if checksum:
            return checksum

        for asset in release.get("assets", []):
            asset_name = asset.get("name", "").lower()
            if asset_name.endswith(".sha256") or asset_name.endswith(".sha256.txt"):
                checksum_text = self._download_text(asset["browser_download_url"])
                checksum = self._find_checksum_in_text(checksum_text, zip_name)
                if checksum:
                    return checksum
        return None

    def _download_text(self, url: str) -> str:
        headers = {"User-Agent": "PangCrypter-Updater/ZIP"}
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        return r.text

    def _find_checksum_in_text(self, text: str, zip_name: str) -> Optional[str]:
        if not text:
            return None

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.search(r"(?i)sha256\s*\([^\)]+\)\s*=\s*([a-f0-9]{64})", line)
            if match:
                return match.group(1)

            hash_match = re.search(r"\b[a-f0-9]{64}\b", line, re.I)
            if hash_match and (zip_name in line or line.lower().startswith("sha256")):
                return hash_match.group(0)

            if zip_name and zip_name in line:
                hash_match = re.search(r"\b[a-f0-9]{64}\b", line, re.I)
                if hash_match:
                    return hash_match.group(0)

        return None

    def _safe_extract(self, zip_ref: zipfile.ZipFile, extract_dir: str) -> None:
        base_path = Path(extract_dir).resolve()
        for member in zip_ref.infolist():
            normalized_name = member.filename.replace("\\", "/")
            member_path = Path(normalized_name)
            first_part = member_path.parts[0] if member_path.parts else ""
            if (
                member_path.is_absolute()
                or normalized_name.startswith("/")
                or normalized_name.startswith("\\")
                or normalized_name.startswith("//")
                or normalized_name.startswith("\\\\")
                or ".." in member_path.parts
            ):
                raise UpdaterError(f"Unsafe ZIP entry detected: {member.filename}")
            if ":" in first_part or re.match(r"^[A-Za-z]:", first_part):
                raise UpdaterError(f"Unsafe ZIP entry detected: {member.filename}")

            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == stat.S_IFLNK:
                raise UpdaterError(f"Unsafe ZIP entry detected: {member.filename}")

            resolved_path = (base_path / normalized_name).resolve()
            if not resolved_path.is_relative_to(base_path):
                raise UpdaterError(f"Unsafe ZIP entry detected: {member.filename}")

            if member.is_dir():
                resolved_path.mkdir(parents=True, exist_ok=True)
                continue

            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            with zip_ref.open(member, "r") as src, open(resolved_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
