"""ZIP updater with checksum + minisign verification.

Security notes:
- SHA-256 checksums alone are not sufficient for supply-chain trust.
- PangCrypter requires a pinned minisign public key to verify update payloads.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import ctypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests  # type: ignore[import-untyped]
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
    external_apply_started: bool = False


@dataclass(frozen=True)
class UpdateCheckResult:
    update_available: bool
    latest_version: Optional[str]
    zip_url: Optional[str]
    checksum: Optional[str]
    minisig_url: Optional[str]


@dataclass(frozen=True)
class ReleaseAssetInfo:
    zip_url: str
    checksum: Optional[str]
    minisig_url: Optional[str]


class AutoUpdater:
    GITHUB_API_URL = "https://api.github.com/repos/Pang-HQ/PangCrypter/releases/latest"
    GITHUB_RELEASES_URL = "https://api.github.com/repos/Pang-HQ/PangCrypter/releases"
    REQUIRE_CHECKSUM = True
    REQUIRE_MINISIGN = True
    MINISIGN_BINARY = "minisign"
    # Keep a pinned minisign key in-app (trust anchor).
    TRUSTED_MINISIGN_PUBKEY = "RWRT41WQfq43N+sP5WjML1rUvI6EePQvMj9IFS7UulgkX85PCcfi5oI0"
    BACKUP_DIR_NAME = ".pangcrypter_backups"
    STAGING_MANIFEST_NAME = ".pang_update_manifest.json"
    NETWORK_RETRY_ATTEMPTS = 3
    NETWORK_RETRY_BASE_DELAY_SEC = 0.5
    NETWORK_RETRY_MAX_DELAY_SEC = 2.0
    MINISIGN_VERIFY_TIMEOUT_SEC = 20

    if os.name == "nt":
        APPLY_HELPER_NAME = "PangApplyUpdate.exe"
    else:
        APPLY_HELPER_NAME = "PangApplyUpdate"

    def __init__(self):
        self.current_version = self._get_current_version()
        self.last_update_report = UpdateReport()
        self._pending_exe_replacement: Optional[tuple[str, str]] = None

    def _install_dir(self) -> str:
        if getattr(sys, "frozen", False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

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
        allow_override = os.getenv("PANGCRYPTER_ALLOW_MINISIGN_PUBKEY_OVERRIDE") == "1"
        dev_ack = os.getenv("PANGCRYPTER_UNSAFE_DEV_MODE") == "1"

        if allow_override and dev_ack:
            env_key = os.getenv("PANGCRYPTER_MINISIGN_PUBKEY", "").strip()
            if env_key:
                logger.warning("Using OVERRIDDEN minisign public key (unsafe dev mode).")
                return env_key

            pubkey_file = self._project_root() / "minisign.pub"
            if pubkey_file.exists():
                logger.warning("Using minisign.pub override file (unsafe dev mode).")
                return pubkey_file.read_text(encoding="utf-8").strip()

        if allow_override and not dev_ack:
            logger.warning(
                "Ignoring minisign public key override because PANGCRYPTER_UNSAFE_DEV_MODE is not enabled."
            )

        return self.TRUSTED_MINISIGN_PUBKEY

    def get_last_update_report(self) -> UpdateReport:
        return self.last_update_report

    def _request_with_retry(self, url: str, *, headers: dict[str, str], timeout: int, stream: bool = False):
        last_error: Optional[Exception] = None
        attempts = max(1, int(self.NETWORK_RETRY_ATTEMPTS))
        for attempt in range(1, attempts + 1):
            try:
                response = requests.get(url, headers=headers, timeout=timeout, stream=stream)
                status = int(response.status_code)
                if status == 429 or status >= 500:
                    response.raise_for_status()
                if 400 <= status < 500:
                    raise UpdaterError(f"HTTP {status} for {url}")
                return response
            except requests.RequestException as e:
                last_error = e
                if attempt >= attempts:
                    break
                sleep_seconds = min(
                    self.NETWORK_RETRY_MAX_DELAY_SEC,
                    self.NETWORK_RETRY_BASE_DELAY_SEC * (2 ** (attempt - 1)),
                )
                sleep_seconds += min(0.25, sleep_seconds * 0.2)
                logger.warning(
                    "Updater request failed (attempt %s/%s): %s. Retrying in %.2fs",
                    attempt,
                    attempts,
                    e,
                    sleep_seconds,
                )
                time.sleep(sleep_seconds)
            except UpdaterError:
                raise
        raise UpdaterError(f"Network error: {last_error}")

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
                    if len(parts) >= 3:
                        return ".".join(map(str, parts[:3]))
                    return ".".join(map(str, parts))
        except (OSError, ValueError, IndexError) as e:
            logger.warning(f"Could not read version.txt: {e}")
        return "0.0.0"

    # --------------------------
    # Update check
    # --------------------------
    def check_for_updates_result(self) -> UpdateCheckResult:
        try:
            headers = {
                "User-Agent": "PangCrypter-Updater/ZIP",
                "Accept": "application/vnd.github.v3+json",
            }
            r = self._request_with_retry(self.GITHUB_API_URL, headers=headers, timeout=15)
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
            return UpdateCheckResult(
                update_available=update_available,
                latest_version=latest_version,
                zip_url=zip_url,
                checksum=checksum,
                minisig_url=minisig_url,
            )
        except (ValueError, TypeError, KeyError, UpdaterError) as e:
            raise UpdaterError(f"Update check failed: {e}")

    def check_for_updates(self) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[str]]:
        """Backward-compatible tuple API for older call sites."""
        result = self.check_for_updates_result()
        return (
            result.update_available,
            result.latest_version,
            result.zip_url,
            result.checksum,
            result.minisig_url,
        )

    def get_available_versions(self) -> List[str]:
        releases = self._get_releases()
        versions = []
        for release in releases:
            tag = release.get("tag_name", "").lstrip("v")
            if tag and self._has_zip_asset(release):
                versions.append(tag)
        return versions

    def get_release_assets_for_version(self, target_version: str) -> ReleaseAssetInfo:
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
                return ReleaseAssetInfo(zip_url=zip_url, checksum=checksum, minisig_url=minisig_url)
        raise UpdaterError(f"No release found for version {target_version}")

    def get_zip_url_for_version(self, target_version: str) -> Tuple[str, Optional[str], Optional[str]]:
        """Backward-compatible tuple API for older call sites."""
        result = self.get_release_assets_for_version(target_version)
        return result.zip_url, result.checksum, result.minisig_url

    # --------------------------
    # Download
    # --------------------------
    def _create_session_temp_file(self, temp_root: Optional[str], suffix: str) -> str:
        dir_arg = temp_root if temp_root else None
        fd, temp_path = tempfile.mkstemp(prefix="pang_update_", suffix=suffix, dir=dir_arg)
        os.close(fd)
        return temp_path

    def download_zip(self, url: str, temp_root: Optional[str] = None, progress_callback=None) -> str:
        temp_zip = self._create_session_temp_file(temp_root=temp_root, suffix=".zip")
        headers = {"User-Agent": "PangCrypter-Updater/ZIP"}
        with self._request_with_retry(url, headers=headers, stream=True, timeout=60) as r:
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

    def download_file(self, url: str, suffix: str, temp_root: Optional[str] = None) -> str:
        temp_path = self._create_session_temp_file(temp_root=temp_root, suffix=suffix)
        headers = {"User-Agent": "PangCrypter-Updater/ZIP"}
        with self._request_with_retry(url, headers=headers, stream=True, timeout=60) as r:
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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.MINISIGN_VERIFY_TIMEOUT_SEC,
            )
        except FileNotFoundError:
            logger.error("minisign binary not found on system PATH")
            return False
        except subprocess.TimeoutExpired:
            logger.error("minisign verification timed out")
            return False
        if result.returncode != 0:
            logger.error("minisign verification failed: %s", (result.stderr or result.stdout).strip())
            return False
        return True

    # --------------------------
    # Install
    # --------------------------
    def _extract_payload_root(self, zip_path: str, extract_root: str) -> str:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            self._safe_extract(zip_ref, extract_root)

        payload_root = extract_root
        root_items = os.listdir(extract_root)
        if len(root_items) == 1 and os.path.isdir(os.path.join(extract_root, root_items[0])):
            payload_root = os.path.join(extract_root, root_items[0])
        return payload_root

    def _compute_sha256(self, file_path: str) -> str:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest().lower()

    def _write_staging_manifest(self, staging_dir: str) -> str:
        files_manifest: dict[str, str] = {}
        base = Path(staging_dir)
        for root, _, files in os.walk(staging_dir):
            for file_name in files:
                full_path = Path(root) / file_name
                rel_path = full_path.relative_to(base).as_posix()
                if rel_path == self.STAGING_MANIFEST_NAME:
                    continue
                files_manifest[rel_path] = self._compute_sha256(str(full_path))

        if not files_manifest:
            raise UpdaterError("Update staging payload is empty.")

        manifest_path = Path(staging_dir) / self.STAGING_MANIFEST_NAME
        manifest_payload = {"files": files_manifest}
        manifest_path.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(manifest_path)

    def prepare_staging_from_zip(self, zip_path: str, temp_root: str) -> str:
        extract_root = tempfile.mkdtemp(prefix="pang_extract_", dir=temp_root)
        staging_root = tempfile.mkdtemp(prefix="pang_stage_", dir=temp_root)
        try:
            payload_root = self._extract_payload_root(zip_path, extract_root)
            for root, dirs, files in os.walk(payload_root):
                rel = os.path.relpath(root, payload_root)
                dst_root = os.path.join(staging_root, rel)
                os.makedirs(dst_root, exist_ok=True)
                for d in dirs:
                    os.makedirs(os.path.join(dst_root, d), exist_ok=True)
                for file_name in files:
                    shutil.copy2(os.path.join(root, file_name), os.path.join(dst_root, file_name))
            self._write_staging_manifest(staging_root)
            return staging_root
        finally:
            try:
                shutil.rmtree(extract_root)
            except OSError as cleanup_error:
                logger.debug("Updater cleanup could not remove extract root %s: %s", extract_root, cleanup_error)

    def _resolve_apply_helper_source(
        self,
        install_dir: str,
        staging_dir: Optional[str] = None,
        require_staged: bool = False,
    ) -> str:
        # Prefer helper from verified staging payload.
        if staging_dir:
            staged_helper = os.path.join(staging_dir, self.APPLY_HELPER_NAME)
            if os.path.isfile(staged_helper):
                return staged_helper
            if require_staged:
                raise UpdaterError(
                    f"Staged update helper missing from verified payload: {self.APPLY_HELPER_NAME}."
                )

        helper_path = os.path.join(install_dir, self.APPLY_HELPER_NAME)
        if os.path.isfile(helper_path):
            return helper_path

        raise UpdaterError(
            f"Update helper not found in staging/install bundle: {self.APPLY_HELPER_NAME}."
        )

    def launch_external_apply(self, staging_dir: str, session_root: Optional[str] = None) -> bool:
        if os.name != "nt" or not getattr(sys, "frozen", False):
            return False

        install_dir = self._install_dir()
        helper_source = self._resolve_apply_helper_source(
            install_dir,
            staging_dir=staging_dir,
            require_staged=True,
        )
        helper_copy = self._create_session_temp_file(temp_root=tempfile.gettempdir(), suffix=".exe")
        shutil.copy2(helper_source, helper_copy)

        relaunch_exe = sys.executable
        relaunch_args = sys.argv[1:]
        cmd = [
            helper_copy,
            "--install-dir",
            install_dir,
            "--staging-dir",
            staging_dir,
            "--parent-pid",
            str(os.getpid()),
            "--relaunch-exe",
            relaunch_exe,
            "--manifest-name",
            self.STAGING_MANIFEST_NAME,
        ]
        for arg in relaunch_args:
            cmd.extend(["--relaunch-arg", arg])
        if session_root:
            cmd.extend(["--session-root", session_root])

        try:
            # Always request elevation for the external applier on Windows.
            # If this fails, do not continue because the app is about to quit.
            params = subprocess.list2cmdline(cmd[1:])
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                cmd[0],
                params,
                os.path.dirname(cmd[0]),
                0,
            )
            if ret <= 32:
                raise OSError(f"ShellExecuteW failed with code {ret}")
        except OSError as e:
            raise UpdaterError(f"Failed to launch external update helper: {e}") from e
        return True

    def install_zip_update(self, zip_path: str, temp_root: Optional[str] = None) -> bool:
        install_dir = self._install_dir()
        active_temp_root = temp_root or tempfile.mkdtemp(prefix="pang_update_session_")
        temp_root_owned = temp_root is None

        extract_root = tempfile.mkdtemp(prefix="pang_extract_", dir=active_temp_root)

        backup_root = os.path.join(install_dir, self.BACKUP_DIR_NAME)
        os.makedirs(backup_root, exist_ok=True)
        backup_dir = os.path.join(backup_root, f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(backup_dir, exist_ok=True)

        payload_root = self._extract_payload_root(zip_path, extract_root)

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
                    try:
                        os.replace(temp_dst, dst)
                    except PermissionError as replace_error:
                        running_exe = getattr(sys, "frozen", False) and os.name == "nt" and os.path.normcase(dst) == os.path.normcase(sys.executable)
                        if running_exe:
                            pending_path = f"{dst}.new"
                            os.replace(temp_dst, pending_path)
                            self._pending_exe_replacement = (pending_path, dst)
                            logger.info("Deferred replacement of running executable to restart phase: %s", dst)
                            continue
                        raise replace_error
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
            if temp_root_owned:
                try:
                    shutil.rmtree(active_temp_root)
                except OSError as cleanup_error:
                    logger.debug("Updater cleanup could not remove session temp root %s: %s", active_temp_root, cleanup_error)

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
        check = self.check_for_updates_result()
        if not check.update_available:
            return False
        if progress_callback:
            progress_callback(30, f"Downloading {check.latest_version}...")
        temp_root = tempfile.mkdtemp(prefix="pang_update_session_")
        zip_path: Optional[str] = None
        sig_path: Optional[str] = None
        staging_path: Optional[str] = None
        try:
            if not check.zip_url:
                raise UpdaterError("Update payload URL missing from release metadata.")
            zip_path = self.download_zip(check.zip_url, temp_root=temp_root, progress_callback=progress_callback)
            if check.minisig_url:
                sig_path = self.download_file(check.minisig_url, ".minisig", temp_root=temp_root)
            if progress_callback:
                progress_callback(60, "Verifying SHA-256 checksum...")
            if check.checksum and not self.verify_sha256(zip_path, check.checksum):
                raise UpdaterError("SHA-256 checksum verification failed.")
            self.last_update_report.checksum_verified = bool(check.checksum)
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

            if os.name == "nt" and getattr(sys, "frozen", False):
                if progress_callback:
                    progress_callback(88, "Preparing update staging...")
                staging_path = self.prepare_staging_from_zip(zip_path, temp_root=temp_root)
                if progress_callback:
                    progress_callback(95, "Launching installer helper...")
                self.launch_external_apply(staging_path, session_root=temp_root)
                self.last_update_report.external_apply_started = True
                success = True
            else:
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
            # On Windows frozen flow, staging is consumed by external helper after
            # parent process exits, so this temp root may remain temporarily.
            if not (os.name == "nt" and getattr(sys, "frozen", False) and staging_path):
                try:
                    shutil.rmtree(temp_root)
                except OSError as cleanup_error:
                    logger.debug("Updater cleanup could not remove session temp root %s: %s", temp_root, cleanup_error)

    def perform_update_for_version(self, target_version: str, progress_callback=None) -> bool:
        self.last_update_report = UpdateReport()
        if progress_callback:
            progress_callback(10, f"Preparing rollback to {target_version}...")

        release_assets = self.get_release_assets_for_version(target_version)
        temp_root = tempfile.mkdtemp(prefix="pang_update_session_")
        zip_path: Optional[str] = None
        sig_path: Optional[str] = None
        staging_path: Optional[str] = None
        try:
            if progress_callback:
                progress_callback(30, f"Downloading {target_version}...")
            zip_path = self.download_zip(release_assets.zip_url, temp_root=temp_root, progress_callback=progress_callback)
            if release_assets.minisig_url:
                sig_path = self.download_file(release_assets.minisig_url, ".minisig", temp_root=temp_root)

            if progress_callback:
                progress_callback(60, "Verifying SHA-256 checksum...")
            if release_assets.checksum and not self.verify_sha256(zip_path, release_assets.checksum):
                raise UpdaterError("SHA-256 checksum verification failed.")
            self.last_update_report.checksum_verified = bool(release_assets.checksum)

            if progress_callback:
                progress_callback(70, "Verifying minisign signature...")
            if self.REQUIRE_MINISIGN:
                if not sig_path:
                    raise UpdaterError("Missing minisign signature for rollback package.")
                if not self.verify_minisign(zip_path, sig_path):
                    raise UpdaterError("minisign verification failed.")
                self.last_update_report.signature_verified = True
                self.last_update_report.publisher_verified = True

            if progress_callback:
                progress_callback(80, "Verifying ZIP...")
            if not self.verify_zip(zip_path):
                raise UpdaterError("ZIP verification failed.")

            if os.name == "nt" and getattr(sys, "frozen", False):
                if progress_callback:
                    progress_callback(88, "Preparing rollback staging...")
                staging_path = self.prepare_staging_from_zip(zip_path, temp_root=temp_root)
                if progress_callback:
                    progress_callback(95, "Launching installer helper...")
                self.launch_external_apply(staging_path, session_root=temp_root)
                self.last_update_report.external_apply_started = True
                success = True
            else:
                if progress_callback:
                    progress_callback(90, "Installing rollback...")
                success = self.install_zip_update(zip_path, temp_root=temp_root)

            if progress_callback:
                progress_callback(100, "Rollback complete!")
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
            if not (os.name == "nt" and getattr(sys, "frozen", False) and staging_path):
                try:
                    shutil.rmtree(temp_root)
                except OSError as cleanup_error:
                    logger.debug("Updater cleanup could not remove session temp root %s: %s", temp_root, cleanup_error)

    # --------------------------
    # Restart
    # --------------------------
    def restart_application(self):
        exe = sys.executable
        args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv

        pending = self._pending_exe_replacement
        if pending and os.name == "nt":
            pending_new, target_exe = pending
            if os.path.exists(pending_new):
                quoted_args = subprocess.list2cmdline(args) if args else ""
                launch_cmd = f'start "" "{target_exe}" {quoted_args}'.strip()
                helper_cmd = (
                    f'timeout /t 1 /nobreak >nul & '
                    f'move /y "{pending_new}" "{target_exe}" >nul & '
                    f'{launch_cmd}'
                )
                subprocess.Popen(["cmd", "/c", helper_cmd], close_fds=True)
                return True

        subprocess.Popen([exe] + args, close_fds=True)
        return True

    def _get_releases(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "PangCrypter-Updater/ZIP",
            "Accept": "application/vnd.github.v3+json",
        }
        r = self._request_with_retry(self.GITHUB_RELEASES_URL, headers=headers, timeout=15)
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
        r = self._request_with_retry(url, headers=headers, timeout=30)
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
