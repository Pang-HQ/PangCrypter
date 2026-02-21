"""External update applier for Windows onedir installs.

This helper is launched by PangCrypter after download/signature verification.
It waits for the parent process to exit, validates a staging manifest,
atomically swaps directories with retries/backoff, then relaunches the app.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Callable


LOG_PATH = Path(tempfile.gettempdir()) / "pang_apply_update.log"


def _log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}\n"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


def _is_admin_windows() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _can_write_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=str(path), prefix="pang_write_probe_", delete=True):
            pass
        return True
    except OSError:
        return False


def _can_swap_install_dir(install_dir: Path) -> bool:
    parent = install_dir.parent
    return _can_write_dir(parent)


def _relaunch_self_as_admin() -> bool:
    if os.name != "nt":
        return False

    if "--elevated" in sys.argv[1:]:
        return False

    try:
        if getattr(sys, "frozen", False):
            executable = sys.executable
            args = sys.argv[1:] + ["--elevated"]
        else:
            executable = sys.executable
            script_path = str(Path(__file__).resolve())
            args = [script_path] + sys.argv[1:] + ["--elevated"]

        params = subprocess.list2cmdline(args)
        working_dir = str(Path(executable).resolve().parent)
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, working_dir, 1)
        return ret > 32
    except (OSError, AttributeError):
        return False


def _wait_for_pid_exit(pid: int, timeout_seconds: int = 120) -> None:
    if pid <= 0:
        return

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if os.name == "nt":
            SYNCHRONIZE = 0x00100000
            WAIT_TIMEOUT = 0x00000102
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if not handle:
                return
            try:
                result = ctypes.windll.kernel32.WaitForSingleObject(handle, 500)
                if result != WAIT_TIMEOUT:
                    return
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        else:
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(0.25)


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def _validate_manifest(staging_dir: Path, manifest_name: str) -> None:
    manifest_path = staging_dir / manifest_name
    if not manifest_path.exists():
        raise RuntimeError(f"Manifest not found: {manifest_path}")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = data.get("files", {})
    if not isinstance(files, dict) or not files:
        raise RuntimeError("Manifest is empty or invalid")

    for rel_path, expected_hash in files.items():
        file_path = staging_dir / rel_path
        if not file_path.exists() or not file_path.is_file():
            raise RuntimeError(f"Manifest file missing: {rel_path}")
        actual_hash = _sha256_file(file_path)
        if actual_hash != str(expected_hash).lower():
            raise RuntimeError(f"Manifest hash mismatch: {rel_path}")


def _retry(action: Callable[[], None], retries: int, base_sleep_ms: int) -> None:
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            action()
            return
        except OSError as e:
            last_error = e
            sleep_ms = min(base_sleep_ms + attempt * 50, 750)
            time.sleep(sleep_ms / 1000.0)
    if last_error:
        raise last_error


def _copytree_staging(staging_dir: Path, incoming_dir: Path, retries: int, base_sleep_ms: int) -> None:
    def _copy() -> None:
        if incoming_dir.exists():
            shutil.rmtree(incoming_dir, ignore_errors=True)
        shutil.copytree(staging_dir, incoming_dir)

    _retry(_copy, retries=retries, base_sleep_ms=base_sleep_ms)


def _materialize_incoming_from_staging(
    staging_dir: Path,
    incoming_dir: Path,
    retries: int,
    base_sleep_ms: int,
) -> None:
    # Prefer atomic move if possible (same volume). Fallback to copytree.
    def _move() -> None:
        if incoming_dir.exists():
            shutil.rmtree(incoming_dir, ignore_errors=True)
        os.replace(str(staging_dir), str(incoming_dir))

    try:
        _retry(_move, retries=retries, base_sleep_ms=base_sleep_ms)
        _log(f"Moved staging to incoming: {staging_dir} -> {incoming_dir}")
        return
    except OSError as move_error:
        _log(f"Move staging failed, falling back to copytree: {move_error}")

    _copytree_staging(staging_dir, incoming_dir, retries=retries, base_sleep_ms=base_sleep_ms)
    _log(f"Copied staging to incoming: {staging_dir} -> {incoming_dir}")


def _swap_install_dirs(
    install_dir: Path,
    incoming_dir: Path,
    backup_dir: Path,
    retries: int,
    base_sleep_ms: int,
) -> None:
    if not install_dir.exists():
        raise RuntimeError(f"Install directory does not exist: {install_dir}")

    def _rename_install_to_backup() -> None:
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
        os.replace(str(install_dir), str(backup_dir))

    _retry(_rename_install_to_backup, retries=retries, base_sleep_ms=base_sleep_ms)

    def _rename_incoming_to_install() -> None:
        os.replace(str(incoming_dir), str(install_dir))

    try:
        _retry(_rename_incoming_to_install, retries=retries, base_sleep_ms=base_sleep_ms)
    except OSError as swap_error:
        if not install_dir.exists() and backup_dir.exists():
            try:
                os.replace(str(backup_dir), str(install_dir))
            except OSError:
                pass
        raise RuntimeError(f"Failed to activate incoming installation: {swap_error}") from swap_error


def _cleanup_old_backups(install_dir: Path, keep: int) -> None:
    if keep < 0:
        return
    base_name = f"{install_dir.name}.old."
    parent = install_dir.parent
    backups = sorted(
        [p for p in parent.iterdir() if p.is_dir() and p.name.startswith(base_name)],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for stale in backups[keep:]:
        try:
            shutil.rmtree(stale, ignore_errors=True)
        except OSError:
            pass


def _launch_updated_app(executable: Path, relaunch_args: list[str]) -> None:
    subprocess.Popen([str(executable)] + relaunch_args, close_fds=True)


def _cleanup_path(path_value: str | None) -> None:
    if not path_value:
        return
    p = Path(path_value)
    try:
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="PangCrypter external update applier")
    parser.add_argument("--install-dir", required=True)
    parser.add_argument("--staging-dir", required=True)
    parser.add_argument("--parent-pid", type=int, default=0)
    parser.add_argument("--relaunch-exe", required=True)
    parser.add_argument("--relaunch-arg", action="append", default=[])
    parser.add_argument("--manifest-name", default=".pang_update_manifest.json")
    parser.add_argument("--max-retries", type=int, default=20)
    parser.add_argument("--retry-base-ms", type=int, default=150)
    parser.add_argument("--keep-backups", type=int, default=3)
    parser.add_argument("--session-root", default="")
    parser.add_argument("--elevated", action="store_true")
    args = parser.parse_args()

    install_dir = Path(args.install_dir).resolve()
    staging_dir = Path(args.staging_dir).resolve()
    relaunch_exe = Path(args.relaunch_exe).resolve()

    try:
        _log(f"Helper started. install_dir={install_dir} staging_dir={staging_dir}")

        if os.name == "nt" and not args.elevated and (not _is_admin_windows()) and (not _can_swap_install_dir(install_dir)):
            _log("Insufficient rights for swap; attempting elevation.")
            if _relaunch_self_as_admin():
                _log("Elevation launch succeeded; exiting unelevated helper.")
                return 0
            raise RuntimeError("Could not elevate update helper")

        _wait_for_pid_exit(args.parent_pid)
        _validate_manifest(staging_dir, args.manifest_name)

        incoming_dir = install_dir.parent / f".pang_incoming_{int(time.time())}_{random.randint(1000, 9999)}"
        backup_dir = install_dir.parent / f"{install_dir.name}.old.{int(time.time())}"

        _materialize_incoming_from_staging(
            staging_dir,
            incoming_dir,
            retries=args.max_retries,
            base_sleep_ms=args.retry_base_ms,
        )
        _swap_install_dirs(
            install_dir=install_dir,
            incoming_dir=incoming_dir,
            backup_dir=backup_dir,
            retries=args.max_retries,
            base_sleep_ms=args.retry_base_ms,
        )

        _cleanup_path(args.session_root)
        _cleanup_path(str(staging_dir))

        _cleanup_old_backups(install_dir, keep=args.keep_backups)
        _launch_updated_app(relaunch_exe, args.relaunch_arg)
        _log(f"Update apply complete. Relaunched: {relaunch_exe}")
        return 0
    except Exception as exc:
        _log(f"FATAL: helper failed: {exc}")
        _log(traceback.format_exc())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
