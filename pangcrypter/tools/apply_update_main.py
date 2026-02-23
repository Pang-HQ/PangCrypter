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

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


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


def _wait_for_pid_exit(pid: int, timeout_seconds: int = 1) -> None:
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


def _is_process_running_windows(image_name: str) -> bool:
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "").strip().lower()
        if not output or "no tasks are running" in output or "info:" in output:
            return False
        # If CSV row exists, process is still alive.
        return image_name.lower() in output
    except (OSError, subprocess.SubprocessError):
        return False


def _wait_for_image_exit_windows(image_name: str, timeout_seconds: int = 1) -> None:
    if os.name != "nt":
        return
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if not _is_process_running_windows(image_name):
            return
        time.sleep(0.25)
    raise RuntimeError(f"Timed out waiting for process to exit: {image_name}")


def _terminate_process_image_windows(image_name: str) -> None:
    if os.name != "nt":
        return
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/T", "/IM", image_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        out = (result.stdout or "") + (result.stderr or "")
        _log(f"taskkill {image_name}: rc={result.returncode} output={out.strip()}")
    except (OSError, subprocess.SubprocessError) as e:
        _log(f"taskkill failed for {image_name}: {e}")


def _wait_for_install_dir_unlock_windows(install_dir: Path, timeout_seconds: int = 1) -> bool:
    if os.name != "nt":
        return True

    deadline = time.time() + timeout_seconds
    last_error: OSError | None = None
    probe_target = install_dir.parent / f".pang_lock_probe_{int(time.time())}_{random.randint(1000,9999)}"

    while time.time() < deadline:
        try:
            if probe_target.exists():
                shutil.rmtree(probe_target, ignore_errors=True)
            os.replace(str(install_dir), str(probe_target))
            os.replace(str(probe_target), str(install_dir))
            return True
        except OSError as e:
            last_error = e
            time.sleep(0.25)

    _log(f"Install directory still locked after wait: {last_error}")
    return False


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
    attempts = 1
    for attempt in range(attempts):
        try:
            action()
            return
        except OSError as e:
            last_error = e
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

    try:
        _retry(_rename_install_to_backup, retries=retries, base_sleep_ms=base_sleep_ms)
    except OSError as initial_swap_error:
        # Best effort: wait for lock release, then try again.
        _log(f"Initial install->backup rename failed: {initial_swap_error}")
        _wait_for_install_dir_unlock_windows(install_dir, timeout_seconds=120)
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


def _apply_incoming_in_place(
    install_dir: Path,
    incoming_dir: Path,
    backup_dir: Path,
    retries: int,
    base_sleep_ms: int,
) -> None:
    """Apply incoming payload by file replacement instead of directory swap.

    This avoids whole-directory rename failures when external processes keep a
    handle open on the install directory path.
    """
    if not install_dir.exists():
        raise RuntimeError(f"Install directory does not exist: {install_dir}")
    if not incoming_dir.exists():
        raise RuntimeError(f"Incoming directory does not exist: {incoming_dir}")

    backup_dir.mkdir(parents=True, exist_ok=True)
    replaced_files: list[tuple[Path, Path]] = []

    def _replace_file(src: Path, dst: Path) -> None:
        tmp_dst = dst.with_name(dst.name + ".tmp")

        def _op() -> None:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, tmp_dst)
            os.replace(str(tmp_dst), str(dst))

        try:
            _retry(_op, retries=retries, base_sleep_ms=base_sleep_ms)
        finally:
            try:
                if tmp_dst.exists():
                    tmp_dst.unlink()
            except OSError:
                pass

    try:
        for root, _dirs, files in os.walk(incoming_dir):
            root_path = Path(root)
            rel_dir = root_path.relative_to(incoming_dir)
            dest_root = install_dir / rel_dir

            for file_name in files:
                src = root_path / file_name
                dst = dest_root / file_name

                if dst.exists():
                    backup_target = backup_dir / rel_dir / file_name
                    backup_target.parent.mkdir(parents=True, exist_ok=True)

                    def _backup_copy() -> None:
                        shutil.copy2(dst, backup_target)

                    _retry(_backup_copy, retries=retries, base_sleep_ms=base_sleep_ms)
                    replaced_files.append((backup_target, dst))

                _replace_file(src, dst)
    except OSError as apply_error:
        _log(f"In-place apply failed, attempting rollback: {apply_error}")
        for backup_src, dst in reversed(replaced_files):
            try:
                _replace_file(backup_src, dst)
            except OSError as rollback_error:
                _log(f"Rollback failed for {dst}: {rollback_error}")
        raise RuntimeError(f"Failed to apply incoming payload in-place: {apply_error}") from apply_error


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
    parser.add_argument("--max-retries", type=int, default=1)
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

        if os.name == "nt" and not args.elevated and (not _is_admin_windows()):
            _log("Helper is not elevated; attempting elevation.")
            if _relaunch_self_as_admin():
                _log("Elevation launch succeeded; exiting unelevated helper.")
                return 0
            raise RuntimeError("Could not elevate update helper")

        # Wait for original process to exit first.
        _wait_for_pid_exit(args.parent_pid, timeout_seconds=1)
        _log(f"Parent process exited or unavailable: pid={args.parent_pid}")

        # Extra safety: ensure PangCrypter binary is no longer running before swap.
        if os.name == "nt":
            image_name = relaunch_exe.name or "PangCrypter.exe"
            _log(f"Waiting for process image to stop: {image_name}")
            _wait_for_image_exit_windows(image_name, timeout_seconds=1)
            _log(f"Process image is no longer running: {image_name}")
            _terminate_process_image_windows(image_name)
            _wait_for_image_exit_windows(image_name, timeout_seconds=1)
            if _wait_for_install_dir_unlock_windows(install_dir, timeout_seconds=1):
                _log("Install directory lock probe passed.")
            else:
                _log("Install directory lock probe did not pass yet; continuing to swap with retries.")

        _validate_manifest(staging_dir, args.manifest_name)
        _log("Manifest validated.")

        incoming_dir = install_dir.parent / f".pang_incoming_{int(time.time())}_{random.randint(1000, 9999)}"
        backup_dir = install_dir.parent / f"{install_dir.name}.old.{int(time.time())}"

        _materialize_incoming_from_staging(
            staging_dir,
            incoming_dir,
            retries=args.max_retries,
            base_sleep_ms=args.retry_base_ms,
        )
        _apply_incoming_in_place(
            install_dir=install_dir,
            incoming_dir=incoming_dir,
            backup_dir=backup_dir,
            retries=args.max_retries,
            base_sleep_ms=args.retry_base_ms,
        )
        _log(f"Install payload applied in-place. backup={backup_dir} active={install_dir}")

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
