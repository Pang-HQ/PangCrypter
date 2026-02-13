"""
Safety-focused mem-guard probe for PangCrypter.

This script is intended for local defensive testing only. It does NOT dump memory
contents. It only opens a PROCESS_VM_READ handle to a running PangCrypter process
and keeps it open briefly so MemGuard can detect the access rights.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
import time

import psutil


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _find_target_pid(explicit_pid: int | None, name_hint: str) -> int:
    if explicit_pid is not None:
        if not psutil.pid_exists(explicit_pid):
            raise RuntimeError(f"PID {explicit_pid} does not exist")
        return explicit_pid

    hint = name_hint.lower()
    matches: list[int] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            pname = (proc.info.get("name") or "").lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            if hint in pname or hint in cmdline:
                matches.append(int(proc.info["pid"]))
        except (psutil.Error, OSError, ValueError):
            continue

    if not matches:
        raise RuntimeError(
            f"No process matched hint '{name_hint}'. Start PangCrypter first or pass --pid."
        )

    # Prefer newest candidate (usually the one just launched).
    return matches[-1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Open a VM_READ handle to a running PangCrypter process for MemGuard testing."
    )
    parser.add_argument("--pid", type=int, default=None, help="Exact target PID")
    parser.add_argument(
        "--name",
        default="pangcrypter",
        help="Name/cmdline hint to find target process when --pid is not provided",
    )
    parser.add_argument(
        "--hold-seconds",
        type=float,
        default=8.0,
        help="How long to keep the VM_READ handle open",
    )
    args = parser.parse_args()

    try:
        target_pid = _find_target_pid(args.pid, args.name)
    except RuntimeError as exc:
        print(f"[probe] {exc}")
        return 2

    desired_access = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    handle = open_process(desired_access, 0, int(target_pid))
    if not handle:
        err = ctypes.get_last_error()
        print(f"[probe] OpenProcess failed for PID {target_pid} (error={err})")
        return 1

    print(
        f"[probe] Opened handle 0x{int(handle):x} to PID {target_pid} "
        f"with access=0x{desired_access:08x}"
    )
    print(f"[probe] Holding handle for {args.hold_seconds:.1f}s so MemGuard can detect it...")

    try:
        time.sleep(max(0.0, args.hold_seconds))
    finally:
        close_handle(handle)

    print("[probe] Handle closed.")
    return 0


if __name__ == "__main__":
    if sys.platform != "win32":
        print("This probe is Windows-only.")
        raise SystemExit(2)
    raise SystemExit(main())
