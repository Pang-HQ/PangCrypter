"""
Headless mem-guard detection-latency benchmark.

Measures detection latency for mem-guard scan intervals by repeatedly opening a
PROCESS_VM_READ handle from a separate probe process and timing:

    latency_ms = t_detect - t_open

Where:
  - t_open   = when probe OpenProcess succeeds
  - t_detect = when MemGuard emits a detection for probe PID

This script intentionally does not launch PangCrypter's GUI.
"""

from __future__ import annotations

import argparse
import ctypes
import math
import os
import random
import sys
import threading
import time
from pathlib import Path
from dataclasses import dataclass
from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection
from typing import Any
from queue import Empty, Queue

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pangcrypter.utils.mem_guard import MemGuardChecker, MemGuardMode
from PyQt6.QtCore import Qt


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


@dataclass
class SampleDetection:
    pid: int
    detected_at: float


def _percentile_nearest_rank(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return float("nan")
    rank = int(math.ceil((max(0.0, min(100.0, p)) / 100.0) * len(sorted_values)))
    idx = max(0, min(len(sorted_values) - 1, rank - 1))
    return sorted_values[idx]


def _probe_worker(conn: Connection, target_pid: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    handle: ctypes.c_void_p | None = None
    desired_access = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION

    try:
        while True:
            cmd = conn.recv()
            if not cmd:
                continue
            action = cmd[0]

            if action == "exit":
                break

            if action == "open":
                sample_id = int(cmd[1])
                delay_ms = int(cmd[2])
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                if handle:
                    close_handle(handle)
                    handle = None

                handle = open_process(desired_access, 0, int(target_pid))
                if not handle:
                    err = ctypes.get_last_error()
                    conn.send(("open_failed", sample_id, int(err)))
                    continue

                t_open = time.perf_counter()
                conn.send(("opened", sample_id, os.getpid(), float(t_open)))
                continue

            if action == "close":
                sample_id = int(cmd[1])
                if handle:
                    close_handle(handle)
                    handle = None
                conn.send(("closed", sample_id))
                continue
    finally:
        if handle:
            close_handle(handle)


def _probe_oneshot_worker(conn: Connection, target_pid: int) -> None:
    """Open one VM_READ handle, report t_open, then wait for close/exit."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    desired_access = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
    handle: ctypes.c_void_p | None = None

    try:
        handle = open_process(desired_access, 0, int(target_pid))
        if not handle:
            err = ctypes.get_last_error()
            conn.send(("open_failed", int(err)))
            return

        t_open = time.perf_counter()
        conn.send(("opened", os.getpid(), float(t_open)))

        deadline = time.perf_counter() + 10.0
        while time.perf_counter() < deadline:
            if conn.poll(0.05):
                cmd = conn.recv()
                if cmd and cmd[0] in {"close", "exit"}:
                    break
    finally:
        if handle:
            close_handle(handle)


def _start_checker(
    interval_ms: int,
    detection_queue: Queue[SampleDetection],
    *,
    enhanced_detection_enabled: bool,
) -> tuple[MemGuardChecker, threading.Thread]:
    checker = MemGuardChecker(
        mode=MemGuardMode.NORMAL,
        whitelist=[],
        check_interval_ms=interval_ms,
        alert_cooldown_sec=0,
        enhanced_detection_enabled=enhanced_detection_enabled,
    )
    # Benchmark must support legacy 20-40ms intervals even if app runtime defaults
    # clamp scan intervals higher for normal GUI operation.
    checker.check_interval_ms = int(interval_ms)

    def _on_detection(finding):
        detection_queue.put(SampleDetection(pid=int(finding.pid), detected_at=time.perf_counter()))

    checker.memory_probe_detected.connect(_on_detection)
    worker = threading.Thread(target=checker.run, name=f"memguard-{interval_ms}ms", daemon=True)
    worker.start()
    return checker, worker


def _run_interval(
    interval_ms: int,
    detections: int,
    per_sample_timeout_sec: float,
    *,
    enhanced_detection_enabled: bool,
    workload: str,
) -> list[float]:
    detection_queue: Queue[SampleDetection] = Queue()
    checker, checker_thread = _start_checker(
        interval_ms,
        detection_queue,
        enhanced_detection_enabled=enhanced_detection_enabled,
    )

    parent_conn: Any = None
    probe: Process | None = None
    if workload == "reopen":
        parent_conn, child_conn = Pipe()
        probe = Process(target=_probe_worker, args=(child_conn, os.getpid()), daemon=True)
        probe.start()

    latencies_ms: list[float] = []
    probe_pid: int | None = None

    try:
        for sample_id in range(1, detections + 1):
            delay_ms = random.randint(1, 20)
            if workload == "reopen":
                assert parent_conn is not None
                parent_conn.send(("open", sample_id, delay_ms))
            else:
                parent_conn, child_conn = Pipe()
                probe = Process(target=_probe_oneshot_worker, args=(child_conn, os.getpid()), daemon=True)
                probe.start()

            opened_deadline = time.perf_counter() + per_sample_timeout_sec
            opened = False
            t_open = 0.0
            while time.perf_counter() < opened_deadline:
                assert parent_conn is not None
                if not parent_conn.poll(0.05):
                    continue
                msg = parent_conn.recv()
                if workload == "reopen":
                    if msg[0] == "open_failed" and int(msg[1]) == sample_id:
                        raise RuntimeError(f"OpenProcess failed for sample {sample_id} (error={msg[2]})")
                    if msg[0] == "opened" and int(msg[1]) == sample_id:
                        probe_pid = int(msg[2])
                        t_open = float(msg[3])
                        opened = True
                        break
                else:
                    if msg[0] == "open_failed":
                        raise RuntimeError(f"OpenProcess failed for sample {sample_id} (error={msg[1]})")
                    if msg[0] == "opened":
                        probe_pid = int(msg[1])
                        t_open = float(msg[2])
                        opened = True
                        break
            if not opened:
                raise TimeoutError(f"Timed out waiting for probe open for sample {sample_id}")

            detect_deadline = time.perf_counter() + per_sample_timeout_sec
            detected = False
            while time.perf_counter() < detect_deadline:
                remaining = max(0.0, detect_deadline - time.perf_counter())
                try:
                    event = detection_queue.get(timeout=min(0.05, remaining))
                except Empty:
                    continue

                if probe_pid is not None and event.pid == probe_pid and event.detected_at >= t_open:
                    latencies_ms.append((event.detected_at - t_open) * 1000.0)
                    detected = True
                    break

            assert parent_conn is not None
            if workload == "reopen":
                parent_conn.send(("close", sample_id))
                close_deadline = time.perf_counter() + per_sample_timeout_sec
                while time.perf_counter() < close_deadline:
                    if not parent_conn.poll(0.05):
                        continue
                    msg = parent_conn.recv()
                    if msg[0] == "closed" and int(msg[1]) == sample_id:
                        break
            else:
                parent_conn.send(("close",))
                if probe is not None:
                    probe.join(timeout=2.0)
                    if probe.is_alive():
                        probe.terminate()
                        probe.join(timeout=1.0)
                probe = None
                parent_conn = None

            if not detected:
                raise TimeoutError(f"Timed out waiting for detection for sample {sample_id}")

    finally:
        if workload == "reopen" and parent_conn is not None:
            try:
                parent_conn.send(("exit",))
            except (OSError, EOFError, BrokenPipeError):
                pass

        checker.stop()
        checker_thread.join(timeout=10.0)

        if probe is not None:
            probe.join(timeout=5.0)
            if probe.is_alive():
                probe.terminate()
                probe.join(timeout=2.0)

    return latencies_ms


def _parse_intervals(raw: str) -> list[int]:
    items = [part.strip() for part in str(raw).split(",") if part.strip()]
    values = [int(item) for item in items]
    if not values:
        raise ValueError("No intervals supplied")
    for value in values:
        if value < 50 or value > 250:
            raise ValueError(f"Interval out of supported range 50-250 ms: {value}")
    return values


def _parse_workload(raw: str) -> str:
    mode = str(raw or "reopen").strip().lower()
    if mode not in {"reopen", "procstart"}:
        raise ValueError("workload must be one of: reopen, procstart")
    return mode


def main() -> int:
    if sys.platform != "win32":
        print("This benchmark is Windows-only.")
        return 2

    parser = argparse.ArgumentParser(description="Benchmark MemGuard detection latency by scan interval")
    parser.add_argument(
        "--intervals",
        default="50,100,150,200,250",
        help="Comma-separated scan intervals in ms",
    )
    parser.add_argument("--detections", type=int, default=5000, help="Detections per interval")
    parser.add_argument("--timeout-sec", type=float, default=5.0, help="Per-sample timeout seconds")
    parser.add_argument(
        "--workload",
        default="reopen",
        help="Benchmark workload: reopen (reuse one probe process) or procstart (new process per sample)",
    )
    parser.add_argument(
        "--enhanced-detection",
        dest="enhanced_detection",
        action="store_true",
        help="Enable ETW process watcher hints during benchmark (default: on)",
    )
    parser.add_argument(
        "--no-enhanced-detection",
        dest="enhanced_detection",
        action="store_false",
        help="Disable ETW process watcher hints during benchmark",
    )
    parser.set_defaults(enhanced_detection=True)
    args = parser.parse_args()

    intervals = _parse_intervals(args.intervals)
    workload = _parse_workload(args.workload)
    detections = max(1, int(args.detections))
    timeout_sec = max(0.5, float(args.timeout_sec))

    print("MemGuard headless latency benchmark")
    print(f"intervals={intervals}")
    print(f"detections_per_interval={detections}")
    print("mode=normal, probe=PROCESS_VM_READ, latency=t_detect-t_open")
    print(f"enhanced_detection={bool(args.enhanced_detection)}")
    print(f"workload={workload}")
    print("random_reopen_delay_ms=1..20")
    print()

    header = f"{'interval_ms':>11} {'count':>7} {'avg_ms':>10} {'p95_ms':>10} {'p99_ms':>10} {'min_ms':>10} {'max_ms':>10}"
    print(header)
    print("-" * len(header))

    for interval_ms in intervals:
        latencies = _run_interval(
            interval_ms=interval_ms,
            detections=detections,
            per_sample_timeout_sec=timeout_sec,
            enhanced_detection_enabled=bool(args.enhanced_detection),
            workload=workload,
        )
        ordered = sorted(latencies)
        avg_ms = sum(ordered) / len(ordered)
        p95_ms = _percentile_nearest_rank(ordered, 95)
        p99_ms = _percentile_nearest_rank(ordered, 99)
        min_ms = ordered[0]
        max_ms = ordered[-1]

        print(
            f"{interval_ms:11d} {len(ordered):7d} {avg_ms:10.3f} {p95_ms:10.3f} {p99_ms:10.3f} {min_ms:10.3f} {max_ms:10.3f}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
