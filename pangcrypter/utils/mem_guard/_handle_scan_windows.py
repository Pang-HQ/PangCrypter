from __future__ import annotations

import ctypes
import os
from collections import OrderedDict
from dataclasses import dataclass
from threading import Event
from time import perf_counter, sleep
from typing import Any

from ._deps import HandleScanDeps
from ._types import MemGuardScanStats


_PROCESS_OBJECT_TYPE_INDEX: int | None = None
_WINAPI: "_HandleScanWinApi | None" = None


@dataclass(frozen=True)
class _HandleScanWinApi:
    NtQuerySystemInformation: Any
    OpenProcess: Any
    DuplicateHandle: Any
    GetCurrentProcess: Any
    GetProcessId: Any
    CloseHandle: Any


def _get_winapi() -> _HandleScanWinApi:
    global _WINAPI
    if _WINAPI is not None:
        return _WINAPI

    ntdll = ctypes.WinDLL("ntdll")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    NtQuerySystemInformation.restype = ctypes.c_ulong

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    OpenProcess.restype = ctypes.c_void_p

    DuplicateHandle = kernel32.DuplicateHandle
    DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    DuplicateHandle.restype = ctypes.c_int

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = ctypes.c_void_p

    GetProcessId = kernel32.GetProcessId
    GetProcessId.argtypes = [ctypes.c_void_p]
    GetProcessId.restype = ctypes.c_ulong

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int

    _WINAPI = _HandleScanWinApi(
        NtQuerySystemInformation=NtQuerySystemInformation,
        OpenProcess=OpenProcess,
        DuplicateHandle=DuplicateHandle,
        GetCurrentProcess=GetCurrentProcess,
        GetProcessId=GetProcessId,
        CloseHandle=CloseHandle,
    )
    return _WINAPI


class PidHandleCache:
    def __init__(self, cap: int = 128):
        self.cap = max(1, int(cap))
        self._lru: OrderedDict[int, int] = OrderedDict()

    def set_cap(self, cap: int, close_handle):
        self.cap = max(1, int(cap))
        while len(self._lru) > self.cap:
            _, handle = self._lru.popitem(last=False)
            close_handle(ctypes.c_void_p(handle))

    def get_or_open(self, pid: int, open_process, close_handle, stats=None) -> int | None:
        if pid in self._lru:
            existing = self._lru[pid]
            self._lru.move_to_end(pid)
            if stats:
                stats.cache_hits += 1
            return existing

        if stats:
            stats.cache_misses += 1
            stats.openprocess_calls += 1

        opened = int(open_process(pid) or 0)
        if not opened:
            if stats:
                stats.openprocess_fail += 1
            return None

        if stats:
            stats.openprocess_success += 1

        self._lru[pid] = opened
        self._lru.move_to_end(pid)

        while len(self._lru) > self.cap:
            _, handle = self._lru.popitem(last=False)
            close_handle(ctypes.c_void_p(handle))
        if stats:
            stats.peak_cache_size = max(stats.peak_cache_size, len(self._lru))
        return opened

    def close_all(self, close_handle):
        for handle in self._lru.values():
            close_handle(ctypes.c_void_p(handle))
        self._lru.clear()


def get_process_object_type_index(*, deps: HandleScanDeps):
    is_mem_guard_supported_fn = deps.is_mem_guard_supported_fn
    constants = deps.constants
    global _PROCESS_OBJECT_TYPE_INDEX
    if _PROCESS_OBJECT_TYPE_INDEX is not None:
        return _PROCESS_OBJECT_TYPE_INDEX
    if not is_mem_guard_supported_fn():
        return None

    try:
        winapi = _get_winapi()
    except OSError:
        return None

    class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
        _fields_ = [
            ("Object", ctypes.c_void_p),
            ("UniqueProcessId", ctypes.c_size_t),
            ("HandleValue", ctypes.c_size_t),
            ("GrantedAccess", ctypes.c_ulong),
            ("CreatorBackTraceIndex", ctypes.c_ushort),
            ("ObjectTypeIndex", ctypes.c_ushort),
            ("HandleAttributes", ctypes.c_ulong),
            ("Reserved", ctypes.c_ulong),
        ]

    current_pid = os.getpid()
    self_handle = winapi.OpenProcess(constants.PROCESS_QUERY_LIMITED_INFORMATION, 0, current_pid)
    if not self_handle:
        return None
    try:
        size = 0x20000
        for _ in range(6):
            buffer = ctypes.create_string_buffer(size)
            return_len = ctypes.c_ulong(0)
            status = winapi.NtQuerySystemInformation(constants.SystemExtendedHandleInformation, ctypes.byref(buffer), size, ctypes.byref(return_len))
            if status == 0:
                break
            if status == constants.STATUS_INFO_LENGTH_MISMATCH:
                size = max(size * 2, return_len.value + 0x1000)
                continue
            return None
        else:
            return None

        count = ctypes.c_size_t.from_buffer_copy(buffer.raw[: ctypes.sizeof(ctypes.c_size_t)]).value
        header_size = ctypes.sizeof(ctypes.c_size_t) * 2
        entries = ctypes.cast(ctypes.byref(buffer, header_size), ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))
        self_handle_value = int(self_handle or 0)

        for idx in range(count):
            entry = entries[idx]
            if int(entry.UniqueProcessId) == current_pid and int(entry.HandleValue) == self_handle_value:
                _PROCESS_OBJECT_TYPE_INDEX = int(entry.ObjectTypeIndex)
                return _PROCESS_OBJECT_TYPE_INDEX
    finally:
        winapi.CloseHandle(self_handle)
    return None


def enumerate_handles_to_pid_windows(
    target_pid: int,
    *,
    deps: HandleScanDeps,
    stop_event: Event | None = None,
    start_index: int = 0,
    max_entries: int = 0,
    owner_pid_filter: set[int] | None = None,
    pid_handle_cache: PidHandleCache | None = None,
    stats: MemGuardScanStats | None = None,
):
    is_mem_guard_supported_fn = deps.is_mem_guard_supported_fn
    constants = deps.constants
    if not is_mem_guard_supported_fn():
        return [], 0, 0, 0

    try:
        winapi = _get_winapi()
    except OSError:
        return [], 0, 0, 0

    class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
        _fields_ = [
            ("Object", ctypes.c_void_p),
            ("UniqueProcessId", ctypes.c_size_t),
            ("HandleValue", ctypes.c_size_t),
            ("GrantedAccess", ctypes.c_ulong),
            ("CreatorBackTraceIndex", ctypes.c_ushort),
            ("ObjectTypeIndex", ctypes.c_ushort),
            ("HandleAttributes", ctypes.c_ulong),
            ("Reserved", ctypes.c_ulong),
        ]

    size = 0x20000
    buffer = None
    for _ in range(6):
        buffer = ctypes.create_string_buffer(size)
        return_len = ctypes.c_ulong(0)
        status = winapi.NtQuerySystemInformation(constants.SystemExtendedHandleInformation, ctypes.byref(buffer), size, ctypes.byref(return_len))
        if status == 0:
            break
        if status == constants.STATUS_INFO_LENGTH_MISMATCH:
            size = max(size * 2, return_len.value + 0x1000)
            continue
        return [], 0, 0, 0
    else:
        return [], 0, 0, 0

    if buffer is None:
        return [], 0, 0, 0
    count = ctypes.c_size_t.from_buffer_copy(buffer.raw[: ctypes.sizeof(ctypes.c_size_t)]).value
    if count <= 0:
        return [], 0, 0, 0

    header_size = ctypes.sizeof(ctypes.c_size_t) * 2
    entries = ctypes.cast(ctypes.byref(buffer, header_size), ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))
    current_process = winapi.GetCurrentProcess()
    process_object_type_index = get_process_object_type_index(deps=deps)

    start_index = max(0, int(start_index)) % count
    max_entries = count if int(max_entries) <= 0 else max(500, int(max_entries))

    hits: list[tuple[int, int]] = []
    scanned = 0
    idx = start_index
    while scanned < min(max_entries, count):
        if stop_event is not None and stop_event.is_set():
            break
        entry = entries[idx]
        owner_pid = int(entry.UniqueProcessId)

        if owner_pid <= 0 or owner_pid == os.getpid():
            idx = (idx + 1) % count
            scanned += 1
            continue
        if owner_pid_filter is not None and owner_pid not in owner_pid_filter:
            idx = (idx + 1) % count
            scanned += 1
            continue
        if process_object_type_index is not None and int(entry.ObjectTypeIndex) != process_object_type_index:
            idx = (idx + 1) % count
            scanned += 1
            continue
        if not (int(entry.GrantedAccess) & constants.PROCESS_VM_ACCESS_MASK):
            idx = (idx + 1) % count
            scanned += 1
            continue

        if pid_handle_cache is not None:
            owner_handle = pid_handle_cache.get_or_open(
                owner_pid,
                lambda p: winapi.OpenProcess(constants.PROCESS_DUP_HANDLE | constants.PROCESS_QUERY_LIMITED_INFORMATION, 0, p),
                winapi.CloseHandle,
                stats,
            )
        else:
            if stats:
                stats.openprocess_calls += 1
            opened = winapi.OpenProcess(constants.PROCESS_DUP_HANDLE | constants.PROCESS_QUERY_LIMITED_INFORMATION, 0, owner_pid)
            owner_handle = int(opened or 0)
            if stats:
                if owner_handle:
                    stats.openprocess_success += 1
                else:
                    stats.openprocess_fail += 1

        if owner_handle:
            dup_handle = ctypes.c_void_p()
            try:
                ok = winapi.DuplicateHandle(ctypes.c_void_p(owner_handle), ctypes.c_void_p(entry.HandleValue), current_process, ctypes.byref(dup_handle), 0, 0, constants.DUPLICATE_SAME_ACCESS)
                if ok and dup_handle and int(winapi.GetProcessId(dup_handle)) == target_pid:
                    hits.append((owner_pid, int(entry.GrantedAccess)))
            finally:
                if dup_handle:
                    winapi.CloseHandle(dup_handle)
                if pid_handle_cache is None:
                    winapi.CloseHandle(ctypes.c_void_p(owner_handle))

        idx = (idx + 1) % count
        scanned += 1

    return hits, idx, int(count), int(scanned)


def enumerate_reader_pids_windows(
    target_pid: int,
    *,
    enumerate_handles_to_pid_windows_fn,
    stop_event: Event | None = None,
    start_index: int = 0,
    max_entries: int = 0,
    owner_pid_filter: set[int] | None = None,
    pid_handle_cache: PidHandleCache | None = None,
    stats: MemGuardScanStats | None = None,
):
    scan_started = perf_counter()
    reader_access: dict[int, int] = {}
    hits, next_index, total_count, scanned_count = enumerate_handles_to_pid_windows_fn(
        target_pid,
        stop_event=stop_event,
        start_index=start_index,
        max_entries=max_entries,
        owner_pid_filter=owner_pid_filter,
        pid_handle_cache=pid_handle_cache,
        stats=stats,
    )
    for owner_pid, access in hits:
        if stop_event is not None and stop_event.is_set():
            break
        prev = reader_access.get(owner_pid)
        if prev is None or access > prev:
            reader_access[owner_pid] = access
    if stats:
        stats.scans += 1
        stats.runtime_ms_total += (perf_counter() - scan_started) * 1000.0
    return reader_access, next_index, total_count, scanned_count


def estimate_scan_time_ms(
    *,
    is_mem_guard_supported_fn,
    MemGuardScanStats,
    enumerate_reader_pids_windows_fn,
    PidHandleCache,
    samples: int = 25,
    max_entries: int = 0,
    cache_cap: int = 128,
    target_pid: int | None = None,
    inter_scan_delay_ms: int = 0,
):
    if not is_mem_guard_supported_fn():
        return None
    try:
        winapi = _get_winapi()
    except OSError:
        return None

    pid = int(target_pid or os.getpid())
    cache = PidHandleCache(cap=max(32, int(cache_cap)))
    stats = MemGuardScanStats()
    cursor = 0
    n = max(1, int(samples))
    delay_ms = max(0, int(inter_scan_delay_ms))
    total_work_ms = 0.0
    full_scans_completed = 0
    current_full_scan_work_ms = 0.0
    current_full_scan_entries = 0
    max_internal_calls = max(100, n * 200)
    internal_calls = 0
    try:
        while full_scans_completed < n and internal_calls < max_internal_calls:
            internal_calls += 1
            prev_cursor = cursor
            t0 = perf_counter()
            _, cursor, total_count, scanned_count = enumerate_reader_pids_windows_fn(pid, start_index=cursor, max_entries=max_entries, pid_handle_cache=cache, stats=stats)
            work_ms = (perf_counter() - t0) * 1000.0
            current_full_scan_work_ms += work_ms
            current_full_scan_entries += max(0, int(scanned_count))
            wrapped = bool(total_count > 0 and cursor < prev_cursor)
            reached_full = bool(total_count > 0 and current_full_scan_entries >= int(total_count))
            if total_count > 0 and (wrapped or reached_full):
                total_work_ms += current_full_scan_work_ms
                full_scans_completed += 1
                current_full_scan_work_ms = 0.0
                current_full_scan_entries = 0
            if delay_ms > 0 and full_scans_completed < n:
                sleep(delay_ms / 1000.0)
    finally:
        cache.close_all(winapi.CloseHandle)
    if full_scans_completed <= 0:
        return None
    return total_work_ms / float(full_scans_completed)
