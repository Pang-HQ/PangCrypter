import ctypes
import hashlib
import json
import logging
import os
import platform
from dataclasses import dataclass
from enum import Enum
from ctypes import wintypes
from threading import Event
from collections import OrderedDict
from time import perf_counter, monotonic, sleep

import psutil
from PyQt6.QtCore import QObject, pyqtSignal

logger = logging.getLogger(__name__)


class MemGuardMode(Enum):
    OFF = "off"
    NORMAL = "normal"
    ULTRA_AGGRESSIVE = "ultra_aggressive"


class SigTrust(Enum):
    UNSIGNED = "unsigned"
    SIGNED_TRUSTED = "trusted"
    SIGNED_UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class FindingSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingDisposition(Enum):
    ALERT = "alert"
    LOG_ONLY = "log_only"


@dataclass(frozen=True)
class SigResult:
    trust: SigTrust
    status: int = 0


@dataclass(frozen=True)
class MemGuardFinding:
    pid: int
    process_name: str
    process_path: str
    sha256: str
    sig_trust: SigTrust
    winverifytrust_status: int
    access_mask: int
    severity: FindingSeverity
    disposition: FindingDisposition
    reason: str


@dataclass
class MemGuardScanStats:
    openprocess_calls: int = 0
    openprocess_success: int = 0
    openprocess_fail: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    peak_cache_size: int = 0
    scans: int = 0
    runtime_ms_total: float = 0.0


class PidHandleCache:
    def __init__(self, cap: int = 128):
        self.cap = max(1, int(cap))
        self._lru: OrderedDict[int, int] = OrderedDict()

    def set_cap(self, cap: int, close_handle):
        self.cap = max(1, int(cap))
        while len(self._lru) > self.cap:
            _, handle = self._lru.popitem(last=False)
            close_handle(ctypes.c_void_p(handle))

    def get_or_open(self, pid: int, open_process, close_handle, stats: MemGuardScanStats | None = None) -> int | None:
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


PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_ACCESS_MASK = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
DUPLICATE_SAME_ACCESS = 0x00000002

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
SystemExtendedHandleInformation = 64
_PROCESS_OBJECT_TYPE_INDEX: int | None = None

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000004
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001


def _emit_telemetry(event: str, **fields) -> None:
    logger.debug("MemGuard telemetry: %s", json.dumps({"event": event, **fields}, sort_keys=True, default=str))


def _log_decision(
    *,
    mode: MemGuardMode,
    pid: int,
    process_name: str,
    process_path: str,
    access_mask: int,
    has_read: bool,
    has_write_or_op: bool,
    sig: SigResult,
    process_hash: str,
    decision: str,
    reason: str,
    lineage: str = "",
    severity: FindingSeverity | None = None,
    disposition: FindingDisposition | None = None,
) -> None:
    logger.info(
        (
            "MemGuard decision=%s mode=%s pid=%s name=%r path=%r "
            "access_mask=0x%08x has_read=%s has_write_or_op=%s "
            "sig_trust=%s winverifytrust_status=0x%08x sha256=%s "
            "severity=%s disposition=%s lineage=%s reason=%s"
        ),
        decision,
        mode.value,
        pid,
        process_name,
        process_path,
        int(access_mask),
        has_read,
        has_write_or_op,
        sig.trust.value,
        int(sig.status),
        process_hash or "<none>",
        severity.value if severity else "<none>",
        disposition.value if disposition else "<none>",
        lineage or "<none>",
        reason,
    )


def is_mem_guard_supported() -> bool:
    return os.name == "nt" and platform.system() == "Windows"


def default_mem_guard_mode() -> str:
    return MemGuardMode.NORMAL.value if is_mem_guard_supported() else MemGuardMode.OFF.value


def _normalize_path(path: str) -> str:
    if not path:
        return ""
    return os.path.normcase(os.path.abspath(path))


def _is_program_files_path(path: str) -> bool:
    if not path:
        return False
    npath = _normalize_path(path)
    program_files_roots = [
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    for root in program_files_roots:
        if not root:
            continue
        nroot = _normalize_path(root)
        if npath == nroot or npath.startswith(nroot + os.sep):
            return True
    return False


def is_path_whitelisted(process_path: str, whitelist: list[str]) -> bool:
    normalized = _normalize_path(process_path)
    return bool(normalized) and normalized in {_normalize_path(p) for p in whitelist}


def _signature_status_windows(path: str, *, cache_only: bool = True) -> SigResult:
    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_uint32),
            ("Data2", ctypes.c_uint16),
            ("Data3", ctypes.c_uint16),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    if not is_mem_guard_supported() or not path or not os.path.exists(path):
        return SigResult(SigTrust.UNKNOWN, 0)

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_uint32),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_uint32),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_uint32),
            ("fdwRevocationChecks", ctypes.c_uint32),
            ("dwUnionChoice", ctypes.c_uint32),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_uint32),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_uint32),
            ("dwUIContext", ctypes.c_uint32),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    action_guid = GUID(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    file_info = WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=path,
        hFile=None,
        pgKnownSubject=None,
    )
    data = WINTRUST_DATA(
        cbStruct=ctypes.sizeof(WINTRUST_DATA),
        pPolicyCallbackData=None,
        pSIPClientData=None,
        dwUIChoice=WTD_UI_NONE,
        fdwRevocationChecks=WTD_REVOKE_NONE,
        dwUnionChoice=WTD_CHOICE_FILE,
        pFile=ctypes.pointer(file_info),
        dwStateAction=WTD_STATEACTION_IGNORE,
        hWVTStateData=None,
        pwszURLReference=None,
        dwProvFlags=WTD_CACHE_ONLY_URL_RETRIEVAL if cache_only else 0,
        dwUIContext=0,
        pSignatureSettings=None,
    )

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    win_verify_trust = wintrust.WinVerifyTrust
    win_verify_trust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
    win_verify_trust.restype = ctypes.c_long

    result = win_verify_trust(None, ctypes.byref(action_guid), ctypes.byref(data))
    status = ctypes.c_uint32(result).value
    if status == 0:
        return SigResult(SigTrust.SIGNED_TRUSTED, 0)
    if status == TRUST_E_NOSIGNATURE:
        if _is_windows_system_path(path):
            return SigResult(SigTrust.UNKNOWN, status)
        return SigResult(SigTrust.UNSIGNED, status)
    if status in (TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN):
        return SigResult(SigTrust.UNKNOWN, status)
    return SigResult(SigTrust.SIGNED_UNTRUSTED, status)


def _signature_status_with_fallback(path: str) -> SigResult:
    sig = _signature_status_windows(path, cache_only=True)
    if sig.trust == SigTrust.SIGNED_TRUSTED:
        return sig

    # Retry non-cache-only for genuine Windows system binaries to reduce
    # cache-induced false negatives while limiting verification overhead.
    if _is_windows_system_path(path) and sig.trust in {SigTrust.UNKNOWN, SigTrust.SIGNED_UNTRUSTED}:
        return _signature_status_windows(path, cache_only=False)
    return sig


def file_sha256(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_process_object_type_index() -> int | None:
    global _PROCESS_OBJECT_TYPE_INDEX
    if _PROCESS_OBJECT_TYPE_INDEX is not None:
        return _PROCESS_OBJECT_TYPE_INDEX

    if not is_mem_guard_supported():
        return None

    ntdll = ctypes.WinDLL("ntdll")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

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

    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.argtypes = [
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    NtQuerySystemInformation.restype = ctypes.c_ulong

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    OpenProcess.restype = ctypes.c_void_p

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int

    current_pid = os.getpid()
    self_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, current_pid)
    if not self_handle:
        return None

    try:
        size = 0x20000
        for _ in range(6):
            buffer = ctypes.create_string_buffer(size)
            return_len = ctypes.c_ulong(0)
            status = NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                ctypes.byref(buffer),
                size,
                ctypes.byref(return_len),
            )
            if status == 0:
                break
            if status == STATUS_INFO_LENGTH_MISMATCH:
                size = max(size * 2, return_len.value + 0x1000)
                continue
            return None
        else:
            return None

        count = ctypes.c_size_t.from_buffer_copy(buffer.raw[: ctypes.sizeof(ctypes.c_size_t)]).value
        header_size = ctypes.sizeof(ctypes.c_size_t) * 2
        entries = ctypes.cast(
            ctypes.byref(buffer, header_size),
            ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
        )
        self_handle_value = int(self_handle or 0)

        for idx in range(count):
            entry = entries[idx]
            if int(entry.UniqueProcessId) != current_pid:
                continue
            if int(entry.HandleValue) == self_handle_value:
                _PROCESS_OBJECT_TYPE_INDEX = int(entry.ObjectTypeIndex)
                return _PROCESS_OBJECT_TYPE_INDEX
    finally:
        CloseHandle(self_handle)

    return None


def _enumerate_handles_to_pid_windows(
    target_pid: int,
    stop_event: Event | None = None,
    start_index: int = 0,
    max_entries: int = 0,
    pid_handle_cache: PidHandleCache | None = None,
    stats: MemGuardScanStats | None = None,
) -> tuple[list[tuple[int, int]], int]:
    if not is_mem_guard_supported():
        return [], 0

    ntdll = ctypes.WinDLL("ntdll")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

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

    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.argtypes = [
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    NtQuerySystemInformation.restype = ctypes.c_ulong

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    OpenProcess.restype = ctypes.c_void_p

    DuplicateHandle = kernel32.DuplicateHandle
    DuplicateHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    DuplicateHandle.restype = ctypes.c_int

    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = ctypes.c_void_p

    GetProcessId = kernel32.GetProcessId
    GetProcessId.argtypes = [ctypes.c_void_p]
    GetProcessId.restype = ctypes.c_ulong

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int

    # Query system handle table
    size = 0x20000
    buffer = None
    for _ in range(6):
        buffer = ctypes.create_string_buffer(size)
        return_len = ctypes.c_ulong(0)
        status = NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            ctypes.byref(buffer),
            size,
            ctypes.byref(return_len),
        )
        if status == 0:
            break
        if status == STATUS_INFO_LENGTH_MISMATCH:
            size = max(size * 2, return_len.value + 0x1000)
            continue
        return [], 0
    else:
        return [], 0

    if buffer is None:
        logger.debug("MemGuard handle scan buffer allocation failed")
        return [], 0
    count = ctypes.c_size_t.from_buffer_copy(buffer.raw[: ctypes.sizeof(ctypes.c_size_t)]).value
    if count <= 0:
        return [], 0

    header_size = ctypes.sizeof(ctypes.c_size_t) * 2
    entries = ctypes.cast(
        ctypes.byref(buffer, header_size),
        ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX),
    )
    current_process = GetCurrentProcess()
    process_object_type_index = _get_process_object_type_index()

    start_index = max(0, int(start_index)) % count
    max_entries = int(max_entries)
    if max_entries <= 0:
        max_entries = count
    else:
        max_entries = max(500, max_entries)

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

        if process_object_type_index is not None and int(entry.ObjectTypeIndex) != process_object_type_index:
            idx = (idx + 1) % count
            scanned += 1
            continue

        if not (int(entry.GrantedAccess) & PROCESS_VM_ACCESS_MASK):
            idx = (idx + 1) % count
            scanned += 1
            continue

        # Obtain or open the owner process handle
        owner_handle: int | None
        if pid_handle_cache is not None:
            owner_handle = pid_handle_cache.get_or_open(
                owner_pid,
                lambda p: OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, p),
                CloseHandle,
                stats,
            )
        else:
            if stats:
                stats.openprocess_calls += 1
            opened = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, owner_pid)
            owner_handle = int(opened or 0)
            if stats:
                if owner_handle:
                    stats.openprocess_success += 1
                else:
                    stats.openprocess_fail += 1

        if not owner_handle:
            idx = (idx + 1) % count
            scanned += 1
            continue

        dup_handle = ctypes.c_void_p()
        try:
            ok = DuplicateHandle(
                ctypes.c_void_p(owner_handle),
                ctypes.c_void_p(entry.HandleValue),
                current_process,
                ctypes.byref(dup_handle),
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
            if ok and dup_handle:
                target = GetProcessId(dup_handle)
                if int(target) == target_pid:
                    hits.append((owner_pid, int(entry.GrantedAccess)))
        finally:
            if dup_handle:
                CloseHandle(dup_handle)
            if pid_handle_cache is None:
                CloseHandle(ctypes.c_void_p(owner_handle))

        idx = (idx + 1) % count
        scanned += 1

    return hits, idx


def _enumerate_reader_pids_windows(
    target_pid: int,
    stop_event: Event | None = None,
    start_index: int = 0,
    max_entries: int = 0,
    pid_handle_cache: PidHandleCache | None = None,
    stats: MemGuardScanStats | None = None,
) -> tuple[dict[int, int], int]:
    scan_started = perf_counter()
    reader_access: dict[int, int] = {}

    hits, next_index = _enumerate_handles_to_pid_windows(
        target_pid,
        stop_event=stop_event,
        start_index=start_index,
        max_entries=max_entries,
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

    return reader_access, next_index


def estimate_scan_time_ms(
    samples: int = 25,
    max_entries: int = 0,
    cache_cap: int = 128,
    target_pid: int | None = None,
    inter_scan_delay_ms: int = 0,
) -> float | None:
    """Estimate average mem-guard scan cost (ms) using a cached sample window."""
    if not is_mem_guard_supported():
        return None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int

    pid = int(target_pid or os.getpid())
    cache = PidHandleCache(cap=max(32, int(cache_cap)))
    stats = MemGuardScanStats()
    cursor = 0
    n = max(1, int(samples))
    delay_ms = max(0, int(inter_scan_delay_ms))
    total_ms = 0.0

    try:
        for idx in range(n):
            t0 = perf_counter()
            _, cursor = _enumerate_reader_pids_windows(
                pid,
                start_index=cursor,
                max_entries=max_entries,
                pid_handle_cache=cache,
                stats=stats,
            )
            total_ms += (perf_counter() - t0) * 1000.0
            if delay_ms > 0 and idx < (n - 1):
                sleep(delay_ms / 1000.0)
    finally:
        cache.close_all(CloseHandle)

    return total_ms / n


def _is_whitelisted(process_path: str, process_sha256: str, whitelist: list[dict | str]) -> bool:
    if not process_path:
        return False
    normalized_path = _normalize_path(process_path)
    for item in whitelist:
        if isinstance(item, str):
            entry_path = _normalize_path(item)
            entry_sha = ""
        elif isinstance(item, dict):
            entry_path = _normalize_path(str(item.get("path", "")))
            entry_sha = str(item.get("sha256", "")).lower()
        else:
            continue

        if normalized_path != entry_path:
            continue
        if entry_sha and process_sha256:
            return entry_sha == process_sha256.lower()
        return True
    return False


def _is_windows_system_path(path: str) -> bool:
    if not path:
        return False
    normalized = _normalize_path(path)
    system_root = _normalize_path(os.environ.get("SystemRoot", r"C:\Windows"))
    system32 = _normalize_path(os.path.join(system_root, "System32"))
    syswow64 = _normalize_path(os.path.join(system_root, "SysWOW64"))
    return normalized.startswith(system32 + os.sep) or normalized.startswith(syswow64 + os.sep)


def _has_vm_write_or_op(access: int) -> bool:
    return bool(access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION))


def _has_vm_read(access: int) -> bool:
    return bool(access & PROCESS_VM_READ)


def _is_suspicious_signer(sig: SigResult) -> bool:
    return sig.trust in {SigTrust.UNSIGNED, SigTrust.SIGNED_UNTRUSTED, SigTrust.UNKNOWN}


def _is_user_writable_path(path: str) -> bool:
    if not path:
        return False
    npath = _normalize_path(path)
    candidates = [
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local"),
        os.path.join(os.path.expanduser("~"), "AppData", "Roaming"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
    ]
    for base in candidates:
        if not base:
            continue
        nbase = _normalize_path(base)
        if npath == nbase or npath.startswith(nbase + os.sep):
            return True
    return False


def _cached_sig_for_path(process_path: str, signature_cache: dict[tuple[str, int, int], SigResult]) -> SigResult:
    if not process_path or not os.path.exists(process_path):
        return SigResult(SigTrust.UNKNOWN, 0)
    try:
        st = os.stat(process_path)
        stat_key = (process_path, int(st.st_mtime), int(st.st_size))
    except OSError:
        return SigResult(SigTrust.UNKNOWN, 0)

    if stat_key in signature_cache:
        return signature_cache[stat_key]

    sig = _signature_status_with_fallback(process_path)
    signature_cache[stat_key] = sig
    return sig


def _assess_parent_lineage(owner_pid: int, signature_cache: dict[tuple[str, int, int], SigResult], max_depth: int = 12) -> tuple[bool, str]:
    """Return (has_suspicious_parent, lineage_summary)."""
    chain: list[str] = []
    try:
        current = psutil.Process(owner_pid)
    except (psutil.Error, OSError):
        return False, ""

    depth = 0
    while depth < max_depth:
        try:
            ppid_fn = getattr(current, "ppid", None)
            if not callable(ppid_fn):
                break
            ppid = int(ppid_fn())
            if ppid <= 0:
                break

            parent = psutil.Process(ppid)
            parent_name = parent.name() or f"pid-{ppid}"
            parent_path = parent.exe() or ""
            parent_sig = _cached_sig_for_path(parent_path, signature_cache)
            parent_is_system = bool(parent_path) and _is_windows_system_path(parent_path)
            sig_suspicious = bool(parent_path) and _is_suspicious_signer(parent_sig)
            path_suspicious = bool(parent_path) and _is_user_writable_path(parent_path)
            parent_suspicious = sig_suspicious or (path_suspicious and parent_sig.trust != SigTrust.SIGNED_TRUSTED)

            chain.append(
                f"{parent_name}(pid={ppid},system={parent_is_system},sig={parent_sig.trust.value})"
            )
            if parent_suspicious:
                return True, " -> ".join(chain)

            current = parent
            depth += 1
        except (psutil.Error, OSError, ValueError):
            break

    return False, " -> ".join(chain)


def enrich_pid_finding(
    owner_pid: int,
    access: int,
    mode: MemGuardMode,
    whitelist: list[dict | str],
    signature_cache: dict[tuple[str, int, int], SigResult],
    hash_cache: dict[tuple[str, int, int], str],
) -> MemGuardFinding | None:
    try:
        proc = psutil.Process(owner_pid)
        process_name = proc.name() or f"pid-{owner_pid}"
        process_path = proc.exe() or ""
    except (psutil.Error, OSError):
        process_name = f"pid-{owner_pid}"
        process_path = ""

    stat_key: tuple[str, int, int] | None = None
    process_hash = ""
    sig = SigResult(SigTrust.UNKNOWN, 0)
    if process_path and os.path.exists(process_path):
        try:
            st = os.stat(process_path)
            stat_key = (process_path, int(st.st_mtime), int(st.st_size))
        except OSError:
            stat_key = None

    if stat_key:
        process_hash = hash_cache.get(stat_key, "")
        if not process_hash:
            process_hash = file_sha256(process_path)
            hash_cache[stat_key] = process_hash

        sig = signature_cache.get(stat_key, SigResult(SigTrust.UNKNOWN, 0))
        if stat_key not in signature_cache:
            sig = _signature_status_with_fallback(process_path)
            signature_cache[stat_key] = sig

    if _is_whitelisted(process_path, process_hash, whitelist):
        _log_decision(
            mode=mode,
            pid=owner_pid,
            process_name=process_name,
            process_path=process_path,
            access_mask=int(access),
            has_read=_has_vm_read(int(access)),
            has_write_or_op=_has_vm_write_or_op(int(access)),
            sig=sig,
            process_hash=process_hash,
            decision="whitelisted",
            reason="Path/hash matches configured mem-guard whitelist",
        )
        _emit_telemetry(
            "suppressed_whitelist",
            pid=owner_pid,
            process_name=process_name,
            process_path=process_path,
            access_mask=f"0x{int(access):08x}",
            sig_trust=sig.trust.value,
        )
        return None

    access_int = int(access)
    has_read = _has_vm_read(access_int)
    has_write_or_op = _has_vm_write_or_op(access_int)

    if mode == MemGuardMode.NORMAL:
        if has_write_or_op:
            is_system_path = bool(process_path) and _is_windows_system_path(process_path)
            is_user_writable = bool(process_path) and _is_user_writable_path(process_path)
            system_loc = is_system_path and not is_user_writable

            trusted_system_signed = system_loc and sig.trust == SigTrust.SIGNED_TRUSTED
            benign_system_inconclusive = system_loc and sig.trust in {SigTrust.UNKNOWN, SigTrust.SIGNED_UNTRUSTED}
            has_suspicious_parent, lineage_summary = _assess_parent_lineage(owner_pid, signature_cache)
            if trusted_system_signed and not has_suspicious_parent:
                severity = FindingSeverity.LOW
                disposition = FindingDisposition.LOG_ONLY
            elif benign_system_inconclusive and not has_suspicious_parent:
                severity = FindingSeverity.MEDIUM
                disposition = FindingDisposition.LOG_ONLY
            else:
                severity = FindingSeverity.HIGH
                disposition = FindingDisposition.ALERT
            reason = f"Handle with VM write/operation access 0x{access:08x}"
            if has_suspicious_parent:
                reason += " (suspicious parent lineage)"
            elif benign_system_inconclusive and disposition == FindingDisposition.LOG_ONLY:
                reason += " (system-path signature inconclusive)"
            _log_decision(
                mode=mode,
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=access_int,
                has_read=has_read,
                has_write_or_op=has_write_or_op,
                sig=sig,
                process_hash=process_hash,
                decision="log_only" if disposition == FindingDisposition.LOG_ONLY else "detected",
                reason=reason,
                lineage=lineage_summary,
                severity=severity,
                disposition=disposition,
            )
            _emit_telemetry(
                "detection",
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=f"0x{access_int:08x}",
                sig_trust=sig.trust.value,
                severity=severity.value,
                disposition=disposition.value,
                detection_reason=reason,
            )
            return MemGuardFinding(
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                sha256=process_hash,
                sig_trust=sig.trust,
                winverifytrust_status=sig.status,
                access_mask=access_int,
                severity=severity,
                disposition=disposition,
                reason=reason,
            )
        elif has_read:
            if _is_suspicious_signer(sig):
                _emit_telemetry(
                    "detection",
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=f"0x{access_int:08x}",
                    sig_trust=sig.trust.value,
                    severity=FindingSeverity.MEDIUM.value,
                    disposition=FindingDisposition.ALERT.value,
                    detection_reason=f"Handle with VM read access 0x{access:08x}",
                )
                _log_decision(
                    mode=mode,
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=access_int,
                    has_read=has_read,
                    has_write_or_op=has_write_or_op,
                    sig=sig,
                    process_hash=process_hash,
                    decision="detected",
                    reason=f"Handle with VM read access 0x{access:08x}",
                    severity=FindingSeverity.MEDIUM,
                    disposition=FindingDisposition.ALERT,
                )
                return MemGuardFinding(
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    sha256=process_hash,
                    sig_trust=sig.trust,
                    winverifytrust_status=sig.status,
                    access_mask=access_int,
                    severity=FindingSeverity.MEDIUM,
                    disposition=FindingDisposition.ALERT,
                    reason=f"Handle with VM read access 0x{access:08x}",
                )
            if process_path and _is_windows_system_path(process_path) and sig.trust == SigTrust.SIGNED_TRUSTED:
                has_suspicious_parent, lineage_summary = _assess_parent_lineage(owner_pid, signature_cache)
                if has_suspicious_parent:
                    reason = f"Handle with VM read access 0x{access:08x} (suspicious parent lineage)"
                    _emit_telemetry(
                        "detection",
                        pid=owner_pid,
                        process_name=process_name,
                        process_path=process_path,
                        access_mask=f"0x{access_int:08x}",
                        sig_trust=sig.trust.value,
                        severity=FindingSeverity.MEDIUM.value,
                        disposition=FindingDisposition.ALERT.value,
                        detection_reason=reason,
                    )
                    _log_decision(
                        mode=mode,
                        pid=owner_pid,
                        process_name=process_name,
                        process_path=process_path,
                        access_mask=access_int,
                        has_read=has_read,
                        has_write_or_op=has_write_or_op,
                        sig=sig,
                        process_hash=process_hash,
                        decision="detected",
                        reason=reason,
                        lineage=lineage_summary,
                        severity=FindingSeverity.MEDIUM,
                        disposition=FindingDisposition.ALERT,
                    )
                    return MemGuardFinding(
                        pid=owner_pid,
                        process_name=process_name,
                        process_path=process_path,
                        sha256=process_hash,
                        sig_trust=sig.trust,
                        winverifytrust_status=sig.status,
                        access_mask=access_int,
                        severity=FindingSeverity.MEDIUM,
                        disposition=FindingDisposition.ALERT,
                        reason=reason,
                    )
                _emit_telemetry(
                    "suppressed_normal_low",
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=f"0x{access_int:08x}",
                    sig_trust=sig.trust.value,
                    suppression_reason="trusted_system_vm_read_only",
                    severity=FindingSeverity.LOW.value,
                    disposition=FindingDisposition.LOG_ONLY.value,
                )
                _log_decision(
                    mode=mode,
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=access_int,
                    has_read=has_read,
                    has_write_or_op=has_write_or_op,
                    sig=sig,
                    process_hash=process_hash,
                    decision="log_only",
                    reason=f"Handle with VM read access 0x{access:08x}",
                    lineage=lineage_summary,
                    severity=FindingSeverity.LOW,
                    disposition=FindingDisposition.LOG_ONLY,
                )
                return MemGuardFinding(
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    sha256=process_hash,
                    sig_trust=sig.trust,
                    winverifytrust_status=sig.status,
                    access_mask=access_int,
                    severity=FindingSeverity.LOW,
                    disposition=FindingDisposition.LOG_ONLY,
                    reason=f"Handle with VM read access 0x{access:08x}",
                )

            # Trusted signer but non-system path: keep visible to user at medium severity.
            _emit_telemetry(
                "detection",
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=f"0x{access_int:08x}",
                sig_trust=sig.trust.value,
                severity=FindingSeverity.MEDIUM.value,
                disposition=FindingDisposition.ALERT.value,
                detection_reason=f"Handle with VM read access (trusted non-system) 0x{access:08x}",
            )
            _log_decision(
                mode=mode,
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=access_int,
                has_read=has_read,
                has_write_or_op=has_write_or_op,
                sig=sig,
                process_hash=process_hash,
                decision="detected",
                reason=f"Handle with VM read access (trusted non-system) 0x{access:08x}",
                severity=FindingSeverity.MEDIUM,
                disposition=FindingDisposition.ALERT,
            )
            return MemGuardFinding(
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                sha256=process_hash,
                sig_trust=sig.trust,
                winverifytrust_status=sig.status,
                access_mask=access_int,
                severity=FindingSeverity.MEDIUM,
                disposition=FindingDisposition.ALERT,
                reason=f"Handle with VM read access (trusted non-system) 0x{access:08x}",
            )

    reason = f"Handle with VM access 0x{access:08x}"
    severity = FindingSeverity.HIGH if has_write_or_op else FindingSeverity.MEDIUM
    disposition = FindingDisposition.ALERT
    _emit_telemetry(
        "detection",
        pid=owner_pid,
        process_name=process_name,
        process_path=process_path,
        access_mask=f"0x{access_int:08x}",
        sig_trust=sig.trust.value,
        severity=severity.value,
        disposition=disposition.value,
        detection_reason=reason,
    )
    _log_decision(
        mode=mode,
        pid=owner_pid,
        process_name=process_name,
        process_path=process_path,
        access_mask=access_int,
        has_read=has_read,
        has_write_or_op=has_write_or_op,
        sig=sig,
        process_hash=process_hash,
        decision="detected",
        reason=reason,
        severity=severity,
        disposition=disposition,
    )
    return MemGuardFinding(
        pid=owner_pid,
        process_name=process_name,
        process_path=process_path,
        sha256=process_hash,
        sig_trust=sig.trust,
        winverifytrust_status=sig.status,
        access_mask=access_int,
        severity=severity,
        disposition=disposition,
        reason=reason,
    )


def find_suspicious_memory_readers(
    target_pid: int,
    mode: MemGuardMode,
    whitelist: list[dict | str],
) -> list[MemGuardFinding]:
    if mode == MemGuardMode.OFF or not is_mem_guard_supported():
        return []

    findings: list[MemGuardFinding] = []
    signature_cache: dict[tuple[str, int, int], SigResult] = {}
    hash_cache: dict[tuple[str, int, int], str] = {}

    owner_map, _ = _enumerate_reader_pids_windows(target_pid)
    for owner_pid, access in owner_map.items():
        finding = enrich_pid_finding(owner_pid, access, mode, whitelist, signature_cache, hash_cache)
        if finding:
            findings.append(finding)

    return findings


class MemGuardChecker(QObject):
    memory_probe_detected = pyqtSignal(object)

    def __init__(
        self,
        mode: MemGuardMode,
        whitelist: list[dict | str],
        check_interval_ms: int = 50,
        pid_handle_cache_cap: int = 128,
        alert_cooldown_sec: int = 10,
    ):
        super().__init__()
        self.mode = mode
        self.whitelist = whitelist
        self.check_interval_ms = max(20, int(check_interval_ms))
        self.running = True
        self._stop_event = Event()
        self._signature_cache: dict[tuple[str, int, int], SigResult] = {}
        self._hash_cache: dict[tuple[str, int, int], str] = {}
        self._scan_cursor = 0
        # 0 means "scan full handle table per cycle".
        self._max_entries_per_scan = 0
        self._pid_handle_cache = PidHandleCache(cap=max(32, int(pid_handle_cache_cap)))
        self._scan_stats = MemGuardScanStats()
        self._alert_cooldown_sec = max(0, int(alert_cooldown_sec))
        self._last_alert_at: dict[tuple[int, FindingSeverity], float] = {}

    def _should_emit_alert(self, pid: int, severity: FindingSeverity) -> bool:
        if self._alert_cooldown_sec <= 0:
            return True
        key = (int(pid), severity)
        now = monotonic()
        last = self._last_alert_at.get(key, 0.0)
        if (now - last) < self._alert_cooldown_sec:
            return False
        self._last_alert_at[key] = now
        return True

    def stop(self):
        self.running = False
        self._stop_event.set()

    def close_resources(self):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [ctypes.c_void_p]
        CloseHandle.restype = ctypes.c_int
        self._pid_handle_cache.close_all(CloseHandle)

    def run(self):
        while self.running:
            try:
                current_alertable_pids: set[int] = set()
                owner_map, self._scan_cursor = _enumerate_reader_pids_windows(
                    os.getpid(),
                    stop_event=self._stop_event,
                    start_index=self._scan_cursor,
                    max_entries=self._max_entries_per_scan,
                    pid_handle_cache=self._pid_handle_cache,
                    stats=self._scan_stats,
                )
                for owner_pid, access in owner_map.items():
                    if self._stop_event.is_set():
                        break

                    finding = enrich_pid_finding(
                        owner_pid,
                        access,
                        self.mode,
                        self.whitelist,
                        self._signature_cache,
                        self._hash_cache,
                    )
                    if not finding:
                        continue
                    if finding.disposition != FindingDisposition.ALERT:
                        continue
                    current_alertable_pids.add(finding.pid)
                    if not self._should_emit_alert(finding.pid, finding.severity):
                        _emit_telemetry(
                            "suppressed_debounce",
                            pid=finding.pid,
                            process_name=finding.process_name,
                            process_path=finding.process_path,
                            access_mask=f"0x{finding.access_mask:08x}",
                            sig_trust=finding.sig_trust.value,
                            severity=finding.severity.value,
                            disposition=finding.disposition.value,
                            suppression_reason="alert_cooldown",
                        )
                        continue
                    self.memory_probe_detected.emit(finding)
            except (OSError, RuntimeError, ValueError, psutil.Error) as e:
                logger.debug("Memory guard scan failed: %s", e)

            if self._stop_event.wait(self.check_interval_ms / 1000.0):
                break

        self.close_resources()
