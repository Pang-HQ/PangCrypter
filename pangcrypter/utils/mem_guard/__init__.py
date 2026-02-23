import ctypes
import json
import logging
import os
import platform
from ctypes import wintypes

import psutil

from . import _constants as constants
from ._types import (
    MemGuardMode,
    SigTrust,
    FindingSeverity,
    FindingDisposition,
    SigResult,
    MemGuardFinding,
    DecisionLogContext,
    DecisionLogEvent,
    MemGuardScanStats,
)
from ._deps import EnrichPolicyDeps, HandleScanDeps, SignatureWindowsDeps
from ._paths import normalize_path, is_windows_system_path, is_user_writable_path, whitelist_requirements_for_path
from ._hashing import file_sha256 as _file_sha256_impl, build_stat_key as _build_stat_key_impl, compute_or_get_hash as _compute_or_get_hash_impl
from ._signature_windows import signature_status_windows as _signature_status_windows_impl, signature_status_with_fallback as _signature_status_with_fallback_impl
from ._lineage import cached_sig_for_path as _cached_sig_for_path_impl, assess_parent_lineage as _assess_parent_lineage_impl
from ._handle_scan_windows import (
    PidHandleCache,
    get_process_object_type_index as _get_process_object_type_index_impl,
    enumerate_handles_to_pid_windows as _enumerate_handles_to_pid_windows_impl,
    enumerate_reader_pids_windows as _enumerate_reader_pids_windows_impl,
    estimate_scan_time_ms as _estimate_scan_time_ms_impl,
)
from ._policy import has_vm_write_or_op as _has_vm_write_or_op_impl, has_vm_read as _has_vm_read_impl, is_suspicious_signer as _is_suspicious_signer_impl, enrich_pid_finding as _enrich_pid_finding_impl
from .etw_process_watcher import EtwProcessWatcher, ProcessWatcherStatus
from ._impl import MemGuardChecker

__all__ = [
    "MemGuardMode",
    "SigTrust",
    "FindingSeverity",
    "FindingDisposition",
    "SigResult",
    "MemGuardFinding",
    "DecisionLogContext",
    "DecisionLogEvent",
    "MemGuardScanStats",
    "MemGuardChecker",
    "EtwProcessWatcher",
    "ProcessWatcherStatus",
    "is_mem_guard_supported",
    "default_mem_guard_mode",
    "file_sha256",
    "estimate_scan_time_ms",
    "find_suspicious_memory_readers",
    "enrich_pid_finding",
    "PROCESS_VM_OPERATION",
    "PROCESS_VM_READ",
    "PROCESS_VM_WRITE",
    "PROCESS_VM_ACCESS_MASK",
    "PROCESS_DUP_HANDLE",
    "PROCESS_QUERY_LIMITED_INFORMATION",
    "DUPLICATE_SAME_ACCESS",
    "STATUS_INFO_LENGTH_MISMATCH",
    "SystemExtendedHandleInformation",
    "WTD_UI_NONE",
    "WTD_REVOKE_NONE",
    "WTD_CHOICE_FILE",
    "WTD_STATEACTION_IGNORE",
    "WTD_CACHE_ONLY_URL_RETRIEVAL",
    "TRUST_E_NOSIGNATURE",
    "TRUST_E_SUBJECT_FORM_UNKNOWN",
    "TRUST_E_PROVIDER_UNKNOWN",
]

logger = logging.getLogger(__name__)

PROCESS_VM_OPERATION = constants.PROCESS_VM_OPERATION
PROCESS_VM_READ = constants.PROCESS_VM_READ
PROCESS_VM_WRITE = constants.PROCESS_VM_WRITE
PROCESS_VM_ACCESS_MASK = constants.PROCESS_VM_ACCESS_MASK
PROCESS_DUP_HANDLE = constants.PROCESS_DUP_HANDLE
PROCESS_QUERY_LIMITED_INFORMATION = constants.PROCESS_QUERY_LIMITED_INFORMATION
DUPLICATE_SAME_ACCESS = constants.DUPLICATE_SAME_ACCESS
STATUS_INFO_LENGTH_MISMATCH = constants.STATUS_INFO_LENGTH_MISMATCH
SystemExtendedHandleInformation = constants.SystemExtendedHandleInformation
WTD_UI_NONE = constants.WTD_UI_NONE
WTD_REVOKE_NONE = constants.WTD_REVOKE_NONE
WTD_CHOICE_FILE = constants.WTD_CHOICE_FILE
WTD_STATEACTION_IGNORE = constants.WTD_STATEACTION_IGNORE
WTD_CACHE_ONLY_URL_RETRIEVAL = constants.WTD_CACHE_ONLY_URL_RETRIEVAL
TRUST_E_NOSIGNATURE = constants.TRUST_E_NOSIGNATURE
TRUST_E_SUBJECT_FORM_UNKNOWN = constants.TRUST_E_SUBJECT_FORM_UNKNOWN
TRUST_E_PROVIDER_UNKNOWN = constants.TRUST_E_PROVIDER_UNKNOWN


def _emit_telemetry(event: str, **fields) -> None:
    logger.debug("MemGuard telemetry: %s", json.dumps({"event": event, **fields}, sort_keys=True, default=str))


def _log_decision(event_or_context: DecisionLogEvent | DecisionLogContext, *, decision: str | None = None, reason: str | None = None, lineage: str = "", severity: FindingSeverity | None = None, disposition: FindingDisposition | None = None) -> None:
    event = event_or_context if isinstance(event_or_context, DecisionLogEvent) else DecisionLogEvent(context=event_or_context, decision=decision or "unknown", reason=reason or "", lineage=lineage, severity=severity, disposition=disposition)
    context = event.context
    logger.info(
        "MemGuard decision=%s mode=%s pid=%s name=%r path=%r access_mask=0x%08x has_read=%s has_write_or_op=%s sig_trust=%s winverifytrust_status=0x%08x sha256=%s severity=%s disposition=%s lineage=%s reason=%s",
        event.decision,
        context.mode.name.lower(),
        context.pid,
        context.process_name,
        context.process_path,
        int(context.access_mask),
        context.has_read,
        context.has_write_or_op,
        context.sig.trust.name.lower(),
        int(context.sig.status),
        context.process_hash or "<none>",
        event.severity.name.lower() if event.severity else "<none>",
        event.disposition.name.lower() if event.disposition else "<none>",
        event.lineage or "<none>",
        event.reason,
    )


def is_mem_guard_supported() -> bool:
    return os.name == "nt" and platform.system() == "Windows"


def default_mem_guard_mode() -> str:
    return MemGuardMode.NORMAL.name.lower() if is_mem_guard_supported() else MemGuardMode.OFF.name.lower()


def _normalize_path(path: str) -> str:
    return normalize_path(path)


def _is_windows_system_path(path: str) -> bool:
    return is_windows_system_path(path)


def _is_user_writable_path(path: str) -> bool:
    return is_user_writable_path(path)


def _whitelist_requirements_for_path(process_path: str, whitelist: list[dict | str]) -> tuple[bool, set[str], bool]:
    return whitelist_requirements_for_path(process_path, whitelist)


def file_sha256(path: str) -> str:
    return _file_sha256_impl(path, exists_fn=os.path.exists)


def _build_stat_key(process_path: str) -> tuple[str, int, int] | None:
    return _build_stat_key_impl(process_path, exists_fn=os.path.exists, stat_fn=os.stat, normalize_path_fn=_normalize_path)


def _compute_or_get_hash(*, stat_key: tuple[str, int, int] | None, process_path: str, hash_cache: dict[tuple[str, int, int], str]) -> str:
    return _compute_or_get_hash_impl(stat_key=stat_key, process_path=process_path, hash_cache=hash_cache, file_sha256_fn=file_sha256)


def _signature_status_windows(path: str, *, cache_only: bool = True) -> SigResult:
    return _signature_status_windows_impl(
        path,
        cache_only=cache_only,
        deps=SignatureWindowsDeps(
            ctypes_module=ctypes,
            wintypes_module=wintypes,
            os_module=os,
            is_mem_guard_supported_fn=is_mem_guard_supported,
            is_windows_system_path_fn=_is_windows_system_path,
            SigResult=SigResult,
            SigTrust=SigTrust,
            WTD_UI_NONE=WTD_UI_NONE,
            WTD_REVOKE_NONE=WTD_REVOKE_NONE,
            WTD_CHOICE_FILE=WTD_CHOICE_FILE,
            WTD_STATEACTION_IGNORE=WTD_STATEACTION_IGNORE,
            WTD_CACHE_ONLY_URL_RETRIEVAL=WTD_CACHE_ONLY_URL_RETRIEVAL,
            TRUST_E_NOSIGNATURE=TRUST_E_NOSIGNATURE,
            TRUST_E_SUBJECT_FORM_UNKNOWN=TRUST_E_SUBJECT_FORM_UNKNOWN,
            TRUST_E_PROVIDER_UNKNOWN=TRUST_E_PROVIDER_UNKNOWN,
        ),
    )


def _signature_status_with_fallback(path: str) -> SigResult:
    return _signature_status_with_fallback_impl(path, signature_status_windows_fn=_signature_status_windows, is_windows_system_path_fn=_is_windows_system_path, SigTrust=SigTrust)


def _has_vm_write_or_op(access: int) -> bool:
    return _has_vm_write_or_op_impl(access, PROCESS_VM_WRITE=PROCESS_VM_WRITE, PROCESS_VM_OPERATION=PROCESS_VM_OPERATION)


def _has_vm_read(access: int) -> bool:
    return _has_vm_read_impl(access, PROCESS_VM_READ=PROCESS_VM_READ)


def _is_suspicious_signer(sig: SigResult) -> bool:
    return _is_suspicious_signer_impl(sig, SigTrust=SigTrust)


def _cached_sig_for_path(process_path: str, signature_cache: dict[tuple[str, int, int], SigResult]) -> SigResult:
    return _cached_sig_for_path_impl(process_path, signature_cache, build_stat_key_fn=_build_stat_key, signature_status_with_fallback_fn=_signature_status_with_fallback, SigResult=SigResult, SigTrust=SigTrust)


def _assess_parent_lineage(owner_pid: int, signature_cache: dict[tuple[str, int, int], SigResult], max_depth: int = 12) -> tuple[bool, str]:
    return _assess_parent_lineage_impl(owner_pid, signature_cache, psutil_module=psutil, cached_sig_for_path_fn=_cached_sig_for_path, is_windows_system_path_fn=_is_windows_system_path, is_suspicious_signer_fn=_is_suspicious_signer, is_user_writable_path_fn=_is_user_writable_path, SigTrust=SigTrust, max_depth=max_depth)


def _get_process_object_type_index() -> int | None:
    return _get_process_object_type_index_impl(deps=HandleScanDeps(is_mem_guard_supported_fn=is_mem_guard_supported, constants=constants))


def _enumerate_handles_to_pid_windows(target_pid: int, stop_event=None, start_index: int = 0, max_entries: int = 0, owner_pid_filter=None, pid_handle_cache=None, stats=None):
    return _enumerate_handles_to_pid_windows_impl(
        target_pid,
        deps=HandleScanDeps(is_mem_guard_supported_fn=is_mem_guard_supported, constants=constants),
        stop_event=stop_event,
        start_index=start_index,
        max_entries=max_entries,
        owner_pid_filter=owner_pid_filter,
        pid_handle_cache=pid_handle_cache,
        stats=stats,
    )


def _enumerate_reader_pids_windows(target_pid: int, stop_event=None, start_index: int = 0, max_entries: int = 0, owner_pid_filter=None, pid_handle_cache=None, stats=None):
    return _enumerate_reader_pids_windows_impl(target_pid, enumerate_handles_to_pid_windows_fn=_enumerate_handles_to_pid_windows, stop_event=stop_event, start_index=start_index, max_entries=max_entries, owner_pid_filter=owner_pid_filter, pid_handle_cache=pid_handle_cache, stats=stats)


def estimate_scan_time_ms(samples: int = 25, max_entries: int = 0, cache_cap: int = 128, target_pid: int | None = None, inter_scan_delay_ms: int = 0) -> float | None:
    return _estimate_scan_time_ms_impl(is_mem_guard_supported_fn=is_mem_guard_supported, MemGuardScanStats=MemGuardScanStats, enumerate_reader_pids_windows_fn=_enumerate_reader_pids_windows, PidHandleCache=PidHandleCache, samples=samples, max_entries=max_entries, cache_cap=cache_cap, target_pid=target_pid, inter_scan_delay_ms=inter_scan_delay_ms)


def enrich_pid_finding(owner_pid: int, access: int, mode: MemGuardMode, whitelist: list[dict | str], signature_cache: dict[tuple[str, int, int], SigResult], hash_cache: dict[tuple[str, int, int], str]) -> MemGuardFinding | None:
    return _enrich_pid_finding_impl(
        owner_pid,
        access,
        mode,
        whitelist,
        signature_cache,
        hash_cache,
        deps=EnrichPolicyDeps(
            psutil_module=psutil,
            build_stat_key_fn=_build_stat_key,
            signature_status_with_fallback_fn=_signature_status_with_fallback,
            whitelist_requirements_for_path_fn=_whitelist_requirements_for_path,
            compute_or_get_hash_fn=_compute_or_get_hash,
            is_windows_system_path_fn=_is_windows_system_path,
            is_user_writable_path_fn=_is_user_writable_path,
            assess_parent_lineage_fn=_assess_parent_lineage,
            has_vm_read_fn=_has_vm_read,
            has_vm_write_or_op_fn=_has_vm_write_or_op,
            is_suspicious_signer_fn=_is_suspicious_signer,
            emit_telemetry_fn=_emit_telemetry,
            log_decision_fn=_log_decision,
            MemGuardMode=MemGuardMode,
            SigResult=SigResult,
            SigTrust=SigTrust,
            MemGuardFinding=MemGuardFinding,
            FindingSeverity=FindingSeverity,
            FindingDisposition=FindingDisposition,
            DecisionLogContext=DecisionLogContext,
        ),
    )


def find_suspicious_memory_readers(target_pid: int, mode: MemGuardMode, whitelist: list[dict | str]) -> list[MemGuardFinding]:
    if mode == MemGuardMode.OFF or not is_mem_guard_supported():
        return []
    findings: list[MemGuardFinding] = []
    signature_cache: dict[tuple[str, int, int], SigResult] = {}
    hash_cache: dict[tuple[str, int, int], str] = {}
    owner_map, _, _total_count, _scanned_count = _enumerate_reader_pids_windows(target_pid)
    for owner_pid, access in owner_map.items():
        finding = enrich_pid_finding(owner_pid, access, mode, whitelist, signature_cache, hash_cache)
        if finding:
            findings.append(finding)
    return findings
