from __future__ import annotations

import concurrent.futures
import ctypes
import functools
import json
import logging
import os
import platform
import random
from threading import Event
from time import monotonic, perf_counter
from ctypes import wintypes

import psutil
from PyQt6.QtCore import QObject, pyqtSignal

from . import _constants as constants
from ._deps import EnrichPolicyDeps, HandleScanDeps, SignatureWindowsDeps
from ._handle_scan_windows import (
    PidHandleCache,
    enumerate_handles_to_pid_windows,
    enumerate_reader_pids_windows,
)
from ._hashing import build_stat_key, compute_or_get_hash, file_sha256
from ._lineage import assess_parent_lineage, cached_sig_for_path
from ._paths import is_user_writable_path, is_windows_system_path, normalize_path, whitelist_requirements_for_path
from ._policy import enrich_pid_finding
from ._signature_windows import signature_status_windows, signature_status_with_fallback
from ._types import (
    DecisionLogContext,
    DecisionLogEvent,
    FindingDisposition,
    FindingSeverity,
    MemGuardCheckerConfig,
    MemGuardFinding,
    MemGuardMode,
    MemGuardScanStats,
    MemGuardTuning,
    SigResult,
    SigTrust,
)
from .etw_process_watcher import EtwProcessWatcher, ProcessWatcherStatus

logger = logging.getLogger(__name__)


def _emit_telemetry(event: str, **fields) -> None:
    logger.debug("MemGuard telemetry: %s", json.dumps({"event": event, **fields}, sort_keys=True, default=str))


def _log_decision(
    event_or_context: DecisionLogEvent | DecisionLogContext,
    *,
    decision: str | None = None,
    reason: str | None = None,
    lineage: str = "",
    severity: FindingSeverity | None = None,
    disposition: FindingDisposition | None = None,
) -> None:
    event = (
        event_or_context
        if isinstance(event_or_context, DecisionLogEvent)
        else DecisionLogEvent(
            context=event_or_context,
            decision=decision or "unknown",
            reason=reason or "",
            lineage=lineage,
            severity=severity,
            disposition=disposition,
        )
    )
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


def _signature_status_windows(path: str, *, cache_only: bool = True) -> SigResult:
    return signature_status_windows(
        path,
        cache_only=cache_only,
        deps=SignatureWindowsDeps(
            ctypes_module=ctypes,
            wintypes_module=wintypes,
            os_module=os,
            is_mem_guard_supported_fn=is_mem_guard_supported,
            is_windows_system_path_fn=is_windows_system_path,
            SigResult=SigResult,
            SigTrust=SigTrust,
            WTD_UI_NONE=constants.WTD_UI_NONE,
            WTD_REVOKE_NONE=constants.WTD_REVOKE_NONE,
            WTD_CHOICE_FILE=constants.WTD_CHOICE_FILE,
            WTD_STATEACTION_IGNORE=constants.WTD_STATEACTION_IGNORE,
            WTD_CACHE_ONLY_URL_RETRIEVAL=constants.WTD_CACHE_ONLY_URL_RETRIEVAL,
            TRUST_E_NOSIGNATURE=constants.TRUST_E_NOSIGNATURE,
            TRUST_E_SUBJECT_FORM_UNKNOWN=constants.TRUST_E_SUBJECT_FORM_UNKNOWN,
            TRUST_E_PROVIDER_UNKNOWN=constants.TRUST_E_PROVIDER_UNKNOWN,
        ),
    )


def _signature_status_with_fallback(path: str) -> SigResult:
    return signature_status_with_fallback(
        path,
        signature_status_windows_fn=_signature_status_windows,
        is_windows_system_path_fn=is_windows_system_path,
        SigTrust=SigTrust,
    )


def _cached_sig_for_path(process_path: str, signature_cache: dict[tuple[str, int, int], SigResult]) -> SigResult:
    return cached_sig_for_path(
        process_path,
        signature_cache,
        build_stat_key_fn=lambda p: build_stat_key(p, exists_fn=os.path.exists, stat_fn=os.stat, normalize_path_fn=normalize_path),
        signature_status_with_fallback_fn=_signature_status_with_fallback,
        SigResult=SigResult,
        SigTrust=SigTrust,
    )


def _build_enrich_deps() -> EnrichPolicyDeps:
    return EnrichPolicyDeps(
        psutil_module=psutil,
        build_stat_key_fn=lambda p: build_stat_key(p, exists_fn=os.path.exists, stat_fn=os.stat, normalize_path_fn=normalize_path),
        signature_status_with_fallback_fn=_signature_status_with_fallback,
        whitelist_requirements_for_path_fn=whitelist_requirements_for_path,
        compute_or_get_hash_fn=lambda **kwargs: compute_or_get_hash(
            **kwargs,
            file_sha256_fn=lambda path: file_sha256(path, exists_fn=os.path.exists),
        ),
        is_windows_system_path_fn=is_windows_system_path,
        is_user_writable_path_fn=is_user_writable_path,
        assess_parent_lineage_fn=lambda owner_pid, signature_cache: assess_parent_lineage(
            owner_pid,
            signature_cache,
            psutil_module=psutil,
            cached_sig_for_path_fn=_cached_sig_for_path,
            is_windows_system_path_fn=is_windows_system_path,
            is_suspicious_signer_fn=lambda sig: sig.trust in {SigTrust.UNSIGNED, SigTrust.SIGNED_UNTRUSTED, SigTrust.UNKNOWN},
            is_user_writable_path_fn=is_user_writable_path,
            SigTrust=SigTrust,
            max_depth=12,
        ),
        has_vm_read_fn=lambda access: bool(access & constants.PROCESS_VM_READ),
        has_vm_write_or_op_fn=lambda access: bool(access & (constants.PROCESS_VM_WRITE | constants.PROCESS_VM_OPERATION)),
        is_suspicious_signer_fn=lambda sig: sig.trust in {SigTrust.UNSIGNED, SigTrust.SIGNED_UNTRUSTED, SigTrust.UNKNOWN},
        emit_telemetry_fn=_emit_telemetry,
        log_decision_fn=_log_decision,
        MemGuardMode=MemGuardMode,
        SigResult=SigResult,
        SigTrust=SigTrust,
        MemGuardFinding=MemGuardFinding,
        FindingSeverity=FindingSeverity,
        FindingDisposition=FindingDisposition,
        DecisionLogContext=DecisionLogContext,
    )


class MemGuardChecker(QObject):
    memory_probe_detected = pyqtSignal(object)
    process_watcher_status_changed = pyqtSignal(object)

    def __init__(
        self,
        mode: MemGuardMode,
        whitelist: list[dict | str],
        check_interval_ms: int = 100,
        pid_handle_cache_cap: int = 128,
        alert_cooldown_sec: int = 10,
        enhanced_detection_enabled: bool = False,
        config: MemGuardCheckerConfig | None = None,
    ):
        super().__init__()
        if config is None:
            config = MemGuardCheckerConfig(
                check_interval_ms=check_interval_ms,
                pid_handle_cache_cap=pid_handle_cache_cap,
                alert_cooldown_sec=alert_cooldown_sec,
                enhanced_detection_enabled=enhanced_detection_enabled,
            )

        self.mode = mode
        self.whitelist = whitelist
        self.config = config
        self.tuning: MemGuardTuning = config.tuning
        self.check_interval_ms = max(self.tuning.min_check_interval_ms, int(config.check_interval_ms))
        self.running = True
        self._stop_event = Event()
        self._wake_event = Event()
        self._signature_cache: dict[tuple[str, int, int], SigResult] = {}
        self._hash_cache: dict[tuple[str, int, int], str] = {}
        self._scan_cursor = 0
        self._max_entries_per_scan = 0
        self._scan_deps = HandleScanDeps(is_mem_guard_supported_fn=is_mem_guard_supported, constants=constants)
        self._enumerate_handles_to_pid_windows_fn = functools.partial(
            enumerate_handles_to_pid_windows,
            deps=self._scan_deps,
        )
        self._pid_handle_cache = PidHandleCache(cap=max(32, int(config.pid_handle_cache_cap)))
        self._scan_stats = MemGuardScanStats()
        self._alert_cooldown_sec = max(0, int(config.alert_cooldown_sec))
        self._last_alert_at: dict[tuple[int, FindingSeverity], float] = {}
        self._finding_cache: dict[tuple[int, int], tuple[float, MemGuardFinding | None]] = {}
        self._recent_hint_pids: dict[int, float] = {}
        self._fast_scan_streak = 0
        self._enriched_inflight: set[tuple[int, int]] = set()
        self._enrich_futures: dict[concurrent.futures.Future, tuple[int, int]] = {}
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, int(self.tuning.enrich_workers)),
            thread_name_prefix="memguard-enrich",
        )
        self._enhanced_detection_enabled = bool(config.enhanced_detection_enabled)
        self._enrich_deps = _build_enrich_deps()
        self._process_watcher: EtwProcessWatcher | None = None
        self.process_watcher_status = ProcessWatcherStatus(available=False, permission_denied=False, reason="disabled")

        if self._enhanced_detection_enabled and is_mem_guard_supported():
            try:
                self._process_watcher = EtwProcessWatcher(self._on_process_start_hint)
                status = self._process_watcher.start()
                self.process_watcher_status = status
                self.process_watcher_status_changed.emit(status)
                if not status.available:
                    logger.warning("ETW process watcher unavailable: %s", status.reason)
            except (OSError, RuntimeError, ValueError) as exc:
                self.process_watcher_status = ProcessWatcherStatus(False, False, reason=f"etw_error:{exc}")
                logger.warning("ETW process watcher failed: %s", exc)

    def _on_process_start_hint(self, pid: int, _ppid: int, _ts: float) -> None:
        if pid <= 0:
            return
        self._recent_hint_pids[int(pid)] = monotonic() + self.tuning.hint_ttl_sec
        self._wake_event.set()

    def _next_finding_cache_ttl(self) -> float:
        base = max(0.1, float(self.tuning.finding_cache_ttl_sec))
        jitter = max(0.0, float(self.tuning.finding_cache_jitter_ratio))
        low = max(0.1, base * (1.0 - jitter))
        high = max(low, base * (1.0 + jitter))
        return random.uniform(low, high)

    def _enrich_finding(self, owner_pid: int, access: int) -> MemGuardFinding | None:
        return enrich_pid_finding(
            owner_pid,
            access,
            self.mode,
            self.whitelist,
            self._signature_cache,
            self._hash_cache,
            deps=self._enrich_deps,
        )

    def _get_enriched_finding_cached(self, owner_pid: int, access: int) -> MemGuardFinding | None:
        key = (int(owner_pid), int(access))
        now = monotonic()
        cached = self._finding_cache.get(key)
        if cached and now < cached[0]:
            return cached[1]

        finding = self._enrich_finding(owner_pid, access)
        self._finding_cache[key] = (now + self._next_finding_cache_ttl(), finding)

        if len(self._finding_cache) > self.tuning.finding_cache_max_size:
            expired_keys = [k for k, (expires_at, _v) in self._finding_cache.items() if expires_at <= now]
            for expired_key in expired_keys[: self.tuning.finding_cache_prune_batch]:
                self._finding_cache.pop(expired_key, None)

        return finding

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
        self._wake_event.set()

    def _drain_enrichment_results(self) -> list[MemGuardFinding]:
        findings: list[MemGuardFinding] = []
        done = [f for f in list(self._enrich_futures.keys()) if f.done()]
        for future in done:
            key = self._enrich_futures.pop(future, None)
            if key:
                self._enriched_inflight.discard(key)
            try:
                finding = future.result()
            except Exception:
                logger.debug("MemGuard async enrichment failed", exc_info=True)
                continue
            if key:
                self._finding_cache[key] = (monotonic() + self._next_finding_cache_ttl(), finding)
            if finding:
                findings.append(finding)
        return findings

    def _schedule_enrichment(self, owner_pid: int, access: int, force_refresh: bool) -> None:
        key = (int(owner_pid), int(access))
        if key in self._enriched_inflight:
            return
        if len(self._enriched_inflight) >= self.tuning.max_enrich_inflight:
            return

        if not force_refresh:
            cached = self._finding_cache.get(key)
            if cached and monotonic() < cached[0]:
                return

        future = self._executor.submit(self._enrich_finding, owner_pid, access)
        self._enriched_inflight.add(key)
        self._enrich_futures[future] = key

    def _get_recent_hint_set(self) -> set[int]:
        now = monotonic()
        expired = [pid for pid, exp in self._recent_hint_pids.items() if exp <= now]
        for pid in expired:
            self._recent_hint_pids.pop(pid, None)
        return set(self._recent_hint_pids.keys())

    def close_resources(self):
        if self._process_watcher is not None:
            self._process_watcher.stop()
            self._process_watcher = None

        for future in list(self._enrich_futures.keys()):
            future.cancel()
        self._enrich_futures.clear()
        self._enriched_inflight.clear()
        self._executor.shutdown(wait=False, cancel_futures=True)

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        self._pid_handle_cache.close_all(close_handle)

    def _adjust_scan_budget(self, elapsed_ms: float, total_count: int, scanned_count: int) -> None:
        interval_ms = float(self.check_interval_ms)
        if interval_ms <= 0 or total_count <= 0 or scanned_count <= 0:
            return

        target_sweep_ms = max(self.tuning.min_target_sweep_ms, float(self.tuning.target_full_sweep_ms))
        estimated_full_sweep_ms = elapsed_ms * (float(total_count) / float(max(1, scanned_count)))

        if self._max_entries_per_scan <= 0 and estimated_full_sweep_ms > target_sweep_ms:
            self._fast_scan_streak = 0
            return

        if estimated_full_sweep_ms > (target_sweep_ms * self.tuning.slow_scan_ratio):
            self._fast_scan_streak = 0
            if self._max_entries_per_scan <= 0:
                proportional = int((total_count * interval_ms) / max(1.0, target_sweep_ms))
                self._max_entries_per_scan = max(self.tuning.initial_chunk_entries, min(total_count, proportional))
            else:
                growth = min(
                    self.tuning.chunk_growth_max_factor,
                    max(self.tuning.chunk_growth_min_factor, estimated_full_sweep_ms / max(1.0, target_sweep_ms)),
                )
                self._max_entries_per_scan = min(
                    total_count,
                    max(self.tuning.min_chunk_entries, int(self._max_entries_per_scan * growth)),
                )
            return

        if self._max_entries_per_scan > 0:
            if estimated_full_sweep_ms < (target_sweep_ms * self.tuning.fast_scan_ratio):
                self._fast_scan_streak += 1
                self._max_entries_per_scan = max(
                    self.tuning.min_chunk_entries,
                    int(self._max_entries_per_scan * self.tuning.chunk_shrink_factor),
                )
                if (
                    self._fast_scan_streak >= self.tuning.disable_chunk_fast_streak
                    and self._max_entries_per_scan >= int(total_count * self.tuning.disable_chunk_total_ratio)
                ):
                    self._max_entries_per_scan = 0
                    self._fast_scan_streak = 0
            else:
                self._fast_scan_streak = 0

    def run(self):
        interval_sec = self.check_interval_ms / 1000.0
        next_deadline = monotonic()
        while self.running:
            try:
                cycle_started = perf_counter()
                hint_set = self._get_recent_hint_set()
                targeted = bool(hint_set)
                hint_budget = max(
                    self.tuning.hint_min_chunk_entries,
                    min(self.tuning.hint_max_chunk_entries, self._max_entries_per_scan or self.tuning.hint_max_chunk_entries),
                )
                owner_map, self._scan_cursor, total_count, scanned_count = enumerate_reader_pids_windows(
                    os.getpid(),
                    enumerate_handles_to_pid_windows_fn=self._enumerate_handles_to_pid_windows_fn,
                    stop_event=self._stop_event,
                    start_index=self._scan_cursor,
                    max_entries=self._max_entries_per_scan if not targeted else hint_budget,
                    owner_pid_filter=hint_set if targeted else None,
                    pid_handle_cache=self._pid_handle_cache,
                    stats=self._scan_stats,
                )

                for owner_pid, access in owner_map.items():
                    if self._stop_event.is_set():
                        break
                    force_refresh = owner_pid in hint_set
                    if force_refresh:
                        self._schedule_enrichment(owner_pid, access, force_refresh=True)
                        continue

                    finding = self._get_enriched_finding_cached(owner_pid, access)
                    if not finding or finding.disposition != FindingDisposition.ALERT:
                        continue
                    if not self._should_emit_alert(finding.pid, finding.severity):
                        _emit_telemetry(
                            "suppressed_debounce",
                            pid=finding.pid,
                            process_name=finding.process_name,
                            process_path=finding.process_path,
                            access_mask=f"0x{finding.access_mask:08x}",
                            sig_trust=finding.sig_trust.name.lower(),
                            severity=finding.severity.name.lower(),
                            disposition=finding.disposition.name.lower(),
                            suppression_reason="alert_cooldown",
                        )
                        continue
                    self.memory_probe_detected.emit(finding)

                for finding in self._drain_enrichment_results():
                    if finding.disposition != FindingDisposition.ALERT:
                        continue
                    if not self._should_emit_alert(finding.pid, finding.severity):
                        continue
                    self.memory_probe_detected.emit(finding)

                elapsed_ms = (perf_counter() - cycle_started) * 1000.0
                self._adjust_scan_budget(elapsed_ms, total_count=total_count, scanned_count=scanned_count)
            except (OSError, RuntimeError, ValueError, psutil.Error) as exc:
                logger.debug("Memory guard scan failed: %s", exc)

            next_deadline += interval_sec
            remaining = next_deadline - monotonic()
            if remaining > 0:
                self._wake_event.wait(remaining)
                self._wake_event.clear()
                if self._stop_event.is_set():
                    break
            else:
                next_deadline = monotonic()
                if self._stop_event.is_set():
                    break

        self.close_resources()
