from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class MemGuardMode(Enum):
    OFF = auto()
    NORMAL = auto()
    ULTRA_AGGRESSIVE = auto()


class SigTrust(Enum):
    UNSIGNED = auto()
    SIGNED_TRUSTED = auto()
    SIGNED_UNTRUSTED = auto()
    UNKNOWN = auto()


class FindingSeverity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


class FindingDisposition(Enum):
    ALERT = auto()
    LOG_ONLY = auto()


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


@dataclass(frozen=True)
class DecisionLogContext:
    mode: MemGuardMode
    pid: int
    process_name: str
    process_path: str
    access_mask: int
    has_read: bool
    has_write_or_op: bool
    sig: SigResult
    process_hash: str


@dataclass(frozen=True)
class DecisionLogEvent:
    context: DecisionLogContext
    decision: str
    reason: str
    lineage: str = ""
    severity: FindingSeverity | None = None
    disposition: FindingDisposition | None = None


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


@dataclass(frozen=True)
class MemGuardTuning:
    min_check_interval_ms: int = 50
    finding_cache_ttl_sec: float = 2.0
    finding_cache_jitter_ratio: float = 0.25
    finding_cache_max_size: int = 4096
    finding_cache_prune_batch: int = 1024
    hint_ttl_sec: float = 5.0
    max_enrich_inflight: int = 100
    enrich_workers: int = 2
    target_full_sweep_ms: float = 120.0
    min_chunk_entries: int = 2000
    hint_min_chunk_entries: int = 500
    hint_max_chunk_entries: int = 5000
    initial_chunk_entries: int = 8000
    chunk_growth_max_factor: float = 2.0
    chunk_growth_min_factor: float = 1.10
    fast_scan_ratio: float = 0.70
    slow_scan_ratio: float = 1.10
    chunk_shrink_factor: float = 0.90
    disable_chunk_fast_streak: int = 10
    disable_chunk_total_ratio: float = 0.90
    min_target_sweep_ms: float = 80.0


@dataclass(frozen=True)
class MemGuardCheckerConfig:
    check_interval_ms: int = 100
    pid_handle_cache_cap: int = 128
    alert_cooldown_sec: int = 10
    enhanced_detection_enabled: bool = False
    tuning: MemGuardTuning = MemGuardTuning()
