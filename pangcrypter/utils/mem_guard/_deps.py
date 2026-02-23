from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import TYPE_CHECKING, Callable, Protocol, TypeAlias

if TYPE_CHECKING:
    from ._types import (
        DecisionLogContext,
        DecisionLogEvent,
        FindingDisposition,
        FindingSeverity,
        MemGuardFinding,
        MemGuardMode,
        SigResult,
        SigTrust,
    )

StatKey: TypeAlias = tuple[str, int, int]


class TelemetryFn(Protocol):
    def __call__(self, event: str, **fields: object) -> None: ...


class LogDecisionFn(Protocol):
    def __call__(
        self,
        event_or_context: "DecisionLogEvent | DecisionLogContext",
        *,
        decision: str | None = None,
        reason: str | None = None,
        lineage: str = "",
        severity: "FindingSeverity | None" = None,
        disposition: "FindingDisposition | None" = None,
    ) -> None: ...


@dataclass(frozen=True)
class SignatureWindowsDeps:
    ctypes_module: ModuleType
    wintypes_module: ModuleType
    os_module: ModuleType
    is_mem_guard_supported_fn: Callable[[], bool]
    is_windows_system_path_fn: Callable[[str], bool]
    SigResult: type[SigResult]
    SigTrust: type[SigTrust]
    WTD_UI_NONE: int
    WTD_REVOKE_NONE: int
    WTD_CHOICE_FILE: int
    WTD_STATEACTION_IGNORE: int
    WTD_CACHE_ONLY_URL_RETRIEVAL: int
    TRUST_E_NOSIGNATURE: int
    TRUST_E_SUBJECT_FORM_UNKNOWN: int
    TRUST_E_PROVIDER_UNKNOWN: int


@dataclass(frozen=True)
class EnrichPolicyDeps:
    psutil_module: ModuleType
    build_stat_key_fn: Callable[[str], StatKey | None]
    signature_status_with_fallback_fn: Callable[[str], SigResult]
    whitelist_requirements_for_path_fn: Callable[[str, list[dict | str]], tuple[bool, set[str], bool]]
    compute_or_get_hash_fn: Callable[..., str]
    is_windows_system_path_fn: Callable[[str], bool]
    is_user_writable_path_fn: Callable[[str], bool]
    assess_parent_lineage_fn: Callable[[int, dict[StatKey, SigResult]], tuple[bool, str]]
    has_vm_read_fn: Callable[[int], bool]
    has_vm_write_or_op_fn: Callable[[int], bool]
    is_suspicious_signer_fn: Callable[[SigResult], bool]
    emit_telemetry_fn: TelemetryFn
    log_decision_fn: LogDecisionFn
    MemGuardMode: type[MemGuardMode]
    SigResult: type[SigResult]
    SigTrust: type[SigTrust]
    MemGuardFinding: type[MemGuardFinding]
    FindingSeverity: type[FindingSeverity]
    FindingDisposition: type[FindingDisposition]
    DecisionLogContext: type[DecisionLogContext]


@dataclass(frozen=True)
class HandleScanDeps:
    is_mem_guard_supported_fn: Callable[[], bool]
    constants: ModuleType
