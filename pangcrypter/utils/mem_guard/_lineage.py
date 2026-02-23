from __future__ import annotations

from typing import Any, cast

from ._types import SigResult


def cached_sig_for_path(
    process_path: str,
    signature_cache: dict[tuple[str, int, int], SigResult],
    *,
    build_stat_key_fn,
    signature_status_with_fallback_fn,
    SigResult,
    SigTrust,
):
    stat_key = build_stat_key_fn(process_path)
    if not stat_key:
        return SigResult(SigTrust.UNKNOWN, 0)
    if stat_key in signature_cache:
        return signature_cache[stat_key]
    sig = signature_status_with_fallback_fn(process_path)
    signature_cache[stat_key] = sig
    return sig


def assess_parent_lineage(
    owner_pid: int,
    signature_cache: dict[tuple[str, int, int], SigResult],
    *,
    psutil_module,
    cached_sig_for_path_fn,
    is_windows_system_path_fn,
    is_suspicious_signer_fn,
    is_user_writable_path_fn,
    SigTrust,
    max_depth: int = 12,
) -> tuple[bool, str]:
    chain: list[str] = []
    try:
        current = psutil_module.Process(owner_pid)
    except (psutil_module.Error, OSError):
        return False, ""

    depth = 0
    while depth < max_depth:
        try:
            ppid_fn = getattr(current, "ppid", None)
            if not callable(ppid_fn):
                break
            ppid = int(cast(Any, ppid_fn)())
            if ppid <= 0:
                break

            parent = psutil_module.Process(ppid)
            parent_name = parent.name() or f"pid-{ppid}"
            parent_path = parent.exe() or ""
            parent_sig = cached_sig_for_path_fn(parent_path, signature_cache)
            parent_is_system = bool(parent_path) and is_windows_system_path_fn(parent_path)
            sig_suspicious = bool(parent_path) and is_suspicious_signer_fn(parent_sig)
            path_suspicious = bool(parent_path) and is_user_writable_path_fn(parent_path)
            parent_suspicious = sig_suspicious or (path_suspicious and parent_sig.trust != SigTrust.SIGNED_TRUSTED)
            chain.append(f"{parent_name}(pid={ppid},system={parent_is_system},sig={parent_sig.trust.name.lower()})")
            if parent_suspicious:
                return True, " -> ".join(chain)
            current = parent
            depth += 1
        except (psutil_module.Error, OSError, ValueError):
            break
    return False, " -> ".join(chain)
