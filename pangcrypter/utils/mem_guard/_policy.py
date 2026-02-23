from __future__ import annotations

from ._deps import EnrichPolicyDeps


def has_vm_write_or_op(access: int, *, PROCESS_VM_WRITE: int, PROCESS_VM_OPERATION: int) -> bool:
    return bool(access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION))


def has_vm_read(access: int, *, PROCESS_VM_READ: int) -> bool:
    return bool(access & PROCESS_VM_READ)


def is_suspicious_signer(sig, *, SigTrust) -> bool:
    return sig.trust in {SigTrust.UNSIGNED, SigTrust.SIGNED_UNTRUSTED, SigTrust.UNKNOWN}


def enrich_pid_finding(
    owner_pid: int,
    access: int,
    mode,
    whitelist,
    signature_cache,
    hash_cache,
    *,
    deps: EnrichPolicyDeps,
):
    psutil_module = deps.psutil_module
    MemGuardMode = deps.MemGuardMode
    SigResult = deps.SigResult
    SigTrust = deps.SigTrust
    MemGuardFinding = deps.MemGuardFinding
    FindingSeverity = deps.FindingSeverity
    FindingDisposition = deps.FindingDisposition
    DecisionLogContext = deps.DecisionLogContext

    try:
        proc = psutil_module.Process(owner_pid)
        process_name = proc.name() or f"pid-{owner_pid}"
        process_path = proc.exe() or ""
    except (psutil_module.Error, OSError):
        process_name = f"pid-{owner_pid}"
        process_path = ""

    access_int = int(access)
    has_read = deps.has_vm_read_fn(access_int)
    has_write_or_op = deps.has_vm_write_or_op_fn(access_int)

    process_hash = ""
    sig = SigResult(SigTrust.UNKNOWN, 0)
    stat_key = deps.build_stat_key_fn(process_path)

    if stat_key:
        sig = signature_cache.get(stat_key, SigResult(SigTrust.UNKNOWN, 0))
        if stat_key not in signature_cache:
            sig = deps.signature_status_with_fallback_fn(process_path)
            signature_cache[stat_key] = sig

    path_matched, allowed_hashes, has_unpinned_whitelist = deps.whitelist_requirements_for_path_fn(process_path, whitelist)
    if has_unpinned_whitelist:
        deps.emit_telemetry_fn(
            "ignored_unpinned_whitelist",
            pid=owner_pid,
            process_name=process_name,
            process_path=process_path,
            access_mask=f"0x{access_int:08x}",
            sig_trust=sig.trust.name.lower(),
        )

    if path_matched and allowed_hashes:
        process_hash = deps.compute_or_get_hash_fn(stat_key=stat_key, process_path=process_path, hash_cache=hash_cache)
        if process_hash and process_hash.lower() in allowed_hashes:
            deps.log_decision_fn(
                DecisionLogContext(
                    mode=mode,
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=access_int,
                    has_read=has_read,
                    has_write_or_op=has_write_or_op,
                    sig=sig,
                    process_hash=process_hash,
                ),
                decision="whitelisted",
                reason="Path/hash matches configured mem-guard whitelist",
            )
            deps.emit_telemetry_fn(
                "suppressed_whitelist",
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=f"0x{access_int:08x}",
                sig_trust=sig.trust.name.lower(),
            )
            return None

    if stat_key and not process_hash:
        if mode != MemGuardMode.NORMAL or has_write_or_op or (deps.is_suspicious_signer_fn(sig) and has_read):
            process_hash = deps.compute_or_get_hash_fn(stat_key=stat_key, process_path=process_path, hash_cache=hash_cache)

    if mode == MemGuardMode.NORMAL:
        if has_write_or_op:
            is_system_path = bool(process_path) and deps.is_windows_system_path_fn(process_path)
            is_user_writable = bool(process_path) and deps.is_user_writable_path_fn(process_path)
            system_loc = is_system_path and not is_user_writable

            trusted_system_signed = system_loc and sig.trust == SigTrust.SIGNED_TRUSTED
            benign_system_inconclusive = system_loc and sig.trust in {SigTrust.UNKNOWN, SigTrust.SIGNED_UNTRUSTED}
            has_suspicious_parent, lineage_summary = deps.assess_parent_lineage_fn(owner_pid, signature_cache)

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

            deps.log_decision_fn(
                DecisionLogContext(
                    mode=mode,
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=access_int,
                    has_read=has_read,
                    has_write_or_op=has_write_or_op,
                    sig=sig,
                    process_hash=process_hash,
                ),
                decision="log_only" if disposition == FindingDisposition.LOG_ONLY else "detected",
                reason=reason,
                lineage=lineage_summary,
                severity=severity,
                disposition=disposition,
            )
            deps.emit_telemetry_fn(
                "detection",
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=f"0x{access_int:08x}",
                sig_trust=sig.trust.name.lower(),
                severity=severity.name.lower(),
                disposition=disposition.name.lower(),
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

        if has_read:
            if deps.is_suspicious_signer_fn(sig):
                reason = f"Handle with VM read access 0x{access:08x}"
                deps.emit_telemetry_fn(
                    "detection",
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=f"0x{access_int:08x}",
                    sig_trust=sig.trust.name.lower(),
                    severity=FindingSeverity.MEDIUM.name.lower(),
                    disposition=FindingDisposition.ALERT.name.lower(),
                    detection_reason=reason,
                )
                deps.log_decision_fn(
                    DecisionLogContext(
                        mode=mode,
                        pid=owner_pid,
                        process_name=process_name,
                        process_path=process_path,
                        access_mask=access_int,
                        has_read=has_read,
                        has_write_or_op=has_write_or_op,
                        sig=sig,
                        process_hash=process_hash,
                    ),
                    decision="detected",
                    reason=reason,
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

            if process_path and deps.is_windows_system_path_fn(process_path) and sig.trust == SigTrust.SIGNED_TRUSTED:
                has_suspicious_parent, lineage_summary = deps.assess_parent_lineage_fn(owner_pid, signature_cache)
                reason = f"Handle with VM read access 0x{access:08x}"
                if has_suspicious_parent:
                    reason += " (suspicious parent lineage)"
                    sev = FindingSeverity.MEDIUM
                    disp = FindingDisposition.ALERT
                else:
                    sev = FindingSeverity.LOW
                    disp = FindingDisposition.LOG_ONLY

                deps.emit_telemetry_fn(
                    "detection" if disp == FindingDisposition.ALERT else "suppressed_normal_low",
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=f"0x{access_int:08x}",
                    sig_trust=sig.trust.name.lower(),
                    severity=sev.name.lower(),
                    disposition=disp.name.lower(),
                    detection_reason=reason if disp == FindingDisposition.ALERT else None,
                )
                deps.log_decision_fn(
                    DecisionLogContext(
                        mode=mode,
                        pid=owner_pid,
                        process_name=process_name,
                        process_path=process_path,
                        access_mask=access_int,
                        has_read=has_read,
                        has_write_or_op=has_write_or_op,
                        sig=sig,
                        process_hash=process_hash,
                    ),
                    decision="detected" if disp == FindingDisposition.ALERT else "log_only",
                    reason=reason,
                    lineage=lineage_summary,
                    severity=sev,
                    disposition=disp,
                )
                return MemGuardFinding(
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    sha256=process_hash,
                    sig_trust=sig.trust,
                    winverifytrust_status=sig.status,
                    access_mask=access_int,
                    severity=sev,
                    disposition=disp,
                    reason=reason,
                )

            reason = f"Handle with VM read access (trusted non-system) 0x{access:08x}"
            deps.emit_telemetry_fn(
                "detection",
                pid=owner_pid,
                process_name=process_name,
                process_path=process_path,
                access_mask=f"0x{access_int:08x}",
                sig_trust=sig.trust.name.lower(),
                severity=FindingSeverity.MEDIUM.name.lower(),
                disposition=FindingDisposition.ALERT.name.lower(),
                detection_reason=reason,
            )
            deps.log_decision_fn(
                DecisionLogContext(
                    mode=mode,
                    pid=owner_pid,
                    process_name=process_name,
                    process_path=process_path,
                    access_mask=access_int,
                    has_read=has_read,
                    has_write_or_op=has_write_or_op,
                    sig=sig,
                    process_hash=process_hash,
                ),
                decision="detected",
                reason=reason,
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

    reason = f"Handle with VM access 0x{access:08x}"
    severity = FindingSeverity.HIGH if has_write_or_op else FindingSeverity.MEDIUM
    disposition = FindingDisposition.ALERT
    deps.emit_telemetry_fn(
        "detection",
        pid=owner_pid,
        process_name=process_name,
        process_path=process_path,
        access_mask=f"0x{access_int:08x}",
        sig_trust=sig.trust.name.lower(),
        severity=severity.name.lower(),
        disposition=disposition.name.lower(),
        detection_reason=reason,
    )
    deps.log_decision_fn(
        DecisionLogContext(
            mode=mode,
            pid=owner_pid,
            process_name=process_name,
            process_path=process_path,
            access_mask=access_int,
            has_read=has_read,
            has_write_or_op=has_write_or_op,
            sig=sig,
            process_hash=process_hash,
        ),
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
