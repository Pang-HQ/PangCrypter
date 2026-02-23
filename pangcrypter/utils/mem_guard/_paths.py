from __future__ import annotations

import os


def normalize_path(path: str) -> str:
    if not path:
        return ""
    return os.path.normcase(os.path.abspath(path))


def is_windows_system_path(path: str) -> bool:
    if not path:
        return False
    normalized = normalize_path(path)
    system_root = normalize_path(os.environ.get("SystemRoot", r"C:\Windows"))
    system32 = normalize_path(os.path.join(system_root, "System32"))
    syswow64 = normalize_path(os.path.join(system_root, "SysWOW64"))
    return normalized.startswith(system32 + os.sep) or normalized.startswith(syswow64 + os.sep)


def is_user_writable_path(path: str) -> bool:
    if not path:
        return False
    npath = normalize_path(path)
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
        nbase = normalize_path(base)
        if npath == nbase or npath.startswith(nbase + os.sep):
            return True
    return False


def whitelist_requirements_for_path(
    process_path: str,
    whitelist: list[dict | str],
) -> tuple[bool, set[str], bool]:
    """Return (path_matched, allowed_hashes, has_unpinned_match)."""
    normalized_path = normalize_path(process_path)
    if not normalized_path:
        return False, set(), False

    path_matched = False
    allowed_hashes: set[str] = set()
    has_unpinned_match = False

    for item in whitelist:
        if isinstance(item, str):
            entry_path = normalize_path(item)
            entry_sha = ""
        elif isinstance(item, dict):
            entry_path = normalize_path(str(item.get("path", "")))
            entry_sha = str(item.get("sha256", "")).strip().lower()
        else:
            continue

        if entry_path != normalized_path:
            continue

        path_matched = True
        if entry_sha:
            allowed_hashes.add(entry_sha)
        else:
            has_unpinned_match = True

    return path_matched, allowed_hashes, has_unpinned_match
