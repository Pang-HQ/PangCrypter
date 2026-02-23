from __future__ import annotations

import hashlib
from typing import Callable


def file_sha256(path: str, *, exists_fn: Callable[[str], bool], open_fn=open) -> str:
    if not path or not exists_fn(path):
        return ""
    h = hashlib.sha256()
    with open_fn(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_stat_key(
    process_path: str,
    *,
    exists_fn: Callable[[str], bool],
    stat_fn,
    normalize_path_fn: Callable[[str], str],
) -> tuple[str, int, int] | None:
    if not process_path or not exists_fn(process_path):
        return None
    normalized_path = normalize_path_fn(process_path)
    try:
        st = stat_fn(process_path)
        return (normalized_path, int(st.st_mtime), int(st.st_size))
    except OSError:
        return None


def compute_or_get_hash(
    *,
    stat_key: tuple[str, int, int] | None,
    process_path: str,
    hash_cache: dict[tuple[str, int, int], str],
    file_sha256_fn,
) -> str:
    if not stat_key:
        return ""
    process_hash = hash_cache.get(stat_key, "")
    if process_hash:
        return process_hash
    process_hash = file_sha256_fn(process_path)
    hash_cache[stat_key] = process_hash
    return process_hash
