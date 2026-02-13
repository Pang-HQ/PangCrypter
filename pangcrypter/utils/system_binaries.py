import os
import shutil
from pathlib import Path
from typing import Optional


def trusted_binary_dirs() -> list[Path]:
    if os.name == "nt":
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        dirs = [
            windir / "System32",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        ]
        return [d.resolve() for d in dirs if d.exists()]

    unix_dirs = [
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/local/bin"),
        Path("/usr/local/sbin"),
    ]
    return [d.resolve() for d in unix_dirs if d.exists()]


def is_trusted_binary_path(binary_path: Path) -> bool:
    resolved_binary = binary_path.resolve()
    for trusted_dir in trusted_binary_dirs():
        try:
            resolved_binary.relative_to(trusted_dir)
            return True
        except ValueError:
            continue
    return False


def resolve_trusted_binary(binary_name: str, explicit_candidates: Optional[list[str]] = None) -> str:
    candidates: list[Path] = []

    discovered = shutil.which(binary_name)
    if discovered:
        candidates.append(Path(discovered))

    if explicit_candidates:
        candidates.extend(Path(p) for p in explicit_candidates)

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue

        if not resolved.exists() or not resolved.is_file():
            continue
        if not os.access(resolved, os.X_OK):
            continue
        if not is_trusted_binary_path(resolved):
            continue
        return str(resolved)

    raise RuntimeError(f"Trusted executable not found for '{binary_name}'")
