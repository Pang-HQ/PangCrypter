"""
Build script for PangCrypter.
Creates a standalone executable using PyInstaller.
"""

import os
import shutil
import PyInstaller.__main__
from pathlib import Path


def resolve_minisign_for_bundle() -> str:
    """Resolve minisign binary path to include in release ZIP when available."""
    repo_root = Path(__file__).resolve().parents[1]
    env_path = os.getenv("PANGCRYPTER_MINISIGN_PATH", "").strip()
    candidates = [env_path] if env_path else []

    # 1) Prefer a minisign binary committed/copied into the repository root.
    if os.name == "nt":
        candidates.insert(0, str(repo_root / "minisign.exe"))
    else:
        candidates.insert(0, str(repo_root / "minisign"))

    discovered = shutil.which("minisign")
    if discovered:
        candidates.append(discovered)

    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\minisign\minisign.exe",
                r"C:\Program Files (x86)\minisign\minisign.exe",
            ]
        )

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate

    return ""

# Clean old build/dist
for folder in ("build", "dist"):
    if os.path.exists(folder):
        shutil.rmtree(folder)

# Get the project root directory (parent of scripts/)
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Main script entry point - use run.py which handles imports properly
entry_file = os.path.join(project_root, "run.py")
helper_entry_file = os.path.join(project_root, "pangcrypter", "tools", "apply_update_main.py")

pyinstaller_args = [
    entry_file,
    "--name", "PangCrypter",
    "--onedir",
    "--windowed",
    "--noconfirm",
    "--icon", os.path.join(project_root, "ui", "logo.ico"),
    "--add-data", f"{os.path.join(project_root, 'ui')};ui",
    "--add-data", f"{os.path.join(project_root, 'version.txt')};.",
    "--version-file", os.path.join(project_root, "version.txt"),
    "--hidden-import", "requests",
    "--hidden-import", "packaging",
    "--hidden-import", "packaging.version",
    "--hidden-import", "pangcrypter",
    "--hidden-import", "pangcrypter.core",
    "--hidden-import", "pangcrypter.ui",
    "--hidden-import", "pangcrypter.ui.update_dialog",
    "--hidden-import", "pangcrypter.utils",
]

preferences_path = os.path.join(project_root, "preferences.json")
if os.path.exists(preferences_path):
    pyinstaller_args.extend(["--add-data", f"{preferences_path};."])
else:
    print("preferences.json not found at project root; skipping optional add-data entry")

# PyInstaller build
PyInstaller.__main__.run(pyinstaller_args)

# Build external update helper used for Windows-safe atomic apply flow.
helper_pyinstaller_args = [
    helper_entry_file,
    "--name", "PangApplyUpdate",
    "--onefile",
    "--console",
    "--noconfirm",
]

PyInstaller.__main__.run(helper_pyinstaller_args)

# Create ZIP distribution with proper folder structure (onedir bundle)
import zipfile

dist_dir = "dist"
zip_name = "PangCrypter.zip"
pangcrypter_folder = "PangCrypter"

if os.path.exists(dist_dir):
    bundle_dir = os.path.join(dist_dir, pangcrypter_folder)

    helper_name = "PangApplyUpdate.exe" if os.name == "nt" else "PangApplyUpdate"
    helper_dist_path = os.path.join(dist_dir, helper_name)
    if os.path.isfile(helper_dist_path) and os.path.isdir(bundle_dir):
        shutil.copy2(helper_dist_path, os.path.join(bundle_dir, helper_name))
    else:
        print(f"⚠️ update helper binary not found at {helper_dist_path}; auto-update handoff may fail.")

    # Add bundled minisign binary for updater signature verification
    minisign_src = resolve_minisign_for_bundle()
    if minisign_src and os.path.isdir(bundle_dir):
        minisign_name = "minisign.exe" if os.name == "nt" else "minisign"
        shutil.copy2(minisign_src, os.path.join(bundle_dir, minisign_name))
    elif not minisign_src:
        print("⚠️ minisign binary not found; PangCrypter.zip will not include minisign.")

    with zipfile.ZipFile(os.path.join(dist_dir, zip_name), 'w', zipfile.ZIP_DEFLATED) as zipf:
        if not os.path.isdir(bundle_dir):
            raise FileNotFoundError(f"Expected onedir output not found: {bundle_dir}")

        for root, _dirs, files in os.walk(bundle_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, bundle_dir)
                arcname = os.path.join(pangcrypter_folder, rel_path)
                zipf.write(file_path, arcname)

    print(f"\n✅ ZIP distribution created: {os.path.join(dist_dir, zip_name)}")
    print(f"   Contents: full onedir bundle in {pangcrypter_folder}/")

print("\n✅ Build complete! Check the 'dist' folder for PangCrypter/ and PangCrypter.zip")
