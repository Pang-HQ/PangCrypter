"""
Build script for PangCrypter.
Creates a standalone executable using PyInstaller.
"""

import os
import shutil
import PyInstaller.__main__

# Clean old build/dist
for folder in ("build", "dist"):
    if os.path.exists(folder):
        shutil.rmtree(folder)

# Get the project root directory (parent of scripts/)
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Main script entry point - use run.py which handles imports properly
entry_file = os.path.join(project_root, "run.py")

# PyInstaller build
PyInstaller.__main__.run([
    entry_file,
    "--name", "PangCrypter",
    "--onefile",
    "--windowed",
    "--noconfirm",
    "--icon", os.path.join(project_root, "ui", "logo.ico"),
    "--add-data", f"{os.path.join(project_root, 'ui')};ui",
    "--add-data", f"{os.path.join(project_root, 'preferences.json')};.",
    "--add-data", f"{os.path.join(project_root, 'version.txt')};.",
    "--version-file", os.path.join(project_root, "version.txt"),
    "--hidden-import", "requests",
    "--hidden-import", "packaging",
    "--hidden-import", "packaging.version",
    "--hidden-import", "pangcrypter",
    "--hidden-import", "pangcrypter.core",
    "--hidden-import", "pangcrypter.ui",
    "--hidden-import", "pangcrypter.utils",
])

# Create ZIP distribution with proper folder structure
import zipfile
import os

dist_dir = "dist"
zip_name = "PangCrypter.zip"
pangcrypter_folder = "PangCrypter"

if os.path.exists(dist_dir):
    with zipfile.ZipFile(os.path.join(dist_dir, zip_name), 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add the executable
        exe_path = os.path.join(dist_dir, "PangCrypter.exe")
        if os.path.exists(exe_path):
            zipf.write(exe_path, os.path.join(pangcrypter_folder, "PangCrypter.exe"))

        # Add the ui folder contents
        ui_src = os.path.join(project_root, "ui")
        if os.path.exists(ui_src):
            for root, dirs, files in os.walk(ui_src):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Add to ui/ subfolder in ZIP
                    arcname = os.path.join(pangcrypter_folder, "ui", os.path.relpath(file_path, ui_src))
                    zipf.write(file_path, arcname)

        # Add version.txt
        version_src = os.path.join(project_root, "version.txt")
        if os.path.exists(version_src):
            zipf.write(version_src, os.path.join(pangcrypter_folder, "version.txt"))

    print(f"\n✅ ZIP distribution created: {os.path.join(dist_dir, zip_name)}")
    print(f"   Contents: {pangcrypter_folder}/PangCrypter.exe, {pangcrypter_folder}/ui/, {pangcrypter_folder}/version.txt")

print("\n✅ Build complete! Check the 'dist' folder for PangCrypter.exe and PangCrypter.zip")
