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

print("\n✅ Build complete! Check the 'dist' folder for PangCrypter.exe")
