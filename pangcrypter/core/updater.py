"""
Auto-updater module for PangCrypter.
Checks for new versions on GitHub and downloads/installs updates.
"""

import os
import sys
import json
import logging
import requests
import tempfile
import subprocess
import time
import zipfile
import shutil
from typing import Optional, Tuple, Dict, Any
from packaging import version
import hashlib

logger = logging.getLogger(__name__)

class UpdaterError(Exception):
    """Custom exception for updater-related errors."""
    pass

class AutoUpdater:
    """Handles automatic updates for PangCrypter."""

    GITHUB_API_URL = "https://api.github.com/repos/Pang-HQ/PangCrypter/releases/latest"
    GITHUB_REPO_URL = "https://github.com/Pang-HQ/PangCrypter"

    def __init__(self):
        self.current_version = self._get_current_version()
        self.temp_dir = tempfile.gettempdir()

    def _get_current_version(self) -> str:
        """Get the current application version from version.txt."""
        try:
            # Go up three levels: core/ -> pangcrypter/ -> root/
            version_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "version.txt")
            with open(version_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse version from the VSVersionInfo format
            for line in content.split('\n'):
                if 'filevers=' in line:
                    # Extract version tuple like (1, 0, 0, 0)
                    version_tuple = line.split('filevers=(')[1].split(')')[0]
                    major, minor, patch, build = map(int, version_tuple.split(', '))
                    return f"{major}.{minor}.{patch}.{build}"

        except Exception as e:
            logger.error(f"Failed to read current version: {e}")
            return "0.0.0.0"

    def check_for_updates(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check for updates on GitHub.

        Returns:
            Tuple of (update_available, latest_version, download_url)
        """
        try:
            logger.info("Checking for updates...")

            # Make request to GitHub API
            headers = {
                'User-Agent': 'PangCrypter-Updater/1.0',
                'Accept': 'application/vnd.github.v3+json'
            }

            response = requests.get(self.GITHUB_API_URL, headers=headers, timeout=10)

            if response.status_code == 404:
                # No releases found, try to get all releases including pre-releases
                logger.info("No latest release found, checking all releases...")
                releases_url = self.GITHUB_API_URL.replace('/latest', '')
                response = requests.get(releases_url, headers=headers, timeout=10)
                response.raise_for_status()

                releases_data = response.json()
                if not releases_data:
                    logger.info("No releases found in repository")
                    return False, None, None

                # Get the most recent release (first in the list)
                release_data = releases_data[0]
            else:
                response.raise_for_status()
                release_data = response.json()

            latest_version = release_data.get('tag_name', '').lstrip('v')

            if not latest_version:
                raise UpdaterError("No version tag found in release")

            logger.info(f"Current version: {self.current_version}, Latest version: {latest_version}")

            # Compare versions
            try:
                update_available = version.parse(latest_version) > version.parse(self.current_version)
            except Exception as e:
                logger.warning(f"Version comparison failed: {e}")
                # Fallback to string comparison
                update_available = latest_version != self.current_version

            # Find the Windows exe asset or ZIP file
            download_url = None
            for asset in release_data.get('assets', []):
                asset_name = asset.get('name', '').lower()
                # Look for exe files or zip files containing pangcrypter
                if (asset_name.endswith('.exe') or asset_name.endswith('.zip')) and ('pangcrypter' in asset_name or 'pang' in asset_name):
                    download_url = asset.get('browser_download_url')
                    break

            if not download_url:
                logger.warning("No suitable exe asset found in release")
                return False, latest_version, None

            return update_available, latest_version, download_url

        except requests.RequestException as e:
            logger.error(f"Network error checking for updates: {e}")
            raise UpdaterError(f"Failed to check for updates: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response from GitHub: {e}")
            raise UpdaterError("Invalid response from update server")
        except Exception as e:
            logger.error(f"Unexpected error checking for updates: {e}")
            raise UpdaterError(f"Update check failed: {e}")

    def download_update(self, download_url: str, progress_callback=None) -> str:
        """
        Download the update file.

        Args:
            download_url: URL to download the update from
            progress_callback: Optional callback for download progress

        Returns:
            Path to the downloaded file
        """
        try:
            logger.info(f"Downloading update from: {download_url}")

            # Create temporary file path
            temp_filename = f"pangcrypter_update_{int(time.time())}.exe"
            temp_path = os.path.join(self.temp_dir, temp_filename)

            # Download with progress
            headers = {'User-Agent': 'PangCrypter-Updater/1.0'}
            response = requests.get(download_url, headers=headers, stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))

            with open(temp_path, 'wb') as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        if progress_callback and total_size > 0:
                            progress = int((downloaded / total_size) * 100)
                            progress_callback(progress)

            logger.info(f"Update downloaded to: {temp_path}")
            return temp_path

        except requests.RequestException as e:
            logger.error(f"Download failed: {e}")
            raise UpdaterError(f"Failed to download update: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during download: {e}")
            raise UpdaterError(f"Download failed: {e}")

    def verify_download(self, file_path: str, expected_size: Optional[int] = None) -> bool:
        """
        Verify the downloaded file.

        Args:
            file_path: Path to the downloaded file
            expected_size: Expected file size if known

        Returns:
            True if verification passes
        """
        try:
            if not os.path.exists(file_path):
                return False

            # Check file size if expected size is provided
            if expected_size:
                actual_size = os.path.getsize(file_path)
                if actual_size != expected_size:
                    logger.warning(f"File size mismatch: expected {expected_size}, got {actual_size}")
                    return False

            # Check file type based on extension
            if file_path.lower().endswith('.zip'):
                # Verify ZIP file integrity
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        # Test the ZIP file
                        bad_file = zip_ref.testzip()
                        if bad_file:
                            logger.warning(f"ZIP file corrupted, bad file: {bad_file}")
                            return False
                        logger.info("ZIP file integrity verified")
                except zipfile.BadZipFile:
                    logger.warning("Downloaded file is not a valid ZIP file")
                    return False
            elif file_path.lower().endswith('.exe'):
                # Basic executable check (Windows PE header)
                with open(file_path, 'rb') as f:
                    header = f.read(2)
                    if header != b'MZ':  # Windows executable magic number
                        logger.warning("Downloaded file is not a valid Windows executable")
                        return False
            else:
                logger.warning(f"Unsupported file type: {file_path}")
                return False

            return True

        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False

    def install_update(self, update_file_path: str) -> bool:
        """
        Install the update by replacing the current installation.

        Args:
            update_file_path: Path to the update file (EXE or ZIP)

        Returns:
            True if installation successful
        """
        try:
            # Get current installation directory
            if getattr(sys, 'frozen', False):
                # Running as PyInstaller bundle
                current_dir = os.path.dirname(sys.executable)
            else:
                # Running in development
                current_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

            logger.info(f"Current installation directory: {current_dir}")
            logger.info(f"Update file: {update_file_path}")

            # Create backup directory
            backup_dir = os.path.join(current_dir, "backup")
            try:
                if os.path.exists(backup_dir):
                    shutil.rmtree(backup_dir)
                shutil.copytree(current_dir, backup_dir, ignore=shutil.ignore_patterns("backup"))
                logger.info(f"Created backup: {backup_dir}")
            except Exception as e:
                logger.warning(f"Failed to create backup: {e}")

            # Check if update file is a ZIP
            if update_file_path.lower().endswith('.zip'):
                # Extract ZIP file
                extract_dir = os.path.join(self.temp_dir, f"pangcrypter_extract_{int(time.time())}")
                os.makedirs(extract_dir, exist_ok=True)

                try:
                    with zipfile.ZipFile(update_file_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    logger.info(f"Extracted ZIP to: {extract_dir}")

                    # Find the PangCrypter directory in the extracted files
                    pangcrypter_dir = None
                    for item in os.listdir(extract_dir):
                        item_path = os.path.join(extract_dir, item)
                        if os.path.isdir(item_path) and 'pangcrypter' in item.lower():
                            pangcrypter_dir = item_path
                            break

                    if not pangcrypter_dir:
                        raise UpdaterError("Could not find PangCrypter directory in ZIP file")

                    logger.info(f"Found PangCrypter directory: {pangcrypter_dir}")

                    # Copy files from extracted directory to current directory
                    for item in os.listdir(pangcrypter_dir):
                        src_path = os.path.join(pangcrypter_dir, item)
                        dst_path = os.path.join(current_dir, item)

                        if os.path.isdir(src_path):
                            # Copy directory
                            if os.path.exists(dst_path):
                                shutil.rmtree(dst_path)
                            shutil.copytree(src_path, dst_path)
                        else:
                            # Copy file
                            shutil.copy2(src_path, dst_path)

                    logger.info("Update files copied successfully")

                except Exception as e:
                    logger.error(f"Failed to extract and copy ZIP contents: {e}")
                    raise UpdaterError(f"Failed to install update from ZIP: {e}")
                finally:
                    # Clean up extraction directory
                    try:
                        shutil.rmtree(extract_dir)
                    except:
                        pass

            else:
                # Handle EXE file replacement (legacy support)
                current_exe = os.path.join(current_dir, "PangCrypter.exe")
                if not os.path.exists(current_exe):
                    raise UpdaterError("Current executable not found")

                try:
                    # Create backup of current exe
                    backup_exe = current_exe + ".backup"
                    if os.path.exists(backup_exe):
                        os.remove(backup_exe)
                    os.rename(current_exe, backup_exe)

                    # Replace with new exe
                    os.rename(update_file_path, current_exe)
                    logger.info("EXE update installed successfully")

                except Exception as e:
                    # Restore backup if installation failed
                    try:
                        if os.path.exists(backup_exe):
                            os.rename(backup_exe, current_exe)
                    except:
                        pass
                    raise UpdaterError(f"Failed to install EXE update: {e}")

            # Clean up backup after successful update
            if os.path.exists(backup_dir):
                try:
                    shutil.rmtree(backup_dir)
                except:
                    pass  # Ignore cleanup errors

            logger.info("Update installed successfully")
            return True

        except Exception as e:
            logger.error(f"Installation failed: {e}")
            raise UpdaterError(f"Update installation failed: {e}")

    def restart_application(self) -> None:
        """Restart the application after update."""
        try:
            current_exe = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])

            if not getattr(sys, 'frozen', False):
                # In development, find the built executable
                dist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dist")
                exe_path = os.path.join(dist_dir, "PangCrypter.exe")
                if os.path.exists(exe_path):
                    current_exe = exe_path

            logger.info(f"Restarting application: {current_exe}")

            # Start new instance
            subprocess.Popen([current_exe])

            # Exit current instance
            sys.exit(0)

        except Exception as e:
            logger.error(f"Failed to restart application: {e}")
            raise UpdaterError(f"Failed to restart: {e}")

    def perform_update(self, progress_callback=None) -> bool:
        """
        Perform a complete update check, download, and installation.

        Args:
            progress_callback: Optional callback for progress updates

        Returns:
            True if update was successful
        """
        try:
            # Check for updates
            if progress_callback:
                progress_callback(10, "Checking for updates...")

            update_available, latest_version, download_url = self.check_for_updates()

            if not update_available:
                logger.info("No update available")
                return False

            if not download_url:
                raise UpdaterError("No download URL available for update")

            # Download update
            if progress_callback:
                progress_callback(30, f"Downloading version {latest_version}...")

            update_file = self.download_update(download_url, lambda p: progress_callback(30 + int(p * 0.4)))

            # Verify download
            if progress_callback:
                progress_callback(70, "Verifying download...")

            if not self.verify_download(update_file):
                os.remove(update_file)
                raise UpdaterError("Downloaded file verification failed")

            # Install update
            if progress_callback:
                progress_callback(90, "Installing update...")

            success = self.install_update(update_file)

            if success and progress_callback:
                progress_callback(100, "Update completed successfully!")

            return success

        except UpdaterError:
            raise
        except Exception as e:
            logger.error(f"Update failed: {e}")
            raise UpdaterError(f"Update failed: {e}")
        finally:
            # Clean up any temporary files
            try:
                # Remove any leftover temp files (this is a best-effort cleanup)
                for filename in os.listdir(self.temp_dir):
                    if filename.startswith("pangcrypter_update_") and (filename.endswith(".exe") or filename.endswith(".zip")):
                        filepath = os.path.join(self.temp_dir, filename)
                        try:
                            os.remove(filepath)
                        except:
                            pass
            except:
                pass
