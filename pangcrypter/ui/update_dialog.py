"""
Update dialog for PangCrypter auto-updater.
"""

import sys
import os
import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QWidget, QInputDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer

from ..core.updater import AutoUpdater, UpdaterError
from ..utils.styles import TEXT_COLOR, DARKER_BG, PURPLE, DARK_BG
from .messagebox import PangMessageBox
from ..utils.admin import run_as_admin

logger = logging.getLogger(__name__)


class RollbackWorker(QThread):
    progress_updated = pyqtSignal(int, str)
    rollback_completed = pyqtSignal(bool, str)

    def __init__(self, updater: AutoUpdater, version):
        super().__init__()
        self.updater = updater
        self.version = version

    def run(self):
        try:
            zip_url, checksum, minisig_url = self.updater.get_zip_url_for_version(self.version)
            if not zip_url:
                self.rollback_completed.emit(False, f"No ZIP found for version {self.version}")
                return

            # download zip
            def progress_cb(p, msg):
                self.progress_updated.emit(p, msg)

            zip_path = self.updater.download_zip(zip_url, progress_cb)
            sig_path = None
            if minisig_url:
                sig_path = self.updater.download_file(minisig_url, ".minisig")

            # verify zip
            if checksum and not self.updater.verify_sha256(zip_path, checksum):
                raise UpdaterError("SHA-256 checksum verification failed")
            if self.updater.REQUIRE_MINISIGN:
                if not sig_path:
                    raise UpdaterError("Missing minisign signature for rollback package")
                if not self.updater.verify_minisign(zip_path, sig_path):
                    raise UpdaterError("minisign verification failed")
            if not self.updater.verify_zip(zip_path):
                raise UpdaterError("ZIP verification failed")

            # install zip
            self.updater.install_zip_update(zip_path)
            self.rollback_completed.emit(True, f"Rollback to {self.version} successful!")
        except (UpdaterError, OSError, ValueError, RuntimeError) as e:
            self.rollback_completed.emit(False, str(e))


class UpdateWorker(QThread):
    progress_updated = pyqtSignal(int, str)
    update_completed = pyqtSignal(bool, str)

    def __init__(self, updater: AutoUpdater):
        super().__init__()
        self.updater = updater

    def run(self):
        try:
            def cb(p, msg):
                self.progress_updated.emit(p, msg)

            # --------------------------
            # Prompt admin if needed
            # --------------------------
            install_dir = os.path.dirname(sys.executable)
            if os.name == "nt" and not os.access(install_dir, os.W_OK):
                run_as_admin()  # exits current process

            # Perform update
            success = self.updater.perform_update(cb)
            if success:
                self.update_completed.emit(True, "Update installed successfully!")
            else:
                self.update_completed.emit(False, "No update available.")
        except (UpdaterError, OSError, ValueError, RuntimeError) as e:
            self.update_completed.emit(False, str(e))

class UpdateDialog(QDialog):
    """Dialog for checking and performing updates."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Check for Updates")
        self.setModal(True)
        self.resize(500, 400)

        self.updater = AutoUpdater()
        self.update_worker = None

        self._setup_ui()
        self._setup_connections()

    def _format_update_error(self, error: Exception) -> str:
        text = str(error).strip() or error.__class__.__name__
        lowered = text.lower()
        if "network" in lowered or "connection" in lowered or "timeout" in lowered:
            return f"Network error while checking updates: {text}"
        if "minisign" in lowered or "signature" in lowered:
            return f"Publisher signature verification error: {text}"
        if "no sha-256 checksum found" in lowered or "no checksum" in lowered:
            return "Update metadata error: no SHA-256 checksum found for the selected release package."
        if "checksum" in lowered or "sha-256" in lowered:
            return f"Checksum verification error: {text}"
        return text

    def _setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Header section with gradient background
        header_widget = QWidget()
        header_widget.setFixedHeight(80)
        header_widget.setStyleSheet(f"""
            QWidget {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {PURPLE}, stop:1 #7c3aed);
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }}
        """)

        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 15, 20, 15)

        # App icon (you can replace with actual icon)
        icon_label = QLabel()
        icon_label.setFixedSize(32, 32)
        icon_label.setStyleSheet("""
            QLabel {
                background-color: rgba(255, 255, 255, 0.2);
                border-radius: 6px;
            }
        """)
        header_layout.addWidget(icon_label)

        # Title and subtitle
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        title_label = QLabel("PangCrypter")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 16px;
                font-weight: bold;
            }
        """)

        subtitle_label = QLabel("Software Update")
        subtitle_label.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.8);
                font-size: 12px;
            }
        """)

        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        header_layout.addLayout(title_layout)

        header_layout.addStretch()

        # Version info in header
        version_label = QLabel(f"v{self.updater.current_version}")
        version_label.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.9);
                font-size: 11px;
                background-color: rgba(255, 255, 255, 0.1);
                padding: 4px 8px;
                border-radius: 4px;
            }
        """)
        header_layout.addWidget(version_label)

        main_layout.addWidget(header_widget)

        # Content area
        content_widget = QWidget()
        content_widget.setStyleSheet(f"""
            QWidget {{
                background-color: {DARK_BG};
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
            }}
        """)

        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(15)
        content_layout.setContentsMargins(20, 20, 20, 20)

        # Status indicator section
        status_container = QWidget()
        status_container.setFixedHeight(60)
        status_container.setStyleSheet(f"""
            QWidget {{
                background-color: {DARKER_BG};
                border-radius: 6px;
            }}
        """)

        status_layout = QHBoxLayout(status_container)
        status_layout.setContentsMargins(15, 10, 15, 10)

        # Status icon
        self.status_icon = QLabel()
        self.status_icon.setFixedSize(24, 24)
        self._set_status_icon("ready")
        status_layout.addWidget(self.status_icon)

        # Status text
        self.status_title = QLabel("Ready to Check")
        self.status_title.setStyleSheet(f"""
            QLabel {{
                color: {TEXT_COLOR};
                font-size: 14px;
                font-weight: bold;
            }}
        """)

        self.status_subtitle = QLabel("Click 'Check for Updates' to start")
        self.status_subtitle.setWordWrap(True)
        self.status_subtitle.setStyleSheet("""
            QLabel {
                color: #888;
                font-size: 11px;
            }
        """)

        status_text_layout = QVBoxLayout()
        status_text_layout.setSpacing(2)
        status_text_layout.addWidget(self.status_title)
        status_text_layout.addWidget(self.status_subtitle)

        status_layout.addLayout(status_text_layout)
        status_layout.addStretch()

        content_layout.addWidget(status_container)

        # Progress section
        progress_container = QWidget()
        progress_layout = QVBoxLayout(progress_container)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.setSpacing(8)

        # Progress bar with modern styling
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {DARKER_BG};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {PURPLE}, stop:1 #7c3aed);
                border-radius: 3px;
            }}
        """)
        progress_layout.addWidget(self.progress_bar)

        # Progress text
        self.progress_text = QLabel("")
        self.progress_text.setVisible(False)
        self.progress_text.setWordWrap(True)
        self.progress_text.setStyleSheet(f"""
            QLabel {{
                color: {TEXT_COLOR};
                font-size: 11px;
                text-align: center;
            }}
        """)
        self.progress_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        progress_layout.addWidget(self.progress_text)

        content_layout.addWidget(progress_container)

        # Action buttons
        buttons_widget = QWidget()
        buttons_layout = QHBoxLayout(buttons_widget)
        buttons_layout.setSpacing(10)

        # Primary action button
        self.primary_button = QPushButton("🔍 Check for Updates")
        self.primary_button.setFixedHeight(36)
        self.primary_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {PURPLE};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #7c3aed;
            }}
            QPushButton:pressed {{
                background-color: #6d28d9;
            }}
            QPushButton:disabled {{
                background-color: #444;
                color: #888;
            }}
        """)

        # Secondary action button (hidden initially)
        self.secondary_button = QPushButton("⬇️ Install Update")
        self.secondary_button.setFixedHeight(36)
        self.secondary_button.setVisible(False)
        self.secondary_button.setStyleSheet("""
            QPushButton {
                background-color: #10b981;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #059669;
            }
            QPushButton:pressed {
                background-color: #047857;
            }
            QPushButton:disabled {
                background-color: #444;
                color: #888;
            }
        """)

        # Close button
        self.close_button = QPushButton("✕ Close")
        self.close_button.setFixedHeight(36)
        self.close_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {TEXT_COLOR};
                border: 1px solid #555;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #444;
                border-color: {PURPLE};
            }}
        """)

        buttons_layout.addWidget(self.primary_button)
        buttons_layout.addWidget(self.secondary_button)
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.close_button)

        content_layout.addWidget(buttons_widget)

        main_layout.addWidget(content_widget)

        # Set dialog properties
        self.setFixedSize(480, 320)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setStyleSheet("""
            QDialog {
                background-color: transparent;
                border: none;
            }
        """)

        # Store references for later use
        self.check_button = self.primary_button
        self.update_button = self.secondary_button

    def _set_status_icon(self, status: str):
        """Set the status icon based on current state."""
        if status == "ready":
            self.status_icon.setText("⚪")
            self.status_icon.setStyleSheet("QLabel { color: #6b7280; font-size: 16px; }")
        elif status == "checking":
            self.status_icon.setText("🔄")
            self.status_icon.setStyleSheet("QLabel { color: #3b82f6; font-size: 16px; }")
        elif status == "success":
            self.status_icon.setText("✅")
            self.status_icon.setStyleSheet("QLabel { color: #10b981; font-size: 16px; }")
        elif status == "update_available":
            self.status_icon.setText("⬆️")
            self.status_icon.setStyleSheet("QLabel { color: #f59e0b; font-size: 16px; }")
        elif status == "downloading":
            self.status_icon.setText("⬇️")
            self.status_icon.setStyleSheet("QLabel { color: #8b5cf6; font-size: 16px; }")
        elif status == "error":
            self.status_icon.setText("❌")
            self.status_icon.setStyleSheet("QLabel { color: #ef4444; font-size: 16px; }")
        elif status == "up_to_date":
            self.status_icon.setText("✨")
            self.status_icon.setStyleSheet("QLabel { color: #10b981; font-size: 16px; }")

    def _setup_connections(self):
        """Set up signal connections."""
        self.check_button.clicked.connect(self._check_for_updates)
        self.update_button.clicked.connect(self._perform_update)
        self.close_button.clicked.connect(self.accept)

    def _check_for_updates(self):
        """Check for available updates."""
        # Update UI state
        self._set_status_icon("checking")
        self.status_title.setText("Checking for Updates")
        self.status_subtitle.setText("Contacting update server...")
        self.check_button.setEnabled(False)
        self.check_button.setText("🔄 Checking...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_text.setVisible(True)
        self.progress_text.setText("Connecting to update server...")

        try:
            update_available, latest_version, download_url, _, _ = self.updater.check_for_updates()

            if update_available:
                self._set_status_icon("update_available")
                self.status_title.setText("Update Available!")
                self.status_subtitle.setText(f"Version {latest_version} is ready to install (publisher signature required)")
                self.secondary_button.setVisible(True)
                self.progress_text.setText(f"New version {latest_version} available")
            else:
                self._set_status_icon("up_to_date")
                self.status_title.setText("Up to Date")
                self.status_subtitle.setText("You're running the latest version")
                self.progress_text.setText("No updates available")

        except UpdaterError as e:
            self._set_status_icon("error")
            self.status_title.setText("Check Failed")
            details = self._format_update_error(e)
            self.status_subtitle.setText("Unable to check for updates")
            self.progress_text.setText(details)
            logger.error(f"Update check failed: {e}")
        except (UpdaterError, ValueError, RuntimeError) as e:
            self._set_status_icon("error")
            self.status_title.setText("Error")
            details = self._format_update_error(e)
            self.status_subtitle.setText("An unexpected error occurred")
            self.progress_text.setText(details)
            logger.error(f"Unexpected error during update check: {e}")
        finally:
            self.check_button.setEnabled(True)
            self.check_button.setText("🔍 Check for Updates")
            self.progress_bar.setVisible(False)

    def _perform_update(self):
        """Perform the update process."""
        # Update UI state
        self._set_status_icon("downloading")
        self.status_title.setText("Installing Update")
        self.status_subtitle.setText("Downloading and installing new version...")
        self.update_button.setEnabled(False)
        self.check_button.setEnabled(False)
        self.update_button.setText("⏳ Installing...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_text.setVisible(True)
        self.progress_text.setText("Preparing installation...")

        # Start update in background thread
        self.update_worker = UpdateWorker(self.updater)
        self.update_worker.progress_updated.connect(self._on_progress_updated)
        self.update_worker.update_completed.connect(self._on_update_completed)
        self.update_worker.start()

    def _on_progress_updated(self, progress: int, message: str):
        """Handle progress updates from the update worker."""
        self.progress_bar.setValue(progress)
        self.progress_text.setText(message)

        # Update status based on progress
        if progress < 30:
            self.status_subtitle.setText("Downloading update files...")
        elif progress < 70:
            self.status_subtitle.setText("Verifying download...")
        elif progress < 80:
            self.status_subtitle.setText("Verifying publisher signature...")
        elif progress < 90:
            self.status_subtitle.setText("Installing update...")
        else:
            self.status_subtitle.setText("Finalizing installation...")

    def _on_update_completed(self, success: bool, message: str):
        """Handle update completion."""
        self.progress_bar.setValue(100)

        if success:
            report = self.updater.get_last_update_report()
            self._set_status_icon("success")
            self.status_title.setText("Update Complete!")
            self.status_subtitle.setText("Restarting application...")
            if report.publisher_verified:
                self.progress_text.setText("Installation successful — Verified publisher signature")
            else:
                self.progress_text.setText("Installation completed — NOT verified publisher signature")

            # Show success message and restart
            PangMessageBox.information(self, "Update Complete", message)

            # Schedule restart after a short delay
            QTimer.singleShot(2000, self._restart_application)
        else:
            self._set_status_icon("error")
            self.status_title.setText("Installation Failed")
            self.status_subtitle.setText("Update could not be completed")
            details = self._format_update_error(Exception(message))
            self.progress_text.setText(details)

            # Show error message
            if "No update available" not in message:
                PangMessageBox.warning(self, "Update Failed", details)

            # Re-enable buttons
            self.update_button.setEnabled(True)
            self.check_button.setEnabled(True)
            self.update_button.setText("⬇️ Install Update")

    def _restart_application(self):
        """Restart the application after successful update."""
        try:
            self.updater.restart_application()
        except (OSError, RuntimeError) as e:
            logger.error(f"Failed to restart application: {e}")
            PangMessageBox.critical(
                self,
                "Restart Failed",
                f"Update completed but failed to restart automatically.\nPlease restart PangCrypter manually.\n\nError: {e}"
            )
            self.accept()

    

    def _rollback_update(self):
        # 1. Check admin first
        self._check_admin_and_prompt()

        # 2. Ask user for version
        version_choice, ok = QInputDialog.getItem(
            self, "Rollback Version", "Select version:", self.updater.get_available_versions(), 0, False
        )
        if not ok:
            return

        # 3. Update UI
        self._set_status_icon("downloading")
        self.status_title.setText(f"Rolling back to {version_choice}...")
        self.status_subtitle.setText("Downloading rollback package...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_text.setVisible(True)
        self.progress_text.setText("Starting rollback...")
        self.update_button.setEnabled(False)
        self.check_button.setEnabled(False)

        # 4. Start rollback thread
        self.rollback_worker = RollbackWorker(self.updater, version_choice)
        self.rollback_worker.progress_updated.connect(lambda p, msg: self._update_progress_ui(p, msg))
        self.rollback_worker.rollback_completed.connect(self._on_rollback_completed)
        self.rollback_worker.start()

    def _update_progress_ui(self, progress, message):
        self.progress_bar.setValue(progress)
        self.progress_text.setText(message)

    def _on_rollback_completed(self, success, message):
        self.progress_bar.setValue(100)
        if success:
            PangMessageBox.information(self, "Rollback Complete", message)
            self._restart_application()
        else:
            PangMessageBox.warning(self, "Rollback Failed", message)
        self.update_button.setEnabled(True)
        self.check_button.setEnabled(True)

    def _check_admin_and_prompt(self):
        if os.name != "nt":
            return
        install_dir = os.path.dirname(sys.executable)
        if not os.access(install_dir, os.W_OK):
            run_as_admin()
