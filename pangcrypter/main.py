import argparse
import logging
import os
import sys
from time import monotonic
from typing import List, Optional
from uuid import UUID

from PyQt6.QtCore import QEvent, QMutex, QTimer, Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QLabel, QMainWindow, QMenu, QProgressBar, QStatusBar

from .core.document_service import DocumentService
from .core.file_workflow_controller import FileWorkflowController
from .core.format_config import CONTENT_MODE_HTML, CONTENT_MODE_PLAINTEXT, HEADER_VERSION, SETTINGS_SIZE
from .core.mem_guard_alert_controller import MemGuardAlertController
from .core.preferences_proxy import PangPreferences, PreferencesDialog
from .core.privacy_guard_controller import PrivacyGuardController
from .core.runtime_services_controller import RuntimeServicesController
from .core.session_state import SessionState
from .core.update_dialog_loader import update_dialog_loader
from .ui.main_ui import EditorWidget
from .ui.messagebox import PangMessageBox
from .utils.app_style import apply_app_stylesheet
from .utils.logger import configure_logging, enable_deferred_file_logging
from .utils.usb import list_usb_drives

logger = logging.getLogger(__name__)


def is_mem_guard_supported() -> bool:
    try:
        from .utils.mem_guard import is_mem_guard_supported as _is_supported
        return _is_supported()
    except (ImportError, OSError, RuntimeError, ValueError):
        return False


class MainWindow(QMainWindow):
    MAX_SECRET_CACHE_IDLE_MINUTES = 15
    DEFAULT_SECRET_CACHE_IDLE_MINUTES = 5

    def __init__(self):
        super().__init__()
        self._init_state()
        self._init_ui()
        self._init_timers()
        self.installEventFilter(self)
        self.menuBar().setEnabled(False)
        QTimer.singleShot(0, self._after_first_paint_init)
        QTimer.singleShot(50, PangPreferences.preload_async)

    def _init_state(self):
        self.session_state = SessionState()
        self.document_service = DocumentService()
        self.privacy_guard = PrivacyGuardController(self, PangPreferences)
        self.file_workflow = FileWorkflowController(self)
        self.mem_guard_alerts = MemGuardAlertController(self)
        self.runtime_services = RuntimeServicesController(self)

        self.saved_file_path = None
        self.current_mode = None
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.header_version = HEADER_VERSION
        self._last_editor_activity_at = monotonic()
        self.operation_mutex = QMutex()
        self.mem_guard_controller = None
        self.panic_recovery = None

        self.usb_cache: list[str] = []
        self.allow_editor_activation = True
        self.cooldown_remaining = 0

        self.screen_recorder_thread = None
        self.screen_recorder_checker = None

    def _init_ui(self):
        self.setWindowTitle("PangCrypter Editor")
        self.setWindowIcon(QIcon("ui/logo.ico"))
        self.resize(800, 600)

        self.editor = EditorWidget(tab_setting=PangPreferences.tab_setting)
        self.editor.focusLost.connect(self.privacy_guard.on_editor_focus_lost)
        self.editor.set_content_mode(False)
        self.setCentralWidget(self.editor)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        self.mode_label = QLabel("Plaintext mode")
        self.mode_label.setObjectName("StatusMetaLabel")
        self.mode_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.mode_label.customContextMenuRequested.connect(self.show_content_mode_menu)
        self.status_bar.addPermanentWidget(self.mode_label)

        self.file_info_label = QLabel("No file loaded")
        self.file_info_label.setObjectName("StatusMetaLabel")
        self.status_bar.addPermanentWidget(self.file_info_label)

        self.hidden_label = QLabel("", self)
        self.hidden_label.setObjectName("HiddenNoticeLabel")
        self.hidden_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hidden_label.setWordWrap(True)
        self.hidden_label.hide()
        self.hidden_label.mousePressEvent = self.privacy_guard.on_hidden_label_clicked
        self._layout_hidden_label()

    def _init_timers(self):
        self.autosave_timer = QTimer(singleShot=True)
        self.autosave_timer.setInterval(1000)
        self.autosave_timer.timeout.connect(self.autosave)
        self.editor.textChanged.connect(lambda: self.autosave_timer.start())
        self.editor.textChanged.connect(self._on_editor_activity)

        self.secret_idle_timer = QTimer(singleShot=True)
        self.secret_idle_timer.timeout.connect(self._on_infocus_inactivity_timeout)
        self.cooldown_timer = QTimer()
        self.cooldown_timer.setInterval(1000)
        self.cooldown_timer.timeout.connect(self.privacy_guard.update_cooldown)
        self.usb_cache_timer = QTimer()
        self.usb_cache_timer.timeout.connect(self.refresh_usb_cache)

    def _after_first_paint_init(self):
        self._build_menus()
        self._warn_secret_cache_limit()
        self.menuBar().setEnabled(True)
        QTimer.singleShot(0, update_dialog_loader.preload_async)
        QTimer.singleShot(100, update_dialog_loader.preload_backend_async)
        QTimer.singleShot(50, self.runtime_services.start_deferred_services)

    def _build_menus(self):
        fm = self.menuBar().addMenu("&File")
        fm.addAction("&Open", self.open_file).setShortcut("Ctrl+O")
        fm.addAction("&Save", self.on_save_triggered).setShortcut("Ctrl+S")
        fm.addAction("Save &As", self.save_file).setShortcut("Ctrl+Shift+S")
        fm.addAction("&Close", self.close_file).setShortcut("Ctrl+W")
        fm.addAction("&Preferences", self.open_preferences_dialog).setShortcut("Ctrl+,")

        em = self.menuBar().addMenu("&Edit")
        em.addAction("&Undo", self.editor.undo).setShortcut("Ctrl+Z")
        em.addAction("&Redo", self.editor.redo).setShortcut("Ctrl+Y")
        em.addSeparator()
        em.addAction("Cu&t", self.editor.cut).setShortcut("Ctrl+X")
        em.addAction("&Copy", self.editor.copy).setShortcut("Ctrl+C")
        em.addAction("&Paste", self.editor.paste).setShortcut("Ctrl+V")
        em.addSeparator()
        em.addAction("Select &All", self.editor.selectAll).setShortcut("Ctrl+A")
        em.addSeparator()
        em.addAction("Reset Formatting", self.editor.reset_formatting).setShortcut("Ctrl+Space")
        em.addAction("Increase Font Size", lambda: self.editor.change_font_size(1)).setShortcut("Ctrl+Shift+>")
        em.addAction("Decrease Font Size", lambda: self.editor.change_font_size(-1)).setShortcut("Ctrl+Shift+<")

        hm = self.menuBar().addMenu("&Help")
        hm.addAction("&Help", self.open_help_page).setShortcut("F1")
        hm.addAction("&Check for Updates", self.open_update_dialog)

    def open_help_page(self):
        from webbrowser import open as webopen
        webopen("https://www.panghq.com/tools/pangcrypter/help")

    def _layout_hidden_label(self):
        rect = self.contentsRect()
        w = max(280, rect.width() - 80)
        h = max(96, min(180, rect.height() // 3))
        x = rect.x() + (rect.width() - w) // 2
        y = rect.y() + (rect.height() - h) // 2
        self.hidden_label.setGeometry(x, y, w, h)

    def _ensure_mem_guard_controller(self):
        if self.mem_guard_controller is None:
            from .core.mem_guard_controller import MemGuardController
            self.mem_guard_controller = MemGuardController(self, PangPreferences, logger)
        return self.mem_guard_controller

    def _ensure_panic_recovery_service(self):
        if self.panic_recovery is None:
            from .core.panic_recovery_service import PanicRecoveryService
            self.panic_recovery = PanicRecoveryService(self, PangPreferences)
        return self.panic_recovery

    def _stop_mem_guard(self) -> bool:
        checker = getattr(self, "mem_guard_checker", None)
        thread = getattr(self, "mem_guard_thread", None)
        if checker is not None:
            checker.stop()
        if thread is not None:
            thread.quit()
            if not thread.wait(5000):
                return False
        self.mem_guard_checker = None
        self.mem_guard_thread = None
        return True

    def open_update_dialog(self):
        try:
            if not update_dialog_loader.is_ready():
                self.status_bar.showMessage("Preparing updater…", 1500)
            update_dialog_loader.create_dialog(self).exec()
        except Exception as e:
            logger.error("Failed to open update dialog: %s", e)
            PangMessageBox.critical(self, "Update Error", f"Failed to open update dialog:\n{e}")

    def open_preferences_dialog(self):
        PangPreferences.ensure_loaded()
        dlg = PreferencesDialog(self)
        if dlg.exec():
            self.editor.set_tab_setting(PangPreferences.tab_setting)
            self.reset_secret_idle_timer()
            self._ensure_mem_guard_controller().configure()

    def on_save_triggered(self):
        self.save_file() if self.saved_file_path is None else self.autosave()

    def save_file(self):
        return self.file_workflow.save_file()

    def open_file(self, path: str | None = None):
        return self.file_workflow.open_file(path)

    def autosave(self):
        return self.file_workflow.autosave()

    def on_memory_probe_detected(self, finding):
        self.mem_guard_alerts.handle(finding)

    def refresh_usb_cache(self):
        try:
            self.usb_cache = list_usb_drives()
        except (OSError, RuntimeError, ValueError):
            self.usb_cache = []

    def check_usb_present(self) -> Optional[List[str]]:
        if self.usb_cache:
            return self.usb_cache
        usbs = list_usb_drives()
        if not usbs:
            PangMessageBox.warning(self, "No USB Drives", "No USB drives detected. Please plug in your USB key and try again.")
            return None
        return usbs

    def show_progress(self, message: str, maximum: int = 0):
        self.status_bar.showMessage(message)
        self.progress_bar.setVisible(True)
        if maximum > 0:
            self.progress_bar.setMaximum(maximum)
            self.progress_bar.setValue(0)
        else:
            self.progress_bar.setRange(0, 0)

    def hide_progress(self):
        self.progress_bar.setVisible(False)
        self.status_bar.clearMessage()

    def update_progress(self, value: int):
        self.progress_bar.setValue(value)

    def _on_editor_activity(self):
        self._last_editor_activity_at = monotonic()
        if PangPreferences.session_cache_enabled and (
            self.session_state.cached_password is not None or self.session_state.cached_usb_key is not None
        ):
            self.reset_secret_idle_timer()

    def _effective_secret_cache_idle_minutes(self) -> int:
        return self.session_state.effective_secret_cache_idle_minutes(
            PangPreferences, self.DEFAULT_SECRET_CACHE_IDLE_MINUTES, self.MAX_SECRET_CACHE_IDLE_MINUTES
        )

    def _warn_secret_cache_limit(self):
        if self.session_state.should_warn_secret_cache_limit(PangPreferences):
            logger.warning(
                "Session secret caching uses best-effort obfuscation only and is limited to %s minutes of in-focus inactivity.",
                self._effective_secret_cache_idle_minutes(),
            )
            self.session_state.mark_secret_cache_notice_logged()

    def _on_infocus_inactivity_timeout(self):
        if PangPreferences.session_cache_enabled and PangPreferences.session_infocus_inactivity_reauth_enabled:
            self.clear_cached_secrets()

    def _update_session_cache_after_auth(self, *, file_uuid: UUID, password_bytes: Optional[bytearray], usb_key):
        self.session_state.cached_uuid = file_uuid
        if PangPreferences.session_cache_enabled:
            self.session_state.cached_password = self.session_state.obfuscate_secret(password_bytes) if password_bytes else None
            if usb_key:
                key_bytes = bytearray(usb_key)
                self.session_state.cached_usb_key = self.session_state.obfuscate_secret(key_bytes)
                self._clear_temporary_bytes(key_bytes)
            else:
                self.session_state.cached_usb_key = None
            self.reset_secret_idle_timer()
        else:
            self.clear_cached_secrets()
        self._clear_temporary_bytes(password_bytes)
        if isinstance(usb_key, bytearray):
            self._clear_temporary_bytes(usb_key)

    def best_effort_clear_memory(self, data):
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0

    def _clear_temporary_bytes(self, data: Optional[bytearray]):
        if data is not None:
            self.best_effort_clear_memory(data)

    def clear_cached_secrets(self):
        self.session_state.clear_cached_secrets(self.best_effort_clear_memory)
        self.secret_idle_timer.stop()

    def reset_secret_idle_timer(self):
        if PangPreferences.session_cache_enabled and PangPreferences.session_infocus_inactivity_reauth_enabled:
            self.secret_idle_timer.setInterval(self._effective_secret_cache_idle_minutes() * 60 * 1000)
            self.secret_idle_timer.start()
        else:
            self.secret_idle_timer.stop()

    def _apply_focus_reauth_policy(self):
        if self.session_state.should_reauth_after_focus(PangPreferences):
            self.clear_cached_secrets()

    def _read_file_uuid(self, path: str) -> Optional[UUID]:
        try:
            with open(path, "rb") as f:
                if len(f.read(SETTINGS_SIZE)) != SETTINGS_SIZE:
                    return None
                if len(f.read(16)) != 16:
                    return None
                uid = f.read(16)
                return UUID(bytes=uid) if len(uid) == 16 else None
        except (OSError, ValueError):
            return None

    def close_file(self):
        if self.saved_file_path is None and self.editor.toPlainText().strip() == "":
            return

        if self.editor.toPlainText().strip() != "":
            ret = PangMessageBox.question(
                self,
                "Close File",
                "Are you sure you want to close the current file? Unsaved changes will be lost.",
                buttons=PangMessageBox.StandardButton.Yes | PangMessageBox.StandardButton.No,
                default=PangMessageBox.StandardButton.No,
            )
            if ret == PangMessageBox.StandardButton.No:
                return

        self.saved_file_path = None
        self.current_mode = None
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.header_version = HEADER_VERSION
        self.editor.set_content_mode(False)
        self.clear_cached_secrets()
        self.editor.clear()
        self.update_window_title(None)

    def show_content_mode_menu(self, pos):
        menu = QMenu(self)
        if self.current_content_mode == CONTENT_MODE_PLAINTEXT:
            menu.addAction("Convert to HTML", self.convert_plaintext_to_html)
        else:
            menu.addAction("Convert to plaintext + keep HTML", self.convert_html_to_plaintext_keep_html)
            menu.addAction("Convert to plaintext (discard HTML)", self.convert_html_to_plaintext_discard_html)
        menu.exec(self.mode_label.mapToGlobal(pos))

    def convert_plaintext_to_html(self):
        self.editor.setHtml(self.editor.toPlainText())
        self.editor.setHtml(self.editor.toHtml())
        self.current_content_mode = CONTENT_MODE_HTML
        self.editor.set_content_mode(True)
        self.update_file_info_label()

    def convert_html_to_plaintext_keep_html(self):
        self.editor.setPlainText(self.editor.toHtml().replace("\r\n", "\n").replace("\r", "\n"))
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.editor.set_content_mode(False)
        self.update_file_info_label()

    def convert_html_to_plaintext_discard_html(self):
        self.editor.setPlainText(self.editor.toPlainText().replace("\r\n", "\n").replace("\r", "\n"))
        self.current_content_mode = CONTENT_MODE_PLAINTEXT
        self.editor.set_content_mode(False)
        self.update_file_info_label()

    def _serialize_editor_content(self) -> bytes:
        return self.editor.toHtml().encode("utf-8") if self.current_content_mode == CONTENT_MODE_HTML else self.editor.toPlainText().encode("utf-8")

    def _load_editor_content(self, content: str):
        if self.current_content_mode == CONTENT_MODE_HTML:
            self.editor.setHtml(content)
            self.editor.set_content_mode(True)
        else:
            self.editor.setPlainText(content)
            self.editor.set_content_mode(False)

    def update_file_info_label(self):
        mode_label = "Plaintext" if self.current_content_mode == CONTENT_MODE_PLAINTEXT else "HTML"
        self.mode_label.setText(f"{mode_label} mode")
        if not self.saved_file_path:
            self.file_info_label.setText("No file loaded")
            return
        enc_mode = self.current_mode.name if self.current_mode else "Unknown"
        self.file_info_label.setText(f"Format v{self.header_version} | {enc_mode} | {mode_label}")

    def update_window_title(self, filename: str | None):
        if filename:
            name_without_ext = os.path.splitext(os.path.basename(filename))[0]
            self.setWindowTitle(f"Editing {name_without_ext} - PangCrypter")
        else:
            self.setWindowTitle("PangCrypter")
        self.update_file_info_label()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.WindowActivate:
            self.privacy_guard.on_window_activate()
        elif event.type() == QEvent.Type.WindowDeactivate:
            self.privacy_guard.on_window_deactivate()
        return super().eventFilter(obj, event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._layout_hidden_label()

    def closeEvent(self, event):
        self.runtime_services.stop_all()
        super().closeEvent(event)


def main():
    parser = argparse.ArgumentParser(description="PangCrypter")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args, remaining = parser.parse_known_args()

    configure_logging(args.debug, defer_file_logging=True)
    app = QApplication([sys.argv[0]] + remaining)
    app.setStyle("Fusion")
    apply_app_stylesheet(app)

    win = MainWindow()
    file_arg = next((arg for arg in remaining if os.path.isfile(arg) and arg.lower().endswith(".enc")), None)
    if file_arg:
        try:
            win.open_file(file_arg)
        except (OSError, RuntimeError, ValueError) as e:
            print(f"Failed to open {file_arg}: {e}")

    win.show()
    if args.debug:
        QTimer.singleShot(0, enable_deferred_file_logging)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
