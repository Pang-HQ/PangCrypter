# preferences.py
from dataclasses import dataclass, asdict
import json
import logging
import os
import platform
import hashlib
import sys

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QListView,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtCore import Qt, QSize
from .mem_guard import MemGuardMode

logger = logging.getLogger(__name__)

MEM_GUARD_MODE_OFF = MemGuardMode.OFF.name.lower()
MEM_GUARD_MODE_NORMAL = MemGuardMode.NORMAL.name.lower()
MEM_GUARD_MODE_ULTRA = MemGuardMode.ULTRA_AGGRESSIVE.name.lower()

_MEM_GUARD_MODE_NAME_TO_VALUE = {
    mode.name: mode.name.lower()
    for mode in MemGuardMode
}


def _normalize_mem_guard_mode_name(mode: str) -> str:
    normalized = str(mode or "").strip().replace("-", "_").upper()
    if normalized in {"ULTRA", "ULTRAAGGRESSIVE"}:
        normalized = "ULTRA_AGGRESSIVE"
    if not normalized:
        normalized = MemGuardMode.OFF.name
    return normalized


def _mem_guard_mode_to_storage_value(mode: str) -> str:
    name = _normalize_mem_guard_mode_name(mode)
    return _MEM_GUARD_MODE_NAME_TO_VALUE.get(name, default_mem_guard_mode())


def default_mem_guard_mode() -> str:
    return MemGuardMode.NORMAL.name.lower() if _is_mem_guard_supported() else MemGuardMode.OFF.name.lower()


def _is_mem_guard_supported() -> bool:
    return os.name == "nt" and platform.system() == "Windows"


def _estimate_scan_time_ms(**kwargs):
    try:
        from .mem_guard import estimate_scan_time_ms
        return estimate_scan_time_ms(**kwargs)
    except (ImportError, OSError, RuntimeError, ValueError):
        return None


def _file_sha256(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _normalize_whitelist_entry_with_hash(path: str, sha256: str) -> dict | None:
    clean_path = os.path.abspath(str(path or "").strip())
    if not clean_path:
        return None

    clean_sha = str(sha256 or "").strip().lower()
    if not clean_sha:
        if os.path.isfile(clean_path):
            clean_sha = _file_sha256(clean_path).lower()
        else:
            logger.warning(
                "Dropping mem-guard whitelist entry without hash because file is not accessible: %s",
                clean_path,
            )
            return None

    if not clean_sha:
        logger.warning(
            "Dropping mem-guard whitelist entry because SHA-256 could not be computed: %s",
            clean_path,
        )
        return None

    return {"path": clean_path, "sha256": clean_sha}

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_CHEVRON_DOWN = os.path.join(_PROJECT_ROOT, "ui", "chevron-down.svg").replace("\\", "/")
_CHEVRON_UP = os.path.join(_PROJECT_ROOT, "ui", "chevron-up.svg").replace("\\", "/")


def _preferences_base_dir() -> str:
    if os.name == "nt":
        appdata = os.getenv("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(appdata, "PangCrypter")

    if platform.system() == "Darwin":
        return os.path.join(os.path.expanduser("~/Library/Application Support"), "PangCrypter")

    xdg_config_home = os.getenv("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(xdg_config_home, "PangCrypter")


def _preferences_path() -> str:
    return os.path.join(_preferences_base_dir(), "preferences.json")


PREFERENCES_FILE = _preferences_path()
LEGACY_PREFERENCES_FILE = os.path.join(_PROJECT_ROOT, "preferences.json")
LEGACY_USER_CONFIG_FILES = [
    os.path.join(os.getenv("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "pangcrypter", "preferences.json"),
]


def _preferences_stylesheet() -> str:
    return f"""
        QDialog {{
            background-color: #121212;
            color: #ccc;
        }}
        QLabel {{
            color: #ccc;
        }}
        QListWidget {{
            background-color: #1f1f25;
            color: #ccc;
            border: 1px solid #3a3a3a;
            border-radius: 6px;
            padding: 4px;
        }}
        QListWidget::item {{
            padding: 8px;
            border-radius: 4px;
        }}
        QListWidget::item:selected {{
            background-color: #333;
            color: #eee;
        }}
        QListWidget#MemGuardWhitelistList::item {{
            padding: 4px 8px;
            margin: 0;
            border-radius: 4px;
        }}
        QCheckBox {{
            color: #ccc;
        }}

        /* Base inputs */
        QLineEdit, QComboBox, QSpinBox {{
            background-color: #1f1f25;
            color: #ccc;
            border: 1px solid #555;
            border-radius: 6px;
            min-height: 28px;
            padding: 3px 8px;
        }}

        /* Focus */
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
            border-color: #777;
            outline: 0;
        }}

        /* -------- QComboBox -------- */
        QComboBox {{
            min-height: 28px;
            padding: 3px 24px 3px 8px;
        }}
        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 20px;
            border-left: 1px solid #555;
            background-color: #2a2a30;
            border-top-right-radius: 6px;
            border-bottom-right-radius: 6px;
        }}
        QComboBox::down-arrow {{
            image: url({_CHEVRON_DOWN});
            width: 10px;
            height: 10px;
        }}
        QComboBox QAbstractItemView,
        QListView#PreferencesComboPopup {{
            background-color: #1f1f25;
            color: #ccc;
            border: 1px solid #555;
            outline: 0;
            selection-background-color: #2f2f38;
            padding: 4px;
        }}
        QComboBox QAbstractItemView::item,
        QListView#PreferencesComboPopup::item {{
            min-height: 24px;
            padding: 4px 8px;
            border-radius: 6px;
        }}
        QComboBox QAbstractItemView::item:hover,
        QListView#PreferencesComboPopup::item:hover {{
            background-color: #3a3a46;
            color: #eee;
        }}
        QComboBox QAbstractItemView::item:selected,
        QListView#PreferencesComboPopup::item:selected {{
            background-color: #4a4a58;
            color: #fff;
        }}

        /* -------- QSpinBox -------- */
        QSpinBox {{
            padding-right: 28px;
        }}
        QSpinBox::up-button, QSpinBox::down-button {{
            subcontrol-origin: padding;
            width: 24px;
            border-left: 1px solid #555;
            background-color: #2a2a30;
        }}
        QSpinBox::up-button {{
            subcontrol-position: top right;
            border-top-right-radius: 6px;
        }}
        QSpinBox::down-button {{
            subcontrol-position: bottom right;
            border-bottom-right-radius: 6px;
        }}
        QSpinBox::up-arrow {{
            image: url({_CHEVRON_UP});
            width: 10px;
            height: 10px;
        }}
        QSpinBox::down-arrow {{
            image: url({_CHEVRON_DOWN});
            width: 10px;
            height: 10px;
        }}

        QPushButton {{
            background-color: #6B21A8;
            color: #eee;
            border: none;
            border-radius: 5px;
            padding: 6px 14px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: #581C87;
        }}
        QListWidget:focus,
        QPushButton:focus {{
            outline: 0;
        }}
    """


class StableComboBox(QComboBox):
    """ComboBox with an explicit QListView popup for more stable geometry."""

    def __init__(self, parent=None):
        super().__init__(parent)
        popup_view = QListView(self)
        popup_view.setObjectName("PreferencesComboPopup")
        self.setView(popup_view)
        self.setMaxVisibleItems(12)

    def showPopup(self):
        super().showPopup()
        popup = self.view().window()
        if popup is None:
            return

        below_left = self.mapToGlobal(self.rect().bottomLeft())
        screen = QGuiApplication.screenAt(below_left) or QGuiApplication.primaryScreen()
        if screen is None:
            return

        available = screen.availableGeometry()
        popup_width = max(popup.width(), self.width())
        popup_height = popup.height()

        max_height_below = max(120, available.bottom() - below_left.y() - 4)
        popup_height = min(popup_height, max_height_below)

        x = min(max(available.left(), below_left.x()), max(available.left(), available.right() - popup_width))
        y = min(max(available.top(), below_left.y()), max(available.top(), available.bottom() - popup_height))

        popup.resize(popup_width, popup_height)
        popup.move(x, y)


@dataclass
class Preferences:
    recording_cooldown: int = 30
    screen_recording_hide_enabled: bool = True
    tab_out_hide_enabled: bool = True
    tab_setting: str = "spaces4"
    session_cache_enabled: bool = True
    session_reauth_on_focus_loss: bool = True
    session_reauth_minutes: int = 2
    session_infocus_inactivity_reauth_enabled: bool = True
    session_infocus_inactivity_minutes: int = 5
    mem_guard_mode: str = default_mem_guard_mode()
    mem_guard_whitelist: list[dict | str] = None
    auto_delete_panic_files: bool = True
    mem_guard_scan_interval_ms: int = 50
    mem_guard_pid_cache_cap: int = 128

    def __post_init__(self):
        if self.mem_guard_whitelist is None:
            self.mem_guard_whitelist = []

    def normalize(self):
        self.session_reauth_minutes = max(1, min(5, int(self.session_reauth_minutes)))
        self.session_infocus_inactivity_minutes = max(
            self.session_reauth_minutes,
            min(120, max(5, int(self.session_infocus_inactivity_minutes))),
        )

        if not self.session_cache_enabled or not _is_mem_guard_supported():
            self.mem_guard_mode = MEM_GUARD_MODE_OFF

        self.mem_guard_scan_interval_ms = max(20, min(200, int(self.mem_guard_scan_interval_ms)))
        self.mem_guard_pid_cache_cap = max(32, min(512, int(self.mem_guard_pid_cache_cap)))

        self.mem_guard_mode = _mem_guard_mode_to_storage_value(self.mem_guard_mode)

        if not isinstance(self.mem_guard_whitelist, list):
            self.mem_guard_whitelist = []

        normalized_whitelist: list[dict] = []
        for item in self.mem_guard_whitelist:
            if isinstance(item, str) and item.strip():
                normalized = _normalize_whitelist_entry_with_hash(item, "")
                if normalized:
                    normalized_whitelist.append(normalized)
            elif isinstance(item, dict):
                path = str(item.get("path", "")).strip()
                if path:
                    normalized = _normalize_whitelist_entry_with_hash(path, str(item.get("sha256", "")))
                    if normalized:
                        normalized_whitelist.append(normalized)

        deduped: dict[str, dict] = {}
        for entry in normalized_whitelist:
            canonical_path = os.path.normcase(os.path.abspath(entry["path"]))
            sha = str(entry.get("sha256", "")).strip().lower()
            existing = deduped.get(canonical_path)
            if existing is None:
                deduped[canonical_path] = {"path": entry["path"], "sha256": sha}
                continue

            existing_sha = str(existing.get("sha256", "")).strip().lower()
            if not existing_sha and sha:
                deduped[canonical_path] = {"path": entry["path"], "sha256": sha}
            elif existing_sha and sha and existing_sha != sha:
                logger.warning(
                    "Conflicting mem-guard whitelist hashes for path '%s'; keeping existing hash",
                    entry["path"],
                )

        self.mem_guard_whitelist = list(deduped.values())

    def load_preferences(self):
        path = PREFERENCES_FILE
        legacy_candidates = [LEGACY_PREFERENCES_FILE] + LEGACY_USER_CONFIG_FILES
        if not os.path.exists(path):
            for legacy_path in legacy_candidates:
                if not os.path.exists(legacy_path):
                    continue
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    if os.name != "nt":
                        os.chmod(os.path.dirname(path), 0o700)
                    with open(legacy_path, "r", encoding="utf-8") as src, open(path, "w", encoding="utf-8") as dst:
                        dst.write(src.read())
                    logger.info("Migrated legacy preferences file to user config directory: %s", path)
                except (OSError, ValueError) as e:
                    logger.warning("Could not migrate legacy preferences file: %s", e)
                break

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "cache_passwords_enabled" in data and "session_cache_enabled" not in data:
                    data["session_cache_enabled"] = bool(data.get("cache_passwords_enabled"))
                if "cache_secrets_enabled" in data and "session_cache_enabled" not in data:
                    data["session_cache_enabled"] = bool(data.get("cache_secrets_enabled"))

                for key, value in data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
            logger.warning("Could not load preferences, using defaults: %s", e)
        finally:
            self.normalize()

    def save_preferences(self):
        self.normalize()
        os.makedirs(os.path.dirname(PREFERENCES_FILE), exist_ok=True)
        if os.name != "nt":
            try:
                os.chmod(os.path.dirname(PREFERENCES_FILE), 0o700)
            except OSError as e:
                logger.debug("Could not apply strict permissions to preferences dir: %s", e)

        temp_path = f"{PREFERENCES_FILE}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, PREFERENCES_FILE)


PangPreferences = Preferences()
PangPreferences.load_preferences()


class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self.resize(780, 560)
        self.setStyleSheet(_preferences_stylesheet())
        self._hidden_self_whitelist_entries: list[dict] = []
        self._self_exe_path, self._self_exe_sha = self._current_executable_identity()

        root = QVBoxLayout(self)
        body = QHBoxLayout()
        root.addLayout(body, 1)

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(170)
        self.sidebar.setSpacing(8)
        self.sidebar.addItems(["General", "Session", "Memory Guard", "Editor"])
        body.addWidget(self.sidebar)

        self.pages = QStackedWidget()
        body.addWidget(self.pages, 1)

        self.pages.addWidget(self._build_general_page())
        self.pages.addWidget(self._build_session_page())
        self.pages.addWidget(self._build_mem_guard_page())
        self.pages.addWidget(self._build_editor_page())

        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.sidebar.setCurrentRow(0)

        buttons = QHBoxLayout()
        buttons.addStretch()
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(ok_btn)
        buttons.addWidget(cancel_btn)
        root.addLayout(buttons)

        self._update_mem_guard_controls()

    def _build_general_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Cooldown for recording sessions (seconds):"))
        self.cooldown_spin = QSpinBox()
        self.cooldown_spin.setRange(1, 300)
        self.cooldown_spin.setValue(PangPreferences.recording_cooldown)
        layout.addWidget(self.cooldown_spin)

        self.disable_recording_hide = QCheckBox("Disable hiding editor when recording detected")
        self.disable_recording_hide.setChecked(not PangPreferences.screen_recording_hide_enabled)
        layout.addWidget(self.disable_recording_hide)

        self.disable_tabbing_hide = QCheckBox("Disable hiding editor on tab out (unsafe)")
        self.disable_tabbing_hide.setChecked(not PangPreferences.tab_out_hide_enabled)
        layout.addWidget(self.disable_tabbing_hide)

        self.auto_delete_panic = QCheckBox("Auto-delete .panic.enc after successful restore")
        self.auto_delete_panic.setChecked(PangPreferences.auto_delete_panic_files)
        layout.addWidget(self.auto_delete_panic)
        layout.addStretch()
        return page

    def _build_session_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.enable_session_cache = QCheckBox("Enable session caching (required for mem guard + autosave)")
        self.enable_session_cache.setChecked(PangPreferences.session_cache_enabled)
        self.enable_session_cache.toggled.connect(self._update_mem_guard_controls)
        layout.addWidget(self.enable_session_cache)

        self.session_reauth_on_focus_loss = QCheckBox("Require re-auth after app is out of focus")
        self.session_reauth_on_focus_loss.setChecked(PangPreferences.session_reauth_on_focus_loss)
        layout.addWidget(self.session_reauth_on_focus_loss)

        layout.addWidget(QLabel("Re-auth timeout after focus loss (minutes):"))
        self.reauth_minutes_spin = QSpinBox()
        self.reauth_minutes_spin.setRange(1, 5)
        self.reauth_minutes_spin.setValue(PangPreferences.session_reauth_minutes)
        layout.addWidget(self.reauth_minutes_spin)

        self.infocus_reauth_enabled = QCheckBox("Require re-auth after in-focus inactivity")
        self.infocus_reauth_enabled.setChecked(PangPreferences.session_infocus_inactivity_reauth_enabled)
        layout.addWidget(self.infocus_reauth_enabled)

        layout.addWidget(QLabel("In-focus inactivity timeout (minutes):"))
        self.infocus_minutes_spin = QSpinBox()
        self.infocus_minutes_spin.setRange(5, 120)
        self.infocus_minutes_spin.setValue(PangPreferences.session_infocus_inactivity_minutes)
        layout.addWidget(self.infocus_minutes_spin)
        layout.addStretch()
        return page

    def _build_mem_guard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Memory guard mode:"))
        self.mem_guard_combo = StableComboBox()
        self.mem_guard_combo.addItem("Off", MEM_GUARD_MODE_OFF)
        self.mem_guard_combo.addItem("Normal (recommended)", MEM_GUARD_MODE_NORMAL)
        self.mem_guard_combo.addItem("Ultra aggressive (not recommended)", MEM_GUARD_MODE_ULTRA)
        self.mem_guard_combo.setCurrentIndex(max(0, self.mem_guard_combo.findData(PangPreferences.mem_guard_mode)))
        layout.addWidget(self.mem_guard_combo)

        layout.addWidget(QLabel("Memory guard scan interval (ms):"))
        self.scan_interval_spin = QSpinBox()
        self.scan_interval_spin.setRange(20, 200)
        self.scan_interval_spin.setValue(PangPreferences.mem_guard_scan_interval_ms)
        layout.addWidget(self.scan_interval_spin)

        layout.addWidget(QLabel("PID handle cache cap:"))
        self.cache_cap_spin = QSpinBox()
        self.cache_cap_spin.setRange(32, 512)
        self.cache_cap_spin.setSingleStep(32)
        self.cache_cap_spin.setValue(PangPreferences.mem_guard_pid_cache_cap)
        layout.addWidget(self.cache_cap_spin)

        estimate_row = QHBoxLayout()
        self.scan_estimate_label = QLabel("Expected scan time: not sampled")
        self.scan_estimate_button = QPushButton("Estimate (25 scans)")
        self.scan_estimate_button.clicked.connect(self._estimate_scan_time)
        estimate_row.addWidget(self.scan_estimate_label, 1)
        estimate_row.addWidget(self.scan_estimate_button)
        layout.addLayout(estimate_row)

        self.mem_guard_info = QLabel("")
        layout.addWidget(self.mem_guard_info)

        layout.addWidget(QLabel("Memory guard whitelist (executable paths):"))
        self.whitelist_list = QListWidget()
        self.whitelist_list.setObjectName("MemGuardWhitelistList")
        self.whitelist_list.setSpacing(2)
        self.whitelist_list.itemDoubleClicked.connect(self._toggle_whitelist_item_details)
        for item in PangPreferences.mem_guard_whitelist:
            if isinstance(item, dict):
                p = item.get("path", "")
                s = item.get("sha256", "")
                if self._should_hide_self_whitelist_entry(p, s):
                    self._hidden_self_whitelist_entries.append(
                        {"path": os.path.abspath(str(p).strip()), "sha256": str(s or "").strip().lower()}
                    )
                    continue
                self._add_whitelist_list_item(p, s)
        layout.addWidget(self.whitelist_list)

        wl_row = QHBoxLayout()
        self.whitelist_add_btn = QPushButton("Add executable")
        self.whitelist_add_btn.clicked.connect(self._add_whitelist_entry)
        self.whitelist_remove_btn = QPushButton("Remove selected")
        self.whitelist_remove_btn.clicked.connect(self._remove_whitelist_entry)
        wl_row.addWidget(self.whitelist_add_btn)
        wl_row.addWidget(self.whitelist_remove_btn)
        layout.addLayout(wl_row)

        layout.addStretch()
        return page

    def _build_editor_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Tab character settings:"))
        self.tab_type_combo = StableComboBox()
        self.tab_type_combo.addItems(["Spaces", "Tab character"])
        self.tab_type_combo.setCurrentIndex(1 if PangPreferences.tab_setting.startswith("tab") else 0)
        layout.addWidget(self.tab_type_combo)

        self.spaces_label = QLabel("Number of spaces per indent:")
        layout.addWidget(self.spaces_label)
        self.spaces_spin = QSpinBox()
        self.spaces_spin.setRange(1, 16)
        if PangPreferences.tab_setting.startswith("spaces"):
            try:
                self.spaces_spin.setValue(int(PangPreferences.tab_setting[6:]))
            except ValueError:
                self.spaces_spin.setValue(4)
        else:
            self.spaces_spin.setValue(4)
        layout.addWidget(self.spaces_spin)
        self.tab_type_combo.currentIndexChanged.connect(self._update_spaces_visibility)
        self._update_spaces_visibility(self.tab_type_combo.currentIndex())

        layout.addStretch()
        return page

    def _update_spaces_visibility(self, index: int):
        is_spaces = index == 0
        self.spaces_label.setVisible(is_spaces)
        self.spaces_spin.setVisible(is_spaces)

    def _estimate_scan_time(self):
        if not _is_mem_guard_supported() or not self.enable_session_cache.isChecked():
            self.scan_estimate_label.setText("Expected scan time: unavailable")
            return
        self.scan_estimate_label.setText("Expected scan time: sampling...")
        self.repaint()
        avg = _estimate_scan_time_ms(
            samples=25,
            max_entries=0,
            cache_cap=self.cache_cap_spin.value(),
            inter_scan_delay_ms=self.scan_interval_spin.value(),
        )
        if avg is None:
            self.scan_estimate_label.setText("Expected scan time: unavailable")
        else:
            self.scan_estimate_label.setText(
                f"Expected scan time: ~{avg:.2f} ms (25-scan avg, interval delay excluded)"
            )

    def _update_mem_guard_controls(self):
        supported = _is_mem_guard_supported()
        session_ok = self.enable_session_cache.isChecked()
        enabled = supported and session_ok

        for w in (
            self.mem_guard_combo,
            self.scan_interval_spin,
            self.cache_cap_spin,
            self.scan_estimate_button,
            self.whitelist_list,
            self.whitelist_add_btn,
            self.whitelist_remove_btn,
        ):
            w.setEnabled(enabled)

        if not supported:
            self.mem_guard_info.setText("Memory guard is available on Windows only.")
        elif not session_ok:
            self.mem_guard_info.setText("Enable session caching to use memory guard.")
            self.mem_guard_combo.setCurrentIndex(self.mem_guard_combo.findData(MEM_GUARD_MODE_OFF))
        else:
            self.mem_guard_info.setText("Memory guard will monitor suspicious process memory access.")

    def _add_whitelist_entry(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select executable to whitelist")
        if not path:
            return
        path = os.path.abspath(path)
        digest = _file_sha256(path)
        if self._should_hide_self_whitelist_entry(path, digest):
            return
        canonical = os.path.normcase(path)
        for i in range(self.whitelist_list.count()):
            existing_item = self.whitelist_list.item(i)
            payload = existing_item.data(Qt.ItemDataRole.UserRole) or {}
            existing_path = os.path.normcase(str(payload.get("path", "")))
            if existing_path == canonical:
                return
        self._add_whitelist_list_item(path, digest)

    def _remove_whitelist_entry(self):
        row = self.whitelist_list.currentRow()
        if row >= 0:
            self.whitelist_list.takeItem(row)

    def _compact_whitelist_text(self, path: str) -> str:
        prog_name = os.path.basename(path) or path
        return f"▸ {prog_name}"

    def _expanded_whitelist_text(self, path: str, sha256: str) -> str:
        prog_name = os.path.basename(path) or path
        sig = sha256 or "(not recorded)"
        return f"▾ {prog_name}\n - Path: {path}\n - SHA256: {sig}"

    def _set_whitelist_item_size(self, item: QListWidgetItem, expanded: bool) -> None:
        fm = self.whitelist_list.fontMetrics()
        # Keep compact rows tight and force shrink-back after collapse.
        lines = 3 if expanded else 1
        height = (fm.lineSpacing() * lines) + (8 if expanded else 6)
        item.setSizeHint(QSize(0, height))

    def _current_executable_identity(self) -> tuple[str, str]:
        exe_path = os.path.abspath(sys.executable or "")
        if not exe_path or not os.path.exists(exe_path):
            return "", ""
        return exe_path, _file_sha256(exe_path).lower()

    def _should_hide_self_whitelist_entry(self, path: str, sha256: str) -> bool:
        if not self._self_exe_path or not self._self_exe_sha:
            return False
        candidate_path = os.path.abspath(str(path or "").strip())
        candidate_sha = str(sha256 or "").strip().lower()
        if not candidate_path or not candidate_sha:
            return False
        return (
            os.path.normcase(candidate_path) == os.path.normcase(self._self_exe_path)
            and candidate_sha == self._self_exe_sha
        )

    def _add_whitelist_list_item(self, path: str, sha256: str):
        item = QListWidgetItem(self._compact_whitelist_text(path))
        item.setData(
            Qt.ItemDataRole.UserRole,
            {
                "path": path,
                "sha256": str(sha256 or "").strip().lower(),
                "expanded": False,
            },
        )
        self._set_whitelist_item_size(item, expanded=False)
        self.whitelist_list.addItem(item)

    def _toggle_whitelist_item_details(self, item: QListWidgetItem):
        payload = item.data(Qt.ItemDataRole.UserRole) or {}
        path = str(payload.get("path", "")).strip()
        sha = str(payload.get("sha256", "")).strip().lower()
        expanded = bool(payload.get("expanded", False))
        if not path:
            return

        next_expanded = not expanded
        payload["expanded"] = next_expanded
        item.setData(Qt.ItemDataRole.UserRole, payload)
        if next_expanded:
            item.setText(self._expanded_whitelist_text(path, sha))
            self._set_whitelist_item_size(item, expanded=True)
        else:
            item.setText(self._compact_whitelist_text(path))
            self._set_whitelist_item_size(item, expanded=False)

    def accept(self):
        PangPreferences.recording_cooldown = self.cooldown_spin.value()
        PangPreferences.screen_recording_hide_enabled = not self.disable_recording_hide.isChecked()
        PangPreferences.tab_out_hide_enabled = not self.disable_tabbing_hide.isChecked()
        PangPreferences.session_cache_enabled = self.enable_session_cache.isChecked()
        PangPreferences.session_reauth_on_focus_loss = self.session_reauth_on_focus_loss.isChecked()
        PangPreferences.session_reauth_minutes = self.reauth_minutes_spin.value()
        PangPreferences.session_infocus_inactivity_reauth_enabled = self.infocus_reauth_enabled.isChecked()
        PangPreferences.session_infocus_inactivity_minutes = self.infocus_minutes_spin.value()
        PangPreferences.auto_delete_panic_files = self.auto_delete_panic.isChecked()

        PangPreferences.mem_guard_scan_interval_ms = self.scan_interval_spin.value()
        PangPreferences.mem_guard_pid_cache_cap = self.cache_cap_spin.value()
        requested_mode = self.mem_guard_combo.currentData()
        if not PangPreferences.session_cache_enabled or not _is_mem_guard_supported():
            PangPreferences.mem_guard_mode = MEM_GUARD_MODE_OFF
        else:
            PangPreferences.mem_guard_mode = _mem_guard_mode_to_storage_value(requested_mode)

        whitelist_items: list[dict] = []
        for i in range(self.whitelist_list.count()):
            item = self.whitelist_list.item(i)
            payload = item.data(Qt.ItemDataRole.UserRole) or {}
            path = str(payload.get("path", "")).strip()
            sha = str(payload.get("sha256", "")).strip().lower()
            if not path:
                raw = item.text()
                if " | " in raw:
                    _, maybe_path = raw.split(" | ", 1)
                    path = maybe_path.strip()
            if path:
                whitelist_items.append({"path": path, "sha256": sha})

        for hidden in self._hidden_self_whitelist_entries:
            hidden_path = os.path.abspath(str(hidden.get("path", "")).strip())
            hidden_sha = str(hidden.get("sha256", "")).strip().lower()
            if not hidden_path:
                continue
            exists = False
            for existing in whitelist_items:
                if (
                    os.path.normcase(os.path.abspath(str(existing.get("path", "")))) == os.path.normcase(hidden_path)
                    and str(existing.get("sha256", "")).strip().lower() == hidden_sha
                ):
                    exists = True
                    break
            if not exists:
                whitelist_items.append({"path": hidden_path, "sha256": hidden_sha})
        PangPreferences.mem_guard_whitelist = whitelist_items

        if self.tab_type_combo.currentIndex() == 0:
            PangPreferences.tab_setting = f"spaces{self.spaces_spin.value()}"
        else:
            PangPreferences.tab_setting = "tab"

        PangPreferences.save_preferences()
        super().accept()
