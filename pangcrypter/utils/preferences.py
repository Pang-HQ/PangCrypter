# preferences.py
from dataclasses import dataclass, asdict
import json
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QSpinBox, QCheckBox,
    QComboBox, QPushButton, QHBoxLayout
)

from .styles import DARK_BG, DARKER_BG, PURPLE, PURPLE_HOVER, TEXT_COLOR, BUTTON_TEXT, WARNING_COLOR
from PyQt6.QtCore import Qt

PREFERENCES_FILE = "preferences.json"

@dataclass
class Preferences:
    recording_cooldown: int = 30
    screen_recording_hide_enabled: bool = True
    tab_out_hide_enabled: bool = True
    tab_setting: str = "spaces4"  # e.g. "spaces4" or "tab"

    def load_preferences(self):
        try:
            with open(PREFERENCES_FILE, "r") as f:
                data = json.load(f)
                for key, value in data.items():
                    setattr(self, key, value)
        except Exception:
            # Could not load, use defaults
            pass

    def save_preferences(self):
        with open(PREFERENCES_FILE, "w") as f:
            json.dump(asdict(self), f, indent=4)

PangPreferences = Preferences()
PangPreferences.load_preferences()

class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self.resize(480, 400)
        self.setStyleSheet(f"background-color: {DARK_BG};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Styles
        label_style = f"""
            color: {TEXT_COLOR};
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 13px;
            margin-bottom: 6px;
        """

        checkbox_style = f"""
            QCheckBox {{
                spacing: 5px;
                color: {TEXT_COLOR};
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 13px;
            }}
            QCheckBox::indicator {{
                width: 14px;
                height: 14px;
                border-radius: 3px;  /* less round */
                border: 1.5px solid {PURPLE};
                background: {DARKER_BG};
            }}
            QCheckBox::indicator:checked {{
                background-color: {PURPLE};
                border: 1.5px solid {PURPLE};
            }}
            QCheckBox::indicator:checked:hover {{
                background-color: {PURPLE_HOVER};
                border: 1.5px solid {PURPLE_HOVER};
            }}
            QCheckBox::indicator:hover {{
                border: 1.5px solid {PURPLE_HOVER};
            }}
        """

        spinbox_style = f"""
            QSpinBox {{
                background-color: {DARKER_BG};
                border: 1px solid {PURPLE};
                border-radius: 4px;
                padding: 4px 8px;
                color: {TEXT_COLOR};
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 13px;
                min-height: 24px;
            }}
            QSpinBox::up-button {{
                width: 12px;
                height: 16px;
                border: none;
                margin-right: 10px;
                image: url(ui/dropup.svg);
            }}
            QSpinBox::down-button {{
                width: 12px;
                height: 16px;
                border: none;
                margin-right: 10px;
                image: url(ui/dropdown.svg);
            }}
        """

        tab_type_style = f"""
            QComboBox {{
                background-color: {DARKER_BG};
                border: 1px solid {PURPLE};
                border-radius: 4px;  /* less round */
                padding: 4px 8px;
                color: {TEXT_COLOR};
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 13px;
                min-height: 24px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
                subcontrol-origin: padding;
                subcontrol-position: top right;
            }}
            QComboBox::down-arrow {{
                image: url(ui/dropdown.svg);
                width: 12px;
                height: 16px;
                margin-right: 10px;
            }}
        """

        warning_style = f"""
            color: {WARNING_COLOR};
            font-weight: 600;
            font-size: 11px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin-top: 4px;
        """

        button_style = f"""
            padding: 6px 16px;
            font-weight: 600;
            background-color: {PURPLE};
            border: none;
            border-radius: 6px;
            color: {BUTTON_TEXT};
            min-width: 80px;
        """

        # --- Cooldown ---
        cooldown_label = QLabel("Cooldown for recording sessions (seconds):")
        cooldown_label.setStyleSheet(label_style)
        layout.addWidget(cooldown_label)

        self.cooldown_spin = QSpinBox()
        self.cooldown_spin.setRange(1, 300)
        self.cooldown_spin.setValue(PangPreferences.recording_cooldown)
        self.cooldown_spin.setStyleSheet(spinbox_style)
        layout.addWidget(self.cooldown_spin)

        # --- Checkboxes ---
        self.disable_recording_hide = QCheckBox("Disable hiding editor when recording detected")
        self.disable_recording_hide.setChecked(not PangPreferences.screen_recording_hide_enabled)
        self.disable_recording_hide.setStyleSheet(checkbox_style)
        layout.addWidget(self.disable_recording_hide)

        self.disable_tabbing_hide = QCheckBox("Disable hiding editor on tab out (unsafe)")
        self.disable_tabbing_hide.setChecked(not PangPreferences.tab_out_hide_enabled)
        self.disable_tabbing_hide.setStyleSheet(checkbox_style)
        layout.addWidget(self.disable_tabbing_hide)

        warning_label = QLabel("Warning: Disabling tab out hiding can be unsafe.")
        warning_label.setStyleSheet(warning_style)
        layout.addWidget(warning_label)

        # --- Tab character ---
        tab_label = QLabel("Tab character settings:")
        tab_label.setStyleSheet(label_style)
        layout.addWidget(tab_label)

        self.tab_type_combo = QComboBox()
        self.tab_type_combo.addItems(["Spaces", "Tab character"])
        self.tab_type_combo.setStyleSheet(tab_type_style)
        if PangPreferences.tab_setting.startswith("tab"):
            self.tab_type_combo.setCurrentIndex(1)
        else:
            self.tab_type_combo.setCurrentIndex(0)
        layout.addWidget(self.tab_type_combo)

        spaces_label = QLabel("Number of spaces per indent:")
        spaces_label.setStyleSheet(label_style)
        layout.addWidget(spaces_label)

        self.spaces_spin = QSpinBox()
        self.spaces_spin.setRange(1, 16)
        if PangPreferences.tab_setting.startswith("spaces"):
            try:
                n_spaces = int(PangPreferences.tab_setting[6:])
            except Exception:
                n_spaces = 4
        else:
            n_spaces = 4
        self.spaces_spin.setValue(n_spaces)
        self.spaces_spin.setStyleSheet(spinbox_style)
        layout.addWidget(self.spaces_spin)

        def update_spaces_spin_visibility(index):
            visible = index == 0
            self.spaces_spin.setVisible(visible)
            spaces_label.setVisible(visible)

        self.tab_type_combo.currentIndexChanged.connect(update_spaces_spin_visibility)
        update_spaces_spin_visibility(self.tab_type_combo.currentIndex())

        # --- Buttons ---
        buttons = QHBoxLayout()
        buttons.setSpacing(12)
        buttons.addStretch()

        ok_btn = QPushButton("OK")
        ok_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ok_btn.setStyleSheet(button_style)
        ok_btn.clicked.connect(self.accept)
        buttons.addWidget(ok_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.setStyleSheet(button_style)
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)

        layout.addLayout(buttons)

        # ADD THIS TO KEEP EVERYTHING AT THE TOP:
        layout.addStretch()

        self.setLayout(layout)

    def accept(self):
        PangPreferences.recording_cooldown = self.cooldown_spin.value()
        PangPreferences.screen_recording_hide_enabled = not self.disable_recording_hide.isChecked()
        PangPreferences.tab_out_hide_enabled = not self.disable_tabbing_hide.isChecked()

        if self.tab_type_combo.currentIndex() == 0:
            n = self.spaces_spin.value()
            PangPreferences.tab_setting = f"spaces{n}"
        else:
            PangPreferences.tab_setting = "tab"

        PangPreferences.save_preferences()
        super().accept()
