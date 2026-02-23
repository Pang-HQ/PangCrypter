from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QComboBox, QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout

from ..utils.styles import (
    BUTTON_TEXT,
    DARKER_BG,
    DARK_BG,
    PURPLE,
    PURPLE_HOVER,
    TEXT_COLOR,
    WARNING_COLOR,
)


class EncryptModeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Encryption Mode")
        self.mode: Optional[int] = None  # 0=password,1=both,2=key
        self.resize(400, 120)
        self.setStyleSheet(
            f"""
            background-color: {DARK_BG};
            color: {TEXT_COLOR};
        """
        )

        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.setSpacing(15)

        self.combo = QComboBox()
        self.combo.addItems(["Password only", "Password + USB key", "USB key only"])
        self.combo.setStyleSheet(
            f"""
            QComboBox {{
                background-color: {DARKER_BG};
                border: 1px solid {PURPLE};
                border-radius: 5px;
                padding: 5px 10px;
                color: {TEXT_COLOR};
            }}
            QComboBox:hover {{
                border-color: {PURPLE_HOVER};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
        """
        )
        self._layout.addWidget(self.combo)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ok.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {PURPLE};
                color: {BUTTON_TEXT};
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {PURPLE_HOVER};
            }}
        """
        )
        self.btn_ok.clicked.connect(self.accept)
        self._layout.addWidget(self.btn_ok, alignment=Qt.AlignmentFlag.AlignRight)
        self.setLayout(self._layout)

    def exec_(self) -> bool:
        if super().exec():
            self.mode = self.combo.currentIndex()
            return True
        return False


class PasswordDialog(QDialog):
    def __init__(self, parent=None, warning: bool = False, confirm: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.password: Optional[str] = None
        self._confirm_required = bool(confirm)
        self.resize(400, 140)
        self.setStyleSheet(
            f"""
            background-color: {DARK_BG};
            color: {TEXT_COLOR};
        """
        )

        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.setSpacing(12)

        if warning:
            warning_label = QLabel("⚠️ Remember this password. Data recovery is impossible if lost!")
            warning_label.setStyleSheet(f"color: {WARNING_COLOR}; font-weight: 600;")
            self._layout.addWidget(warning_label)

        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setStyleSheet(
            f"""
            QLineEdit {{
                background-color: {DARKER_BG};
                border: 1px solid {PURPLE};
                border-radius: 5px;
                padding: 6px 10px;
                color: {TEXT_COLOR};
            }}
            QLineEdit:focus {{
                border-color: {PURPLE_HOVER};
            }}
        """
        )
        self._layout.addWidget(self.edit)

        self.confirm_edit: Optional[QLineEdit] = None
        self.mismatch_label: Optional[QLabel] = None
        if self._confirm_required:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_edit.setPlaceholderText("Confirm password")
            self.confirm_edit.setStyleSheet(
                f"""
                QLineEdit {{
                    background-color: {DARKER_BG};
                    border: 1px solid {PURPLE};
                    border-radius: 5px;
                    padding: 6px 10px;
                    color: {TEXT_COLOR};
                }}
                QLineEdit:focus {{
                    border-color: {PURPLE_HOVER};
                }}
            """
            )
            self._layout.addWidget(self.confirm_edit)

            self.mismatch_label = QLabel("Passwords do not match")
            self.mismatch_label.setStyleSheet(f"color: {WARNING_COLOR};")
            self.mismatch_label.hide()
            self._layout.addWidget(self.mismatch_label)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ok.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {PURPLE};
                color: {BUTTON_TEXT};
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {PURPLE_HOVER};
            }}
        """
        )
        self.btn_ok.clicked.connect(self.accept)
        self._layout.addWidget(self.btn_ok, alignment=Qt.AlignmentFlag.AlignRight)

        self.edit.textChanged.connect(self._on_password_fields_changed)
        if self.confirm_edit is not None:
            self.confirm_edit.textChanged.connect(self._on_password_fields_changed)
        self._on_password_fields_changed()

        self.setLayout(self._layout)

    def _on_password_fields_changed(self) -> None:
        if not self._confirm_required:
            return
        password = self.edit.text()
        confirm_password = self.confirm_edit.text() if self.confirm_edit else ""
        mismatch = bool(confirm_password) and password != confirm_password
        if self.mismatch_label is not None:
            self.mismatch_label.setVisible(mismatch)
        self.btn_ok.setEnabled(bool(password) and bool(confirm_password) and not mismatch)

    def exec_(self) -> bool:
        if super().exec():
            self.password = self.edit.text()
            return True
        return False


class USBSelectDialog(QDialog):
    def __init__(self, usb_list: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select USB Key")
        self.selected_usb: Optional[str] = None
        self.usb_list = usb_list
        self.resize(400, 140)
        self.setStyleSheet(
            f"""
            background-color: {DARK_BG};
            color: {TEXT_COLOR};
        """
        )
        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.setSpacing(15)

        self.combo = QComboBox()
        for usb in usb_list:
            self.combo.addItem(usb)
        self.combo.setStyleSheet(
            f"""
            QComboBox {{
                background-color: {DARKER_BG};
                border: 1px solid {PURPLE};
                border-radius: 5px;
                padding: 5px 10px;
                color: {TEXT_COLOR};
            }}
            QComboBox:hover {{
                border-color: {PURPLE_HOVER};
            }}
        """
        )
        self._layout.addWidget(self.combo)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ok.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {PURPLE};
                color: {BUTTON_TEXT};
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {PURPLE_HOVER};
            }}
        """
        )
        self.btn_ok.clicked.connect(self.accept)
        self._layout.addWidget(self.btn_ok, alignment=Qt.AlignmentFlag.AlignRight)

        self.setLayout(self._layout)

    def exec_(self) -> bool:
        if super().exec():
            index = self.combo.currentIndex()
            if index < 0:
                return False
            self.selected_usb = self.usb_list[index]
            return True
        return False
