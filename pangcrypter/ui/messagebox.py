from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QMessageBox
from ..utils.styles import BUTTON_TEXT, DARKER_BG, PURPLE, PURPLE_HOVER, TEXT_COLOR

class PangMessageBox(QMessageBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.setStyleSheet(f"""
            QMessageBox {{
                background-color: {DARKER_BG};
                color: {TEXT_COLOR};
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 13px;
            }}
            QLabel {{
                color: {TEXT_COLOR};
                min-width: 420px;
            }}
            QPushButton {{
                background-color: {PURPLE};
                color: {TEXT_COLOR};
                border-radius: 5px;
                padding: 8px 14px;
                font-weight: 600;
                min-width: 140px;
            }}
            QPushButton:hover {{
                background-color: {PURPLE_HOVER};
            }}
            QPushButton:pressed {{
                background-color: {PURPLE};
                color: {BUTTON_TEXT};
            }}
        """)
        self.setTextFormat(Qt.TextFormat.PlainText)

    def _prepare_layout(self):
        self.setMinimumWidth(560)
        label = self.findChild(QLabel, "qt_msgbox_label")
        if label is not None:
            label.setWordWrap(True)
        self.adjustSize()
        for btn in self.buttons():
            btn.setMinimumWidth(160)

    @staticmethod
    def information(parent, title, text):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setDefaultButton(QMessageBox.StandardButton.Ok)
        box._prepare_layout()
        return box.exec()

    @staticmethod
    def warning(parent, title, text):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setDefaultButton(QMessageBox.StandardButton.Ok)
        box._prepare_layout()
        return box.exec()

    @staticmethod
    def critical(parent, title, text):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setDefaultButton(QMessageBox.StandardButton.Ok)
        box._prepare_layout()
        return box.exec()

    @staticmethod
    def question(parent, title, text, buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, default=QMessageBox.StandardButton.No):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(buttons)
        box.setDefaultButton(default)
        box._prepare_layout()
        return box.exec()
