from PyQt6.QtWidgets import QMessageBox
from ..utils.styles import *

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
            }}
            QPushButton {{
                background-color: {PURPLE};
                color: {TEXT_COLOR};
                border-radius: 5px;
                padding: 8px 20px;
                font-weight: 600;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {PURPLE_HOVER};
            }}
            QPushButton:pressed {{
                background-color: {PURPLE};
                color: {BUTTON_TEXT};
            }}
        """)

    @staticmethod
    def information(parent, title, text):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setDefaultButton(QMessageBox.StandardButton.Ok)
        return box.exec()

    @staticmethod
    def warning(parent, title, text):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setDefaultButton(QMessageBox.StandardButton.Ok)
        return box.exec()

    @staticmethod
    def critical(parent, title, text):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setDefaultButton(QMessageBox.StandardButton.Ok)
        return box.exec()

    @staticmethod
    def question(parent, title, text, buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, default=QMessageBox.StandardButton.No):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(buttons)
        box.setDefaultButton(default)
        return box.exec()
