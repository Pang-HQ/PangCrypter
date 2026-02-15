from __future__ import annotations

from PyQt6.QtWidgets import QApplication


APP_STYLESHEET = """
QMainWindow { background-color: #121212; color: #eee; }
QTextEdit {
    background-color: #121212;
    color: #ccc;
    border: 1px solid #6B21A8;
    border-radius: 6px;
    padding: 8px;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 14px;
}
QTextEdit:focus { border-color: #581C87; }
QMenuBar { background-color: #222; color: #eee; }
QMenuBar::item {
    background: transparent;
    padding: 4px 10px;
    border-radius: 4px;
}
QMenuBar::item:selected {
    background-color: #3a3a46;
}
QMenuBar::item:pressed {
    background-color: #581C87;
}
QMenu {
    background-color: #222;
    color: #eee;
    border: 1px solid #6B21A8;
    padding: 5px;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 12px;
}
QMenu::item { padding: 4px 20px 4px 24px; }
QMenu::item:selected { background-color: #581C87; }
QMenu::item:disabled { color: #888; }
QPushButton { background-color: #333; color: #eee; border-radius: 5px; padding: 5px; }
QPushButton:hover { background-color: #555; }
QLineEdit, QComboBox {
    background-color: #222;
    color: #eee;
    border: 1px solid #555;
    border-radius: 3px;
    padding: 3px;
}

QLabel#StatusMetaLabel {
    color: #8b8b8b;
    padding-right: 10px;
}

QLabel#HiddenNoticeLabel {
    color: #ccc;
    background-color: #1f1f25;
    font-size: 13px;
    padding: 12px 14px;
    border: 1.5px solid #6B21A8;
    border-radius: 6px;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

QMessageBox {
    background-color: #1f1f25;
    color: #ccc;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 13px;
}
QMessageBox QLabel {
    color: #ccc;
    min-width: 420px;
}
QMessageBox QPushButton {
    background-color: #6B21A8;
    color: #ccc;
    border-radius: 5px;
    padding: 8px 14px;
    font-weight: 600;
    min-width: 140px;
}
QMessageBox QPushButton:hover { background-color: #581C87; }
QMessageBox QPushButton:pressed {
    background-color: #6B21A8;
    color: #eee;
}
"""


def apply_app_stylesheet(app: QApplication) -> None:
    app.setStyleSheet(APP_STYLESHEET)
