from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QMessageBox

class PangMessageBox(QMessageBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
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
