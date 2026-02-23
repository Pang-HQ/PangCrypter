from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QMessageBox

class PangMessageBox(QMessageBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setTextFormat(Qt.TextFormat.PlainText)

    def _prepare_layout(self):
        self.setMinimumWidth(460)
        label = self.findChild(QLabel, "qt_msgbox_label")
        if label is not None:
            label.setWordWrap(True)
        self.adjustSize()
        for btn in self.buttons():
            btn.setMinimumWidth(120)

    @staticmethod
    def information(parent, title, text, buttons=QMessageBox.StandardButton.Ok, defaultButton=QMessageBox.StandardButton.NoButton):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(buttons)
        if defaultButton != QMessageBox.StandardButton.NoButton:
            box.setDefaultButton(defaultButton)
        box._prepare_layout()
        return QMessageBox.StandardButton(box.exec())

    @staticmethod
    def warning(parent, title, text, buttons=QMessageBox.StandardButton.Ok, defaultButton=QMessageBox.StandardButton.NoButton):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(buttons)
        if defaultButton != QMessageBox.StandardButton.NoButton:
            box.setDefaultButton(defaultButton)
        box._prepare_layout()
        return QMessageBox.StandardButton(box.exec())

    @staticmethod
    def critical(parent, title, text, buttons=QMessageBox.StandardButton.Ok, defaultButton=QMessageBox.StandardButton.NoButton):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(buttons)
        if defaultButton != QMessageBox.StandardButton.NoButton:
            box.setDefaultButton(defaultButton)
        box._prepare_layout()
        return QMessageBox.StandardButton(box.exec())

    @staticmethod
    def question(parent, title, text, buttons=QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, defaultButton=QMessageBox.StandardButton.No):
        box = PangMessageBox(parent)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(buttons)
        box.setDefaultButton(defaultButton)
        box._prepare_layout()
        return QMessageBox.StandardButton(box.exec())
