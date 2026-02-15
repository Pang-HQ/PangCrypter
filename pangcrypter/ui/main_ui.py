from PyQt6.QtWidgets import (
    QTextEdit, QVBoxLayout, QLabel, QDialog, QPushButton, QLineEdit, QComboBox, QMenu
)
from PyQt6.QtGui import QTextCursor, QKeyEvent, QTextCharFormat, QFont
from PyQt6.QtCore import pyqtSignal, Qt
from ..utils.styles import (
    DARK_BG, DARKER_BG, PURPLE, PURPLE_HOVER, TEXT_COLOR, DISABLED_TEXT_COLOR,
    BUTTON_TEXT, WARNING_COLOR, EDITOR_FONT_SIZE_PT
)

class EncryptModeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Encryption Mode")
        self.mode = None  # 0=password,1=key,2=both
        self.resize(400, 120)
        self.setStyleSheet(f"""
            background-color: {DARK_BG};
            color: {TEXT_COLOR};
        """)

        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        self.combo = QComboBox()
        self.combo.addItems(["Password only", "Password + USB key", "USB key only"])
        self.combo.setStyleSheet(f"""
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
        """)
        self.layout.addWidget(self.combo)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ok.setStyleSheet(f"""
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
        """)
        self.btn_ok.clicked.connect(self.accept)
        self.layout.addWidget(self.btn_ok, alignment=Qt.AlignmentFlag.AlignRight)
        self.setLayout(self.layout)

    def exec_(self):
        if super().exec():
            self.mode = self.combo.currentIndex()
            return True
        return False


class PasswordDialog(QDialog):
    def __init__(self, parent=None, warning=False):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.password = None
        self.resize(400, 140)
        self.setStyleSheet(f"""
            background-color: {DARK_BG};
            color: {TEXT_COLOR};
        """)

        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(12)

        if warning:
            warning_label = QLabel("⚠️ Remember this password. Data recovery is impossible if lost!")
            warning_label.setStyleSheet(f"color: {WARNING_COLOR}; font-weight: 600;")
            self.layout.addWidget(warning_label)

        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setStyleSheet(f"""
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
        """)
        self.layout.addWidget(self.edit)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ok.setStyleSheet(f"""
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
        """)
        self.btn_ok.clicked.connect(self.accept)
        self.layout.addWidget(self.btn_ok, alignment=Qt.AlignmentFlag.AlignRight)

        self.setLayout(self.layout)

    def exec_(self):
        if super().exec():
            self.password = self.edit.text()
            return True
        return False


class USBSelectDialog(QDialog):
    def __init__(self, usb_list: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select USB Key")
        self.selected_usb = None
        self.usb_list = usb_list  # List of drive strings
        self.resize(400, 140)
        self.setStyleSheet(f"""
            background-color: {DARK_BG};
            color: {TEXT_COLOR};
        """)
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        self.combo = QComboBox()
        for usb in usb_list:
            self.combo.addItem(usb)
        self.combo.setStyleSheet(f"""
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
        """)
        self.layout.addWidget(self.combo)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_ok.setStyleSheet(f"""
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
        """)
        self.btn_ok.clicked.connect(self.accept)
        self.layout.addWidget(self.btn_ok, alignment=Qt.AlignmentFlag.AlignRight)

        self.setLayout(self.layout)

    def exec_(self):
        if super().exec():
            index = self.combo.currentIndex()
            if index < 0:
                return False
            self.selected_usb = self.usb_list[index]
            return True
        return False


class EditorWidget(QTextEdit):
    focusLost = pyqtSignal()

    def __init__(self, tab_setting: str = "spaces4"):
        super().__init__()
        self._is_html_mode = False
        self._global_font_size_pt = float(EDITOR_FONT_SIZE_PT)
        self.setAcceptRichText(False)
        self._tab_setting = tab_setting
        base_font = QFont('Segoe UI', int(round(self._global_font_size_pt)))
        base_font.setPointSizeF(self._global_font_size_pt)
        self.setFont(base_font)
        self.document().setDefaultFont(base_font)

        # shortcut map
        self.shortcut_map = {
            # Ctrl shortcuts
            (Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier): self.toggle_bold,
            (Qt.Key.Key_I, Qt.KeyboardModifier.ControlModifier): self.toggle_italic,
            (Qt.Key.Key_Greater, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier): lambda: self.change_font_size(1),
            (Qt.Key.Key_Less, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier): lambda: self.change_font_size(-1),
            (Qt.Key.Key_Space, Qt.KeyboardModifier.ControlModifier): self.reset_formatting,

            # Indentation
            (Qt.Key.Key_BracketLeft, Qt.KeyboardModifier.ControlModifier): lambda: self.unindent_selection(self.get_tab_str()),
            (Qt.Key.Key_BracketRight, Qt.KeyboardModifier.ControlModifier): lambda: self.indent_selection(self.get_tab_str()),
            (Qt.Key.Key_Backtab, Qt.KeyboardModifier.NoModifier): lambda: self.unindent_selection(self.get_tab_str()),
        }
    
    def contextMenuEvent(self, event):
        menu = QMenu(self)

        # Undo / Redo
        undo_action = menu.addAction("Undo")
        undo_action.setEnabled(self.document().isUndoAvailable())
        undo_action.triggered.connect(self.undo)

        redo_action = menu.addAction("Redo")
        redo_action.setEnabled(self.document().isRedoAvailable())
        redo_action.triggered.connect(self.redo)

        menu.addSeparator()

        # Cut / Copy / Paste
        cut_action = menu.addAction("Cut")
        cut_action.setEnabled(self.textCursor().hasSelection())
        cut_action.triggered.connect(self.cut)

        copy_action = menu.addAction("Copy")
        copy_action.setEnabled(self.textCursor().hasSelection())
        copy_action.triggered.connect(self.copy)

        paste_action = menu.addAction("Paste")
        paste_action.setEnabled(self.canPaste())
        paste_action.triggered.connect(self.paste)

        menu.addSeparator()

        # Select All
        select_all_action = menu.addAction("Select All")
        select_all_action.triggered.connect(self.selectAll)

        # Optional: Reset Formatting
        reset_fmt_action = menu.addAction("Reset Formatting")
        reset_fmt_action.triggered.connect(self.reset_formatting)

        # Optional: Increase/Decrease font size
        inc_font_action = menu.addAction("Increase Font Size")
        inc_font_action.triggered.connect(lambda: self.change_font_size(1))

        dec_font_action = menu.addAction("Decrease Font Size")
        dec_font_action.triggered.connect(lambda: self.change_font_size(-1))

        menu.exec(event.globalPos())

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        self.focusLost.emit()

    def set_tab_setting(self, value):
        self._tab_setting = value

    def set_content_mode(self, is_html_mode: bool):
        self._is_html_mode = bool(is_html_mode)
        self.setAcceptRichText(self._is_html_mode)

    # Basic key commands handled automatically by QTextEdit:
    # Ctrl+Arrow, Ctrl+Delete, Ctrl+Backspace, Ctrl+Z/Y already supported

    def get_tab_str(self):
        if self._tab_setting.startswith("spaces"):
            return ' ' * int(self._tab_setting[6:])
        return '\t'

    def keyPressEvent(self, event: QKeyEvent):
        cursor = self.textCursor()
        key = event.key()
        modifiers = event.modifiers()

        # Shortcut map lookup
        handler = self.shortcut_map.get((key, modifiers))
        if handler:
            handler()
            return

        # Special handling for Tab key (depends on selection)
        if key == Qt.Key.Key_Tab:
            tab_str = self.get_tab_str()
            if cursor.hasSelection():
                self.indent_selection(tab_str)
            else:
                self.insertPlainText(tab_str)
            return

        super().keyPressEvent(event)

    def indent_selection(self, tab_str):
        cursor = self.textCursor()
        if not cursor.hasSelection():
            cursor.insertText(tab_str)
            return

        start = cursor.selectionStart()
        end = cursor.selectionEnd()

        doc = self.document()
        cursor.beginEditBlock()

        start_block = doc.findBlock(start)
        end_block = doc.findBlock(end)

        # If selection end is at document end, ensure last block is included
        if end >= doc.characterCount() - 1 and end_block.isValid():
            # Already last block included, no change needed
            pass
        else:
            # If end is at the start of a block, but no characters selected in that block,
            # consider the previous block as the end_block
            if end_block.position() > end and end_block.blockNumber() > 0:
                end_block = doc.findBlock(end - 1)

        block = start_block
        while block.isValid() and block.position() <= end_block.position():
            block_cursor = QTextCursor(block)
            block_cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
            block_cursor.insertText(tab_str)
            block = block.next()

        cursor.endEditBlock()

    def unindent_selection(self, tab_str):
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return

        start = cursor.selectionStart()
        end = cursor.selectionEnd()

        doc = self.document()
        cursor.beginEditBlock()

        start_block = doc.findBlock(start)
        end_block = doc.findBlock(end)

        if end >= doc.characterCount() - 1 and end_block.isValid():
            pass
        else:
            if end_block.position() > end and end_block.blockNumber() > 0:
                end_block = doc.findBlock(end - 1)

        block = start_block
        length = len(tab_str)

        while block.isValid() and block.position() <= end_block.position():
            block_cursor = QTextCursor(block)
            block_cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)

            block_cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, length)
            selected_text = block_cursor.selectedText()

            if selected_text == tab_str:
                block_cursor.removeSelectedText()
            elif tab_str.startswith(' '):
                spaces_to_remove = 0
                for ch in selected_text:
                    if ch == ' ' and spaces_to_remove < length:
                        spaces_to_remove += 1
                    else:
                        break
                if spaces_to_remove > 0:
                    block_cursor.setPosition(block_cursor.position() - length)
                    block_cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, spaces_to_remove)
                    block_cursor.removeSelectedText()

            block = block.next()

        cursor.endEditBlock()
    
    def toggle_bold(self):
        if not self._is_html_mode:
            return
        cursor = self.textCursor()
        if not cursor.hasSelection():
            # toggle bold at current position, affects next typed char
            fmt = self.currentCharFormat()
            fmt.setFontWeight(QFont.Weight.Bold if fmt.fontWeight() != QFont.Weight.Bold else QFont.Weight.Normal)
            self.setCurrentCharFormat(fmt)
        else:
            fmt = QTextCharFormat()
            current_weight = cursor.charFormat().fontWeight()
            new_weight = QFont.Weight.Normal if current_weight == QFont.Weight.Bold else QFont.Weight.Bold
            fmt.setFontWeight(new_weight)
            cursor.mergeCharFormat(fmt)
            self.mergeCurrentCharFormat(fmt)

    def toggle_italic(self):
        if not self._is_html_mode:
            return
        cursor = self.textCursor()
        if not cursor.hasSelection():
            fmt = self.currentCharFormat()
            fmt.setFontItalic(not fmt.fontItalic())
            self.setCurrentCharFormat(fmt)
        else:
            fmt = QTextCharFormat()
            current_italic = cursor.charFormat().fontItalic()
            fmt.setFontItalic(not current_italic)
            cursor.mergeCharFormat(fmt)
            self.mergeCurrentCharFormat(fmt)

    def _effective_font_size_for_format(self, fmt: QTextCharFormat, fallback_cursor: QTextCursor):
        """Return an effective point-size for a char format (with fallbacks)."""
        size = fmt.fontPointSize()
        if size and size > 0:
            return size

        # Try the block's char format
        block_fmt = fallback_cursor.block().charFormat()
        size = block_fmt.fontPointSize()
        if size and size > 0:
            return size

        # Try widget font directly (matches EDITOR_FONT_SIZE if stylesheet is applied)
        size = self.font().pointSizeF()
        if size and size > 0:
            return size

        # config fallback
        return float(EDITOR_FONT_SIZE_PT)
    
    def change_font_size(self, delta):
        if not self._is_html_mode:
            self._global_font_size_pt = max(8.0, min(36.0, self._global_font_size_pt + float(delta)))
            font = self.font()
            font.setPointSizeF(self._global_font_size_pt)
            self.setFont(font)
            self.document().setDefaultFont(font)
            return

        cursor = self.textCursor()

        if not cursor.hasSelection():
            fmt = self.currentCharFormat()
            size = self._effective_font_size_for_format(fmt, cursor)
            new_size = max(1.0, size + delta)
            fmt.setFontPointSize(new_size)
            self.setCurrentCharFormat(fmt)

            # TODO: fix cursor not updating after changing size before typing
            # This is a known issue with QTextEdit, the cursor may not reflect the new size
            return

        cursor.beginEditBlock()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        doc = self.document()
        block = doc.findBlock(start)
        while block.isValid() and block.position() <= end:
            block_cursor = QTextCursor(block)
            block_start = block.position()
            block_end = block_start + block.length() - 1
            sel_start = max(start, block_start)
            sel_end = min(end, block_end)
            block_cursor.setPosition(sel_start)
            block_cursor.setPosition(sel_end, QTextCursor.MoveMode.KeepAnchor)

            fmt = block_cursor.charFormat()
            size = self._effective_font_size_for_format(fmt, block_cursor)
            new_size = max(1.0, size + delta)

            new_fmt = QTextCharFormat(fmt)
            new_fmt.setFontPointSize(new_size)
            block_cursor.mergeCharFormat(new_fmt)
            block = block.next()
        cursor.endEditBlock()

    def reset_formatting(self):
        if not self._is_html_mode:
            return
        cursor = self.textCursor()
        default_fmt = QTextCharFormat()  # no font size override

        if not cursor.hasSelection():
            self.setCurrentCharFormat(default_fmt)
            return

        cursor.beginEditBlock()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        doc = self.document()
        block = doc.findBlock(start)
        while block.isValid() and block.position() <= end:
            block_cursor = QTextCursor(block)
            block_start = block.position()
            block_end = block_start + block.length() - 1
            sel_start = max(start, block_start)
            sel_end = min(end, block_end)
            block_cursor.setPosition(sel_start)
            block_cursor.setPosition(sel_end, QTextCursor.MoveMode.KeepAnchor)
            block_cursor.setCharFormat(default_fmt)
            block = block.next()
        cursor.endEditBlock()
