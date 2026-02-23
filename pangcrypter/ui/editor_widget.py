from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QKeyEvent, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import QMenu, QTextEdit

from ..utils.styles import EDITOR_FONT_SIZE_PT


class EditorWidget(QTextEdit):
    focusLost = pyqtSignal()

    def __init__(self, tab_setting: str = "spaces4"):
        super().__init__()
        self._is_html_mode = False
        self._global_font_size_pt = float(EDITOR_FONT_SIZE_PT)
        self.setAcceptRichText(False)
        self._tab_setting = tab_setting
        base_font = QFont("Segoe UI", int(round(self._global_font_size_pt)))
        base_font.setPointSizeF(self._global_font_size_pt)
        self.setFont(base_font)
        doc = self.document()
        if doc is not None:
            doc.setDefaultFont(base_font)

        self.shortcut_map: dict[tuple[int, Qt.KeyboardModifier], Callable[[], None]] = {
            (int(Qt.Key.Key_B), Qt.KeyboardModifier.ControlModifier): self.toggle_bold,
            (int(Qt.Key.Key_I), Qt.KeyboardModifier.ControlModifier): self.toggle_italic,
            (
                int(Qt.Key.Key_Greater),
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
            ): lambda: self.change_font_size(1),
            (
                int(Qt.Key.Key_Less),
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
            ): lambda: self.change_font_size(-1),
            (int(Qt.Key.Key_Space), Qt.KeyboardModifier.ControlModifier): self.reset_formatting,
            (int(Qt.Key.Key_BracketLeft), Qt.KeyboardModifier.ControlModifier): lambda: self.unindent_selection(
                self.get_tab_str()
            ),
            (int(Qt.Key.Key_BracketRight), Qt.KeyboardModifier.ControlModifier): lambda: self.indent_selection(
                self.get_tab_str()
            ),
            (int(Qt.Key.Key_Backtab), Qt.KeyboardModifier.NoModifier): lambda: self.unindent_selection(
                self.get_tab_str()
            ),
        }

    def _notify_plaintext_formatting_unavailable(self) -> None:
        parent = self.parent()
        status_bar = getattr(parent, "status_bar", None)
        if status_bar is not None and hasattr(status_bar, "showMessage"):
            status_bar.showMessage("Formatting actions are available only in HTML mode", 2500)

    def contextMenuEvent(self, e) -> None:
        menu = QMenu(self)

        undo_action = menu.addAction("Undo")
        if undo_action is not None:
            doc = self.document()
            undo_action.setEnabled(bool(doc and doc.isUndoAvailable()))
            undo_action.triggered.connect(self.undo)

        redo_action = menu.addAction("Redo")
        if redo_action is not None:
            doc = self.document()
            redo_action.setEnabled(bool(doc and doc.isRedoAvailable()))
            redo_action.triggered.connect(self.redo)

        menu.addSeparator()

        cut_action = menu.addAction("Cut")
        if cut_action is not None:
            cut_action.setEnabled(self.textCursor().hasSelection())
            cut_action.triggered.connect(self.cut)

        copy_action = menu.addAction("Copy")
        if copy_action is not None:
            copy_action.setEnabled(self.textCursor().hasSelection())
            copy_action.triggered.connect(self.copy)

        paste_action = menu.addAction("Paste")
        if paste_action is not None:
            paste_action.setEnabled(self.canPaste())
            paste_action.triggered.connect(self.paste)

        menu.addSeparator()

        select_all_action = menu.addAction("Select All")
        if select_all_action is not None:
            select_all_action.triggered.connect(self.selectAll)

        reset_fmt_action = menu.addAction("Reset Formatting")
        if reset_fmt_action is not None:
            reset_fmt_action.triggered.connect(self.reset_formatting)

        inc_font_action = menu.addAction("Increase Font Size")
        if inc_font_action is not None:
            inc_font_action.triggered.connect(lambda: self.change_font_size(1))

        dec_font_action = menu.addAction("Decrease Font Size")
        if dec_font_action is not None:
            dec_font_action.triggered.connect(lambda: self.change_font_size(-1))

        if e is not None:
            menu.exec(e.globalPos())

    def focusOutEvent(self, e) -> None:
        super().focusOutEvent(e)
        self.focusLost.emit()

    def set_tab_setting(self, value: str) -> None:
        self._tab_setting = value

    def set_content_mode(self, is_html_mode: bool) -> None:
        self._is_html_mode = bool(is_html_mode)
        self.setAcceptRichText(self._is_html_mode)

    def get_tab_str(self) -> str:
        if self._tab_setting.startswith("spaces"):
            return " " * int(self._tab_setting[6:])
        return "\t"

    def keyPressEvent(self, e: QKeyEvent | None) -> None:
        if e is None:
            return super().keyPressEvent(e)
        cursor = self.textCursor()
        key = e.key()
        modifiers = e.modifiers()

        handler = self.shortcut_map.get((key, modifiers))
        if handler:
            handler()
            return

        if key == int(Qt.Key.Key_Tab):
            tab_str = self.get_tab_str()
            if cursor.hasSelection():
                self.indent_selection(tab_str)
            else:
                self.insertPlainText(tab_str)
            return

        super().keyPressEvent(e)

    def indent_selection(self, tab_str: str) -> None:
        cursor = self.textCursor()
        if not cursor.hasSelection():
            cursor.insertText(tab_str)
            return

        start = cursor.selectionStart()
        end = cursor.selectionEnd()

        doc = self.document()
        if doc is None:
            return
        cursor.beginEditBlock()

        start_block = doc.findBlock(start)
        end_block = doc.findBlock(end)

        if end >= doc.characterCount() - 1 and end_block.isValid():
            pass
        else:
            if end_block.position() > end and end_block.blockNumber() > 0:
                end_block = doc.findBlock(end - 1)

        block = start_block
        while block.isValid() and block.position() <= end_block.position():
            block_cursor = QTextCursor(block)
            block_cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
            block_cursor.insertText(tab_str)
            block = block.next()

        cursor.endEditBlock()

    def unindent_selection(self, tab_str: str) -> None:
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return

        start = cursor.selectionStart()
        end = cursor.selectionEnd()

        doc = self.document()
        if doc is None:
            return
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
            elif tab_str.startswith(" "):
                spaces_to_remove = 0
                for ch in selected_text:
                    if ch == " " and spaces_to_remove < length:
                        spaces_to_remove += 1
                    else:
                        break
                if spaces_to_remove > 0:
                    block_cursor.setPosition(block_cursor.position() - length)
                    block_cursor.movePosition(
                        QTextCursor.MoveOperation.Right,
                        QTextCursor.MoveMode.KeepAnchor,
                        spaces_to_remove,
                    )
                    block_cursor.removeSelectedText()

            block = block.next()

        cursor.endEditBlock()

    def toggle_bold(self) -> None:
        if not self._is_html_mode:
            self._notify_plaintext_formatting_unavailable()
            return
        cursor = self.textCursor()
        if not cursor.hasSelection():
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

    def toggle_italic(self) -> None:
        if not self._is_html_mode:
            self._notify_plaintext_formatting_unavailable()
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

    def _effective_font_size_for_format(self, fmt: QTextCharFormat, fallback_cursor: QTextCursor) -> float:
        size = fmt.fontPointSize()
        if size and size > 0:
            return size

        block_fmt = fallback_cursor.block().charFormat()
        size = block_fmt.fontPointSize()
        if size and size > 0:
            return size

        size = self.font().pointSizeF()
        if size and size > 0:
            return size

        return float(EDITOR_FONT_SIZE_PT)

    def change_font_size(self, delta: float) -> None:
        if not self._is_html_mode:
            self._global_font_size_pt = max(8.0, min(36.0, self._global_font_size_pt + float(delta)))
            font = self.font()
            font.setPointSizeF(self._global_font_size_pt)
            self.setFont(font)
            doc = self.document()
            if doc is not None:
                doc.setDefaultFont(font)
            return

        cursor = self.textCursor()

        if not cursor.hasSelection():
            fmt = self.currentCharFormat()
            size = self._effective_font_size_for_format(fmt, cursor)
            new_size = max(1.0, size + delta)
            fmt.setFontPointSize(new_size)
            self.setCurrentCharFormat(fmt)
            return

        cursor.beginEditBlock()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        doc = self.document()
        if doc is None:
            return
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

    def reset_formatting(self) -> None:
        if not self._is_html_mode:
            self._notify_plaintext_formatting_unavailable()
            return
        cursor = self.textCursor()
        default_fmt = QTextCharFormat()

        if not cursor.hasSelection():
            self.setCurrentCharFormat(default_fmt)
            return

        cursor.beginEditBlock()
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        doc = self.document()
        if doc is None:
            return
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
