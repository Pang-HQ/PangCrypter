from PyQt6.QtWidgets import QApplication

from pangcrypter.ui.editor_widget import EditorWidget


class _ProbeEditor(EditorWidget):
    def __init__(self):
        super().__init__()
        self.notice_count = 0

    def _notify_plaintext_formatting_unavailable(self):
        self.notice_count += 1


def test_plaintext_formatting_actions_emit_user_affordance():
    app = QApplication.instance() or QApplication([])
    _ = app
    editor = _ProbeEditor()
    editor.set_content_mode(False)

    editor.toggle_bold()
    editor.toggle_italic()
    editor.reset_formatting()

    assert editor.notice_count == 3
