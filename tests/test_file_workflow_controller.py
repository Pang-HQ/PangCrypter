from types import SimpleNamespace
from uuid import uuid4

from pangcrypter.core.file_workflow_controller import FileWorkflowController


def test_autosave_resets_secret_idle_timer_once():
    reset_calls = {"count": 0}

    class _Mutex:
        def tryLock(self):
            return True

        def unlock(self):
            return None

    class _SessionState:
        cached_password = "set"
        cached_usb_key = None
        cached_uuid = uuid4()

        def get_cached_password_bytes(self):
            return bytearray(b"pw")

        def get_cached_usb_key(self):
            return None

    host = SimpleNamespace(
        operation_mutex=_Mutex(),
        session_state=_SessionState(),
        saved_file_path="dummy.enc",
        document_service=SimpleNamespace(encrypt_file=lambda *args, **kwargs: None),
        _serialize_editor_content=lambda: b"hello",
        current_mode=object(),
        current_content_mode=0,
        _clear_temporary_bytes=lambda _v: None,
        reset_secret_idle_timer=lambda: reset_calls.__setitem__("count", reset_calls["count"] + 1),
    )

    controller = FileWorkflowController(host)
    controller.autosave()

    assert reset_calls["count"] == 1
