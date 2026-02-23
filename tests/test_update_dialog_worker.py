from types import SimpleNamespace

from pangcrypter.ui.update_dialog import UpdateCheckWorker


def test_update_check_worker_emits_success_signal():
    class _Updater:
        def check_for_updates_result(self):
            return SimpleNamespace(update_available=True, latest_version="9.9.9")

    received = []
    worker = UpdateCheckWorker(_Updater())
    worker.check_completed.connect(lambda available, version, error: received.append((available, version, error)))

    # Run directly for deterministic unit testing.
    worker.run()

    assert received == [(True, "9.9.9", "")]


def test_update_check_worker_emits_error_signal():
    class _Updater:
        def check_for_updates_result(self):
            raise OSError("network down")

    received = []
    worker = UpdateCheckWorker(_Updater())
    worker.check_completed.connect(lambda available, version, error: received.append((available, version, error)))

    worker.run()

    assert len(received) == 1
    assert received[0][0] is False
    assert received[0][1] == ""
    assert "network down" in received[0][2]
