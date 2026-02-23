from pangcrypter.utils.screen_recording import ScreenRecordingChecker


def test_screen_recording_allowlist_blocks_detection_for_allowed_processes(monkeypatch):
    checker = ScreenRecordingChecker(check_interval=0, allowlist={"obs64.exe"})

    class _Proc:
        def __init__(self, name):
            self.info = {"name": name}

    monkeypatch.setattr(
        "pangcrypter.utils.screen_recording.psutil.process_iter",
        lambda _fields: [_Proc("obs64.exe")],
    )

    emitted = []
    checker.screen_recording_changed.connect(lambda is_recording: emitted.append(is_recording))

    # Run single loop iteration
    checker.running = False
    checker.run()

    assert emitted == []
