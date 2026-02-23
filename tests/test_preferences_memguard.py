import json
from collections import deque
from types import SimpleNamespace
from unittest.mock import patch

from pangcrypter.main import MainWindow
from pangcrypter.core.mem_guard_controller import MemGuardController
from pangcrypter.preferences.preferences import Preferences
import pangcrypter.utils.mem_guard as mem_guard
from pangcrypter.utils.mem_guard.etw_process_watcher import _is_process_start_event


class _FakeChecker:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


class _FakeThread:
    def __init__(self, wait_result=False):
        self.wait_result = wait_result
        self.quit_called = False

    def quit(self):
        self.quit_called = True

    def wait(self, _timeout):
        return self.wait_result


class _FakeStatusBar:
    def __init__(self):
        self.last_message = None

    def showMessage(self, message, _timeout=0):
        self.last_message = message


def test_preferences_migrates_legacy_file(monkeypatch, tmp_path):
    new_dir = tmp_path / "new_cfg"
    new_path = new_dir / "preferences.json"
    legacy_path = tmp_path / "legacy_preferences.json"
    legacy_payload = {"session_cache_enabled": False, "recording_cooldown": 42}
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")

    monkeypatch.setattr("pangcrypter.preferences.preferences.PREFERENCES_FILE", str(new_path))
    monkeypatch.setattr("pangcrypter.preferences.preferences.LEGACY_PREFERENCES_FILE", str(legacy_path))
    monkeypatch.setattr("pangcrypter.preferences.preferences.LEGACY_USER_CONFIG_FILES", [])

    prefs = Preferences()
    prefs.load_preferences()

    assert new_path.exists()
    assert prefs.session_cache_enabled is False
    assert prefs.recording_cooldown == 42

    prefs.recording_cooldown = 10
    prefs.save_preferences()
    saved = json.loads(new_path.read_text(encoding="utf-8"))
    assert saved["recording_cooldown"] == 10


def test_mem_guard_stop_failure_disables_until_restart(monkeypatch):
    host = SimpleNamespace(status_bar=_FakeStatusBar())
    prefs = SimpleNamespace(
        session_cache_enabled=True,
        mem_guard_mode="normal",
        mem_guard_whitelist=[],
        mem_guard_scan_interval_ms=50,
        mem_guard_pid_cache_cap=128,
    )
    logger = SimpleNamespace(error=lambda *a, **k: None, warning=lambda *a, **k: None)

    controller = MemGuardController(host, prefs, logger)
    controller._module_ready = True
    controller._api = {
        "is_mem_guard_supported": lambda: True,
        "MemGuardMode": mem_guard.MemGuardMode,
        "MemGuardChecker": mem_guard.MemGuardChecker,
        "file_sha256": lambda _p: "",
    }

    monkeypatch.setattr(controller, "stop", lambda: False)

    controller.configure()
    assert controller._disabled_until_restart is True
    assert "disabled until restart" in (host.status_bar.last_message or "")


def test_mem_guard_normal_write_trusted_system_is_log_only(monkeypatch):
    process_path = r"C:\Windows\System32\trusted.exe"
    stat_key: tuple[str, int, int] = (mem_guard._normalize_path(process_path), 1, 2)

    class _Proc:
        def name(self):
            return "trusted.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: True)

    signature_cache: dict[tuple[str, int, int], mem_guard.SigResult] = {
        stat_key: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0)
    }
    hash_cache: dict[tuple[str, int, int], str] = {stat_key: "abc"}
    finding = mem_guard.enrich_pid_finding(
        123,
        mem_guard.PROCESS_VM_WRITE,
        mem_guard.MemGuardMode.NORMAL,
        [],
        signature_cache,
        hash_cache,
    )

    assert finding is not None
    assert finding.severity == mem_guard.FindingSeverity.LOW
    assert finding.disposition == mem_guard.FindingDisposition.LOG_ONLY


def test_mem_guard_normal_read_trusted_non_system_alerts(monkeypatch):
    process_path = r"C:\Tools\overlay.exe"
    stat_key: tuple[str, int, int] = (mem_guard._normalize_path(process_path), 1, 2)

    class _Proc:
        def name(self):
            return "overlay.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: False)

    signature_cache: dict[tuple[str, int, int], mem_guard.SigResult] = {
        stat_key: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0)
    }
    hash_cache: dict[tuple[str, int, int], str] = {stat_key: "abc"}
    finding = mem_guard.enrich_pid_finding(
        234,
        mem_guard.PROCESS_VM_READ,
        mem_guard.MemGuardMode.NORMAL,
        [],
        signature_cache,
        hash_cache,
    )

    assert finding is not None
    assert finding.severity == mem_guard.FindingSeverity.MEDIUM
    assert finding.disposition == mem_guard.FindingDisposition.ALERT


def test_mem_guard_ultra_aggressive_keeps_write_only(monkeypatch):
    process_path = r"C:\Temp\proc.exe"
    stat_key: tuple[str, int, int] = (mem_guard._normalize_path(process_path), 1, 2)

    class _Proc:
        def name(self):
            return "proc.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))

    signature_cache: dict[tuple[str, int, int], mem_guard.SigResult] = {
        stat_key: mem_guard.SigResult(mem_guard.SigTrust.UNKNOWN, 0)
    }
    hash_cache: dict[tuple[str, int, int], str] = {stat_key: "abc"}
    finding = mem_guard.enrich_pid_finding(
        345,
        mem_guard.PROCESS_VM_WRITE,
        mem_guard.MemGuardMode.ULTRA_AGGRESSIVE,
        [],
        signature_cache,
        hash_cache,
    )

    assert finding is not None
    assert finding.severity == mem_guard.FindingSeverity.HIGH
    assert finding.disposition == mem_guard.FindingDisposition.ALERT


def test_mem_guard_debounce_is_per_pid_and_severity():
    checker = mem_guard.MemGuardChecker(
        mode=mem_guard.MemGuardMode.NORMAL,
        whitelist=[],
        alert_cooldown_sec=60,
    )

    assert checker._should_emit_alert(1001, mem_guard.FindingSeverity.MEDIUM) is True
    assert checker._should_emit_alert(1001, mem_guard.FindingSeverity.MEDIUM) is False
    assert checker._should_emit_alert(1001, mem_guard.FindingSeverity.HIGH) is True
    assert checker._should_emit_alert(2002, mem_guard.FindingSeverity.MEDIUM) is True


def test_nosignature_system_path_maps_to_unknown(monkeypatch):
    monkeypatch.setattr(mem_guard, "is_mem_guard_supported", lambda: True)
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: True)

    class _FakeWinDLL:
        def __init__(self, *_args, **_kwargs):
            def _f(*_a, **_k):
                return mem_guard.TRUST_E_NOSIGNATURE

            self.WinVerifyTrust = _f

    monkeypatch.setattr(mem_guard.ctypes, "WinDLL", lambda *_a, **_k: _FakeWinDLL())

    sig = mem_guard._signature_status_windows(r"C:\\Windows\\System32\\conhost.exe", cache_only=True)
    assert sig.trust == mem_guard.SigTrust.UNKNOWN


def test_parent_lineage_program_files_trusted_not_suspicious(monkeypatch):
    class _ChildProc:
        def ppid(self):
            return 500

    class _ParentProc:
        def ppid(self):
            return 0

        def name(self):
            return "Code.exe"

        def exe(self):
            return r"C:\\Program Files\\Microsoft VS Code\\Code.exe"

    def _proc_factory(pid):
        return _ChildProc() if int(pid) == 100 else _ParentProc()

    monkeypatch.setattr(mem_guard.psutil, "Process", _proc_factory)
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: False)
    monkeypatch.setattr(mem_guard, "_signature_status_with_fallback", lambda _p: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0))

    suspicious, lineage = mem_guard._assess_parent_lineage(100, {})
    assert suspicious is False
    assert "Code.exe" in lineage


def test_enrich_pid_finding_uses_normalized_stat_cache_key(monkeypatch):
    process_path = r"C:\Temp\Example.EXE"
    normalized_path = process_path.lower()
    stat_key: tuple[str, int, int] = (normalized_path, 1, 2)

    class _Proc:
        def name(self):
            return "Example.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))

    signature_cache: dict[tuple[str, int, int], mem_guard.SigResult] = {
        stat_key: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0)
    }
    hash_cache = {}

    finding = mem_guard.enrich_pid_finding(
        777,
        mem_guard.PROCESS_VM_READ,
        mem_guard.MemGuardMode.NORMAL,
        [],
        signature_cache,
        hash_cache,
    )

    assert finding is not None
    assert finding.sig_trust == mem_guard.SigTrust.SIGNED_TRUSTED


def test_enrich_pid_finding_skips_sha256_when_no_whitelist_hash(monkeypatch):
    process_path = r"C:\Temp\proc.exe"

    class _Proc:
        def name(self):
            return "proc.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: False)
    monkeypatch.setattr(mem_guard, "_signature_status_with_fallback", lambda _p: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0))

    called = {"sha": 0}

    def _sha(_path):
        called["sha"] += 1
        return "abc"

    monkeypatch.setattr(mem_guard, "file_sha256", _sha)

    signature_cache = {}
    hash_cache = {}

    finding = mem_guard.enrich_pid_finding(
        888,
        mem_guard.PROCESS_VM_READ,
        mem_guard.MemGuardMode.NORMAL,
        [],
        signature_cache,
        hash_cache,
    )

    assert finding is not None
    assert called["sha"] == 0


def test_mem_guard_alert_whitelist_path_compare_is_normalized():
    from pangcrypter.core.mem_guard_alert_controller import MemGuardAlertController

    class _FakeMsg:
        def __init__(self, _parent):
            self._continue = object()
            self._whitelist = object()
            self._exit = object()
            self._clicked = self._whitelist

        def setWindowTitle(self, _title):
            return None

        def setText(self, _text):
            return None

        def addButton(self, label, _role):
            if "Whitelist" in label:
                return self._whitelist
            if "Exit" in label:
                return self._exit
            return self._continue

        def setMinimumWidth(self, _w):
            return None

        def adjustSize(self):
            return None

        def buttons(self):
            return []

        def exec(self):
            return None

        def clickedButton(self):
            return self._clicked

        class StandardButton:
            Yes = 1
            No = 2

        @staticmethod
        def question(_parent, _title, _text, buttons=None, default=None):
            _ = (buttons, default)
            return _FakeMsg.StandardButton.Yes

    class _FakeEditor:
        def clear(self):
            return None

    class _FakePrivacy:
        def hide_editor_and_show_label(self):
            return None

        def try_restore_editor(self):
            return True

    class _FakePanic:
        def create_snapshot(self):
            return True

        def restore_snapshot(self):
            return True

    host = SimpleNamespace(
        editor=_FakeEditor(),
        privacy_guard=_FakePrivacy(),
        mem_guard_controller=SimpleNamespace(configure=lambda: None),
    )
    host.clear_cached_secrets = lambda: None
    host._ensure_panic_recovery_service = lambda: _FakePanic()
    host.close = lambda: None

    finding = SimpleNamespace(
        pid=1,
        severity=SimpleNamespace(value="high"),
        access_mask=0x10,
        process_name="TestProc",
        process_path=r"C:\Tools\Example.EXE",
        sha256="abc123",
    )

    existing_entry = {"path": r"c:\tools\example.exe", "sha256": "abc123"}
    fake_prefs = SimpleNamespace(
        mem_guard_whitelist=[existing_entry.copy()],
        save_preferences=lambda: None,
    )

    with patch("pangcrypter.core.mem_guard_alert_controller.PangMessageBox", _FakeMsg), patch(
        "pangcrypter.core.mem_guard_alert_controller.QMessageBox",
        SimpleNamespace(ButtonRole=SimpleNamespace(AcceptRole=0, DestructiveRole=1)),
    ), patch(
        "pangcrypter.core.mem_guard_alert_controller.PangPreferences",
        fake_prefs,
    ):
        controller = MemGuardAlertController(host)
        assert isinstance(controller._pending_findings, deque)
        controller.handle(finding)

    assert len(fake_prefs.mem_guard_whitelist) == 1


def test_etw_process_start_event_filter_logic():
    assert _is_process_start_event(1, 1) is True
    assert _is_process_start_event(0, 1) is True
    assert _is_process_start_event(1, 2) is False
    assert _is_process_start_event(2, 1) is False
