import json
from types import SimpleNamespace

from pangcrypter.main import MainWindow
from pangcrypter.utils.preferences import Preferences
import pangcrypter.utils.mem_guard as mem_guard


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

    monkeypatch.setattr("pangcrypter.utils.preferences.PREFERENCES_FILE", str(new_path))
    monkeypatch.setattr("pangcrypter.utils.preferences.LEGACY_PREFERENCES_FILE", str(legacy_path))
    monkeypatch.setattr("pangcrypter.utils.preferences.LEGACY_USER_CONFIG_FILES", [])

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
    mw = MainWindow.__new__(MainWindow)
    mw.mem_guard_checker = _FakeChecker()
    mw.mem_guard_thread = _FakeThread(wait_result=False)
    mw._mem_guard_disabled_until_restart = False
    mw.status_bar = _FakeStatusBar()

    monkeypatch.setattr("pangcrypter.main.PangPreferences", type("P", (), {"session_cache_enabled": True, "mem_guard_mode": "normal"})())
    monkeypatch.setattr("pangcrypter.main.is_mem_guard_supported", lambda: True)

    assert MainWindow._stop_mem_guard(mw) is False
    assert MainWindow._stop_mem_guard(mw) is False

    MainWindow._configure_mem_guard(mw)
    assert mw._mem_guard_disabled_until_restart is True
    assert "disabled until restart" in (mw.status_bar.last_message or "")


def test_mem_guard_normal_write_trusted_system_is_log_only(monkeypatch):
    process_path = r"C:\Windows\System32\trusted.exe"
    stat_key = (mem_guard._normalize_path(process_path), 1, 2)

    class _Proc:
        def name(self):
            return "trusted.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: True)

    signature_cache = {stat_key: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0)}
    hash_cache = {stat_key: "abc"}
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
    stat_key = (mem_guard._normalize_path(process_path), 1, 2)

    class _Proc:
        def name(self):
            return "overlay.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))
    monkeypatch.setattr(mem_guard, "_is_windows_system_path", lambda _p: False)

    signature_cache = {stat_key: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0)}
    hash_cache = {stat_key: "abc"}
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
    stat_key = (mem_guard._normalize_path(process_path), 1, 2)

    class _Proc:
        def name(self):
            return "proc.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))

    signature_cache = {stat_key: mem_guard.SigResult(mem_guard.SigTrust.UNKNOWN, 0)}
    hash_cache = {stat_key: "abc"}
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
    stat_key = (normalized_path, 1, 2)

    class _Proc:
        def name(self):
            return "Example.exe"

        def exe(self):
            return process_path

    monkeypatch.setattr(mem_guard.psutil, "Process", lambda _pid: _Proc())
    monkeypatch.setattr(mem_guard.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(mem_guard.os, "stat", lambda _p, *_a, **_k: SimpleNamespace(st_mtime=1, st_size=2))

    signature_cache = {stat_key: mem_guard.SigResult(mem_guard.SigTrust.SIGNED_TRUSTED, 0)}
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
