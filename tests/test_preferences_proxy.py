from types import SimpleNamespace

from pangcrypter.preferences.proxy import PreferencesProxy
from pangcrypter.preferences.preferences import Preferences


def test_save_preferences_loads_before_save(monkeypatch):
    proxy = PreferencesProxy()
    called = {"saved": 0}

    def _fake_load_real_preferences():
        target = Preferences()
        target.save_preferences = lambda: called.__setitem__("saved", called["saved"] + 1)  # type: ignore[method-assign]
        proxy._target = target
        proxy._loaded = True

    monkeypatch.setattr(proxy, "_load_real_preferences", _fake_load_real_preferences)

    proxy.save_preferences()

    assert called["saved"] == 1


def test_preferences_allowlist_normalization():
    prefs = Preferences(screen_recording_allowlist=[" OBS64.exe ", "obs64.exe", "", "ShareX.exe"])
    prefs.normalize()
    assert prefs.screen_recording_allowlist == ["obs64.exe", "sharex.exe"]
