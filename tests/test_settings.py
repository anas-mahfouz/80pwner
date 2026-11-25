# 80PWNER — by Anas Mahfouz (The 80)

from pathlib import Path

from eightypwner.core.settings import Settings


def test_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    s = Settings()
    assert s.get("theme.mode") == "dark"
    assert s.get("font.mono_size") == 12


def test_save_and_reload_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    s = Settings()
    s.set("theme.mode", "light")
    s.save()

    s2 = Settings()
    assert s2.get("theme.mode") == "light"
    assert (tmp_path / "settings.json").exists()


def test_watcher_called_on_set(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    s = Settings()
    seen = []
    s.watch("theme.mode", lambda k, v: seen.append(v))
    s.set("theme.mode", "system")
    assert seen == ["system"]


def test_corrupt_settings_fall_back_to_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    (tmp_path / "settings.json").write_text("{ not json", encoding="utf-8")
    s = Settings()
    assert s.get("theme.mode") == "dark"


def test_config_dir_layout(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGHTYPWNER_HOME", str(tmp_path))
    from eightypwner.core.settings import log_dir, settings_path

    assert settings_path() == tmp_path / "settings.json"
    assert log_dir().name == "logs" and log_dir().parent == Path(tmp_path)
