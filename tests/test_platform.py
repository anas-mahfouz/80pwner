# 80PWNER — by Anas Mahfouz (The80)

from pathlib import Path

import pytest

from eightypwner.platform import paths


def test_env_override_controls_all_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path))
    assert paths.config_dir() == tmp_path
    assert paths.session_dir() == tmp_path / "sessions"
    assert paths.log_dir() == tmp_path / "logs"


def test_platformdirs_layout_used_without_override(monkeypatch):
    monkeypatch.delenv(paths.ENV_HOME, raising=False)
    config = paths.config_dir()
    assert config.is_absolute() and "." not in config.name  # no hardcoded ~/.80pwner


def test_legacy_migration_moves_and_does_not_clobber(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    legacy = fake_home / paths.LEGACY_DIR_NAME
    legacy.mkdir(parents=True)
    (legacy / "settings.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("HOME", str(fake_home))  # legacy lookup uses Path.home()
    monkeypatch.setenv(paths.ENV_HOME, "")  # no override, no platformdirs clash

    target = paths.migrate_legacy_config()
    assert target == paths.config_dir()
    assert (target / "settings.json").exists()
    assert not legacy.exists()

    # Running again must not overwrite a directory that already exists.
    (target / "settings.json").write_text('{"theme.mode": "light"}', encoding="utf-8")
    assert paths.migrate_legacy_config() is None


@pytest.mark.skipif(not Path.home().exists(), reason="no HOME")
def test_legacy_probe_handles_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "new-home"))
    monkeypatch.setenv(paths.ENV_HOME, "")
    assert paths.legacy_config_dir() is None
