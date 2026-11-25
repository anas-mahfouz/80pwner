# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Packaging invariants: version drift, bundled assets, launcher entry points.

These catch the "works from a git clone but breaks from a wheel" class of bug
(e.g. assets missing from the wheel, pyproject version drifting from
``constants.APP_VERSION``, or the console script disappearing).
"""

from __future__ import annotations

import tomllib
from importlib import resources
from pathlib import Path

from eightypwner.constants import APP_AUTHOR, APP_VERSION

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_pyproject_version_matches_constants():
    assert _pyproject()["project"]["version"] == APP_VERSION


def test_pyproject_metadata_keeps_attribution():
    project = _pyproject()["project"]
    assert project["authors"][0]["name"] == APP_AUTHOR
    assert project["license"] == "MIT"
    assert project["requires-python"].startswith(">=3.11")


def test_console_script_is_declared():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts["80pwner"] == "eightypwner.cli:main"


def test_assets_are_real_package_resources():
    """importlib.resources must find the banner/theme/font data in any install."""
    banner = resources.files("eightypwner.assets").joinpath("banner.txt")
    assert banner.is_file() and banner.read_text(encoding="utf-8").strip()

    for mode in ("dark", "light"):
        qss = resources.files("eightypwner.assets.themes").joinpath(f"{mode}.qss")
        assert qss.is_file() and len(qss.read_text(encoding="utf-8")) > 100

    fonts = resources.files("eightypwner.assets.fonts")
    assert fonts.joinpath("JetBrainsMono-Regular.ttf").is_file()


def test_launchers_and_license_ship_with_the_source():
    assert (ROOT / "LICENSE").is_file()
    for launcher in ("80pwner", "80pwner.bat"):
        path = ROOT / launcher
        assert path.is_file(), f"{launcher} must ship with the project"
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "80PWNER" in text
        assert "The 80" in text


def test_pyinstaller_spec_targets_the_packaging_entry_script():
    spec = (ROOT / "packaging" / "80pwner.spec").read_text(encoding="utf-8")
    assert "run_80pwner.py" in spec
    assert "collect_data_files(\"eightypwner\")" in spec
    assert "name=\"80pwner\"" in spec
