# 80PWNER — by Anas Mahfouz (The80)

from eightypwner.constants import APP_AUTHOR, APP_NAME, window_title


def test_window_title_no_binary():
    assert window_title(None) == APP_NAME


def test_window_title_with_binary():
    assert window_title("crackme.elf") == f"{APP_NAME} — crackme.elf"


def test_version_banner_branded():
    from eightypwner.constants import VERSION_BANNER

    assert APP_AUTHOR in VERSION_BANNER
    assert "80PWNER" in VERSION_BANNER
