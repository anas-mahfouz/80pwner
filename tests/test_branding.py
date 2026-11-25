# 80PWNER — by Anas Mahfouz (The 80)

from eightypwner.constants import APP_AUTHOR, APP_NAME, window_title


def test_window_title_no_binary():
    assert window_title(None) == APP_NAME


def test_window_title_with_binary():
    assert window_title("crackme.elf") == f"{APP_NAME} — crackme.elf"


def test_version_banner_branded():
    from eightypwner.constants import APP_COPYRIGHT, FOOTER_TEXT, VERSION_BANNER

    assert APP_AUTHOR in VERSION_BANNER
    assert "80PWNER" in VERSION_BANNER
    assert APP_COPYRIGHT in VERSION_BANNER
    assert "MIT" in VERSION_BANNER
    assert "The 80" in FOOTER_TEXT


def test_copyright_names_the_author():
    from eightypwner.constants import APP_COPYRIGHT, APP_HANDLE

    assert APP_HANDLE == "The 80"
    assert "Anas Mahfouz (The 80)" in APP_COPYRIGHT
    assert "2026" in APP_COPYRIGHT
