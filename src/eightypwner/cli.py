# 80PWNER — by Anas Mahfouz (The80)

"""Command-line entry point for 80PWNER."""

from __future__ import annotations

import argparse
import sys


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="80pwner",
        description="80PWNER — An Integrated GUI Pwn / Binary Analysis Workbench",
    )
    parser.add_argument("--version", action="store_true", help="print version banner and exit")
    parser.add_argument("--no-splash", action="store_true", help="skip the splash screen")
    parser.add_argument("--theme", choices=("dark", "light", "system"), help="override theme")
    parser.add_argument("--log-level", default="INFO", help="logging level (default INFO)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.version:
        from eightypwner.constants import VERSION_BANNER

        print(VERSION_BANNER)
        return 0

    import logging

    import eightypwner.logging_setup as logging_setup
    from eightypwner.platform.paths import migrate_legacy_config

    logging_setup.setup_logging(getattr(logging, args.log_level.upper(), logging.INFO))
    migrate_legacy_config()

    # GUI stack imports and their graceful failure (spec §8).
    try:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "80PWNER is missing PySide6.\n"
            "Install it with:  pip install PySide6\n"
            "(or: pipx install '80pwner[analysis]')",
            file=sys.stderr,
        )
        return 2

    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.session import SessionState
    from eightypwner.core.settings import Settings
    from eightypwner.core.ui_dispatch import UiBus
    from eightypwner.modules.interface import PluginContext
    from eightypwner.modules.registry import PluginRegistry
    from eightypwner.ui.main_window import MainWindow
    from eightypwner.ui.theme import ThemeManager

    # High-DPI + consistent chrome BEFORE QApplication exists.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # identical look on Windows/macOS/Linux (spec C)
    app.setApplicationName("80PWNER")
    app.setOrganizationName("The80")
    from eightypwner.ui.fonts import load_bundled_fonts

    load_bundled_fonts()

    settings = Settings()
    bus = EventBus()
    ui_bus = UiBus(bus)
    session = SessionState()
    theme = ThemeManager(settings)
    if args.theme:
        theme.set_mode_persist(args.theme)

    ctx = PluginContext(
        bus=bus, settings=settings, app_version="0.1.0", ui_bus=ui_bus, theme=theme, session=session
    )
    registry = PluginRegistry(ctx)
    registry.load_builtins()
    registry.load_external()

    window = MainWindow(ui_bus, theme, registry, session, settings)
    window.restore_layout()
    window.show()

    if not args.no_splash:
        from eightypwner.ui.splash import finish_splash, show_splash

        finish_splash(show_splash(), window)
    logging.getLogger(__name__).info("80PWNER ready")

    code = app.exec()
    window.save_layout()
    settings.save()
    registry.shutdown_all()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
