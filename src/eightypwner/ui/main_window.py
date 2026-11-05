# 80PWNER — by Anas Mahfouz (The80)

"""Main window: dockable layout, branding, status bar, theme toggle, drag & drop."""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QDockWidget,
    QLabel,
    QMainWindow,
    QStatusBar,
    QToolBar,
    QWidget,
)

from eightypwner.constants import APP_VERSION, FOOTER_TEXT, window_title
from eightypwner.core.event_bus import BINARY_DROPPED, BINARY_LOADED, OPEN_BINARY_REQUESTED
from eightypwner.core.session import SessionState
from eightypwner.ui.about_dialog import AboutDialog
from eightypwner.ui.logo import app_logo_pixmap
from eightypwner.ui.theme import ThemeManager

if TYPE_CHECKING:
    from eightypwner.core.event_bus import EventBus
    from eightypwner.core.settings import Settings
    from eightypwner.core.ui_dispatch import UiBus
    from eightypwner.modules.registry import PluginRegistry

log = logging.getLogger(__name__)

BINARY_SUFFIXES = {".elf", ".o", ".so", ".bin", ".out", "exe", ".axf", ""}


class FooterLabel(QLabel):
    """Clickable status-bar footer — opens the About dialog."""

    def __init__(self, text: str, on_click: Any) -> None:
        super().__init__(text)
        self.setProperty("role", "brandFooter")
        self.setToolTip("About 80PWNER")
        self._on_click = on_click

    def mousePressEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
        super().mousePressEvent(event)


class MainWindow(QMainWindow):
    """The 80PWNER main window — one target, synchronized docked modules."""

    def __init__(
        self,
        bus: UiBus | EventBus,
        theme: ThemeManager,
        registry: PluginRegistry,
        session: SessionState,
        settings: Settings,
    ) -> None:
        super().__init__()
        self.bus = bus  # subscribe() compatible — UiBus (cross-thread) or raw bus
        self.theme = theme
        self.registry = registry
        self.session = session
        self.settings = settings
        self.setWindowTitle(window_title(None))
        self.setWindowIcon(app_logo_pixmap(128))
        self.setAcceptDrops(True)
        self.setCentralWidget(QWidget())  # docks carry the UI; central stays spare

        self._dock_by_name: dict[str, QDockWidget] = {}

        self._build_toolbar()
        self._build_statusbar()
        self._build_menus()
        self._build_docks()

        QShortcut(QKeySequence("Ctrl+Shift+T"), self, self.theme.toggle)

        # The window reacts to the bus; it never reaches into plugin widgets.
        bus.subscribe(BINARY_LOADED, self._on_bus_event)
        bus.subscribe(BINARY_DROPPED, self._on_bus_event)
        theme.theme_changed.connect(lambda _t: self._refresh_theme_action())

    # -- construction --------------------------------------------------------
    def _build_menus(self) -> None:
        menubar = self.menuBar()
        menubar.setObjectName("menuBar")

        m_file = menubar.addMenu("&File")
        act_open = m_file.addAction("&Open Binary…")
        act_open.setShortcut(QKeySequence("Ctrl+O"))
        # The Binary Overview module owns parsing; the window just asks for a file.
        act_open.triggered.connect(
            lambda: self.bus.publish(OPEN_BINARY_REQUESTED, {})
        )
        act_settings = m_file.addAction("&Settings…")
        act_settings.setShortcut(QKeySequence("Ctrl+,"))
        act_settings.setEnabled(False)  # settings dialog lands in a later step
        m_file.addSeparator()
        act_quit = m_file.addAction("E&xit")
        act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        act_quit.triggered.connect(self.close)

        m_view = menubar.addMenu("&View")
        m_theme = m_view.addMenu("Theme")
        for mode in ("dark", "light", "system"):
            act = m_theme.addAction(mode.capitalize())
            act.triggered.connect(
                lambda checked=False, m=mode: self.theme.set_mode_persist(m)  # type: ignore[arg-type]
            )
        m_view.addSeparator()
        for plugin in self.registry.plugins:
            dock = self._dock_by_name.get(plugin.name)
            if dock is not None:
                m_view.addAction(dock.toggleViewAction())

        m_help = menubar.addMenu("&Help")
        act_about = m_help.addAction("About 80PWNER…")
        act_about.triggered.connect(self._show_about)

    def _build_toolbar(self) -> None:
        self.toolbar = QToolBar("Main")
        self.toolbar.setObjectName("mainToolBar")
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        # Theme toggle lives in the toolbar (Settings entry arrives with the dialog).
        self.theme_action = self.toolbar.addAction("")
        self.theme_action.triggered.connect(self.theme.toggle)
        self._refresh_theme_action()

    def _build_statusbar(self) -> None:
        status = QStatusBar()
        status.setObjectName("statusBar")
        self.setStatusBar(status)

        self.lbl_binary = QLabel("No binary loaded")
        self.lbl_arch = QLabel("")
        self.lbl_dbg = QLabel("")
        status.addWidget(self.lbl_binary)
        status.addWidget(self.lbl_arch)
        status.addWidget(self.lbl_dbg)

        version = QLabel(f"v{APP_VERSION}")
        version.setObjectName("statusVersion")
        status.addPermanentWidget(version)

        status.addPermanentWidget(FooterLabel(FOOTER_TEXT, self._show_about))

    def _build_docks(self) -> None:
        for plugin in self.registry.plugins:
            try:
                panel = plugin.widget()
            except Exception:
                log.exception("Plugin %r failed to build its widget", plugin.name)
                continue
            dock = QDockWidget(f"{plugin.icon} {plugin.name}".strip(), self)
            dock.setObjectName(plugin.name)  # stable objectName → layout saving works
            dock.setWidget(panel)
            self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)
            self._dock_by_name[plugin.name] = dock

        # Let theme-aware plugins know the module set (welcome's "loaded modules").
        self.bus.publish(
            "modules_loaded",
            {"plugins": [
                {"name": p.name, "icon": p.icon, "description": p.description}
                for p in self.registry.plugins
            ]},
        )

    # -- theme ---------------------------------------------------------------
    def _refresh_theme_action(self) -> None:
        label = "☀ Switch to light" if self.theme.resolved_mode() == "dark" else "🌙 Switch to dark"
        self.theme_action.setToolTip("Toggle dark/light — Ctrl+Shift+T")
        self.theme_action.setText(label)

    # -- bus events ------------------------------------------------------------
    def _on_bus_event(self, topic: str, payload: Any) -> None:
        """Track title/status from the bus — the single source of truth."""
        if topic == BINARY_LOADED:
            info = payload if isinstance(payload, dict) else {}
            name = info.get("name")
            arch = info.get("arch")
            model = info.get("model")
            if model is not None:
                self.session.binary_path = getattr(model, "path", None)
                name = name or model.name
                arch = arch or model.arch
            self.setWindowTitle(window_title(name))
            self.lbl_binary.setText(f"Binary: {name or '?'}")
            self.lbl_arch.setText(str(arch or ""))
        elif topic == BINARY_DROPPED and isinstance(payload, dict):
            log.info("Binary dropped: %s", payload.get("path"))

    # -- drag & drop -------------------------------------------------------------
    def dragEnterEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        urls = event.mimeData().urls()
        if urls:
            event.acceptProposedAction()

    def dropEvent(self, event: Any) -> None:  # noqa: N802 (Qt override)
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        log.info("Binary dropped: %s", path)
        self.bus.publish(BINARY_DROPPED, {"path": path, "icon": "📄"})

    # -- saved layout (spec §7) ----------------------------------------------------
    def restore_layout(self) -> None:
        geo_b64 = str(self.settings.get("window.geometry") or "")
        state_b64 = str(self.settings.get("window.dock_state") or "")
        if geo_b64:
            self.restoreGeometry(_b64_to_qba(geo_b64))
        if state_b64:
            self.restoreState(_b64_to_qba(state_b64))

    def save_layout(self) -> None:
        self.settings.set("window.geometry", _qba_to_b64(self.saveGeometry()))
        self.settings.set("window.dock_state", _qba_to_b64(self.saveState(0)))

    def _show_about(self) -> None:
        AboutDialog(self, tokens=dict(self.theme.theme().tokens)).exec()


def _qba_to_b64(qba: Any) -> str:
    return base64.b64encode(bytes(qba)).decode("ascii")


def _b64_to_qba(value: str) -> Any:
    from PySide6.QtCore import QByteArray

    return QByteArray(base64.b64decode(value))
