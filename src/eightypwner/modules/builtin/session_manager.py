# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Challenge Library dock (Step 9 B / Step 10) — sessions, notes, findings.

Every binary gets a session keyed by SHA-256: notes autosave, findings carry a
severity and address, and the whole thing exports to Markdown (writeup) or JSON
(pipeline). Data lives in a single SQLite database under the app data dir.
"""

from __future__ import annotations

import logging
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from eightypwner.core.event_bus import ADDRESS_SELECTED, BINARY_CLOSED, BINARY_LOADED
from eightypwner.core.session_store import SEVERITIES, SessionStore
from eightypwner.modules.builtin.common import (
    copy_text,
    elide,
    make_table,
    mono_font,
    parse_int,
    set_row,
)
from eightypwner.modules.interface import Plugin

log = logging.getLogger(__name__)

AUTOSAVE_MS = 800


class SessionPlugin(Plugin):
    name = "Challenges"
    description = (
        "Per-binary sessions with notes, findings and Markdown/JSON export — "
        "the writeup starts here."
    )
    icon = "🗂"

    def __init__(self, ctx: Any) -> None:
        super().__init__(ctx)
        self._panel: QWidget | None = None
        self._store: SessionStore | None = None
        self._session_id: int | None = None
        self._loading = False
        self._dirty = False
        self._rows: list[Any] = []
        self._pending_binary: Any = None

    # ------------------------------------------------------------------ widget
    def widget(self) -> QWidget:
        if self._panel is not None:
            return self._panel
        panel = QWidget()
        self._panel = panel
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(4)

        top = QHBoxLayout()
        new_button = QPushButton("New from binary")
        new_button.setToolTip("Create or reuse the session for the loaded binary")
        new_button.clicked.connect(self._new_from_binary)
        top.addWidget(new_button)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh_sessions)
        top.addWidget(refresh)
        delete = QPushButton("Delete")
        delete.clicked.connect(self._delete_session)
        top.addWidget(delete)
        export_md = QPushButton("Export .md")
        export_md.clicked.connect(lambda: self._export("md"))
        top.addWidget(export_md)
        export_json = QPushButton("Export .json")
        export_json.clicked.connect(lambda: self._export("json"))
        top.addWidget(export_json)
        outer.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._list = QListWidget()
        self._list.setFont(mono_font(self.ctx.settings))
        self._list.currentItemChanged.connect(self._select_item)
        self._list.setMinimumWidth(160)
        splitter.addWidget(self._list)

        editor = QWidget()
        edit_layout = QVBoxLayout(editor)
        edit_layout.setContentsMargins(0, 0, 0, 0)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name:"))
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("Challenge name")
        self._name_edit.editingFinished.connect(self._rename_current)
        name_row.addWidget(self._name_edit, 1)
        self._meta = QLabel("")
        self._meta.setWordWrap(True)
        name_row.addWidget(self._meta, 1)
        edit_layout.addLayout(name_row)

        self._notes = QPlainTextEdit()
        self._notes.setFont(mono_font(self.ctx.settings))
        self._notes.setPlaceholderText(
            "Notes: mitigations, bug class, offsets, dead ends, chain plan…"
        )
        self._notes.textChanged.connect(self._notes_changed)
        edit_layout.addWidget(self._notes, 2)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        finding_row = QWidget()
        finding_layout = QHBoxLayout(finding_row)
        finding_layout.setContentsMargins(0, 0, 0, 0)
        self._finding_title = QLineEdit()
        self._finding_title.setPlaceholderText("Finding title (e.g. stack overflow in read_name)")
        finding_layout.addWidget(self._finding_title, 2)
        self._severity = QComboBox()
        self._severity.addItems(SEVERITIES)
        self._severity.setCurrentText("high")
        finding_layout.addWidget(self._severity)
        self._finding_addr = QLineEdit()
        self._finding_addr.setPlaceholderText("0x…")
        self._finding_addr.setMaximumWidth(110)
        finding_layout.addWidget(self._finding_addr)
        add = QPushButton("Add")
        add.clicked.connect(self._add_finding)
        finding_layout.addWidget(add)
        form.addRow("Finding:", finding_row)

        self._finding_detail = QLineEdit()
        self._finding_detail.setPlaceholderText("Detail / reproduction")
        form.addRow("Detail:", self._finding_detail)
        edit_layout.addLayout(form)

        actions = QHBoxLayout()
        use_offset = QPushButton("Use crash offset")
        use_offset.setToolTip("Paste the most recent Pattern Tool offset into the address field")
        use_offset.clicked.connect(self._fill_last_offset)
        actions.addWidget(use_offset)
        copy_md = QPushButton("Copy Markdown")
        copy_md.clicked.connect(self._copy_markdown)
        actions.addWidget(copy_md)
        self._status = QLabel("")
        self._status.setWordWrap(True)
        actions.addWidget(self._status, 1)
        edit_layout.addLayout(actions)

        self._findings = make_table(
            ["Severity", "Title", "Address"], settings=self.ctx.settings
        )
        self._findings.setSelectionBehavior(QListWidget.SelectionBehavior.SelectRows)
        self._findings.itemDoubleClicked.connect(self._finding_clicked)
        edit_layout.addWidget(self._findings, 1)
        splitter.addWidget(editor)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)
        outer.addWidget(splitter, 1)

        self._save_timer = QTimer(panel)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(AUTOSAVE_MS)
        self._save_timer.timeout.connect(self._save_notes)

        self._offset_timer = time.monotonic()
        self._last_offset: int | None = None
        self._refresh_sessions()
        return panel

    # --------------------------------------------------------------- lifecycle
    def initialize(self, parent: Any = None) -> None:
        try:
            self._store = SessionStore()
        except Exception as exc:  # pragma: no cover — permissions/disk
            log.exception("session store unavailable")
            with suppress(Exception):
                self._status.setText(f"⚠ Session database unavailable: {exc}")
            self._store = None
        subscribe = (
            self.ctx.ui_bus.subscribe if self.ctx.ui_bus is not None else self.ctx.bus.subscribe
        )
        self._unsub = subscribe("*", self.on_event)

    def shutdown(self) -> None:
        with suppress(Exception):
            self._unsub()
        self._save_notes(force=True)

    # ------------------------------------------------------------------ events
    def on_event(self, topic: str, payload: Any) -> None:
        if topic == BINARY_LOADED and isinstance(payload, dict):
            self._pending_binary = payload
            if self._panel is not None:
                self._auto_open_for_binary(payload)
            return
        if topic == BINARY_CLOSED:
            return
        if topic == "pattern_lookup_result" and isinstance(payload, dict):
            offset = payload.get("offset")
            if isinstance(offset, int) and offset > 0:
                self._last_offset = offset
            return

    # ------------------------------------------------------------------ session
    def _ensure_store(self) -> SessionStore | None:
        if self._store is None:
            try:
                self._store = SessionStore()
            except Exception as exc:  # pragma: no cover
                log.exception("session store unavailable")
                with suppress(Exception):
                    self._status.setText(f"⚠ {exc}")
                return None
        return self._store

    def _refresh_sessions(self) -> None:
        store = self._ensure_store()
        if store is None or self._panel is None:
            return
        self._loading = True
        try:
            rows = store.list_sessions()
        except Exception as exc:  # pragma: no cover
            log.exception("could not list sessions")
            self._status.setText(f"⚠ {exc}")
            rows = []
        self._rows = rows
        self._list.clear()
        current = self._session_id
        for row in rows:
            stamp = time.strftime("%m-%d %H:%M", time.localtime(row.updated_at or row.created_at))
            label = f"{row.name}  ·  {stamp}"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, row.id)
            item.setToolTip(f"{row.target_path or 'no target'}\n{row.target_sha256[:16]}")
            self._list.addItem(item)
            if current is not None and row.id == current:
                self._list.setCurrentItem(item)
        if current is None and rows:
            self._list.setCurrentRow(0)
        self._loading = False

    def _auto_open_for_binary(self, payload: dict[str, Any]) -> None:
        store = self._ensure_store()
        model = payload.get("model")
        path = getattr(model, "path", None) or payload.get("path")
        if store is None or not path:
            return
        try:
            session_id = store.find_or_create_for_file(str(path), getattr(model, "name", "") or "")
            checksec = [
                {"name": str(getattr(item, "name", "")), "status": str(getattr(item, "status", ""))}
                for item in (getattr(model, "checksec", []) or [])
            ]
            store.set_meta(
                session_id,
                arch=str(getattr(model, "arch", "") or ""),
                bits=int(getattr(model, "bits", 0) or 0),
                checksec=checksec,
            )
        except Exception as exc:  # pragma: no cover
            log.exception("could not open session for %s", path)
            with suppress(Exception):
                self._status.setText(f"⚠ {exc}")
            return
        self._session_id = session_id
        self._refresh_sessions()
        self._load_session(session_id)
        with suppress(Exception):
            self._status.setText(f"Session ready for {elide(Path(path).name, 40)}.")

    def _new_from_binary(self) -> None:
        if isinstance(self._pending_binary, dict):
            self._auto_open_for_binary(self._pending_binary)
            return
        self._status.setText("Load a binary first (or pick a session from the list).")

    def _select_item(self, current: QListWidgetItem | None, _previous: Any) -> None:
        if current is None or self._loading:
            return
        session_id = current.data(Qt.ItemDataRole.UserRole)
        if isinstance(session_id, int):
            self._save_notes(force=True)
            self._session_id = session_id
            self._load_session(session_id)

    def _load_session(self, session_id: int) -> None:
        store = self._ensure_store()
        panel = self._panel
        if store is None or panel is None:
            return
        try:
            session = store.get(session_id)
        except Exception as exc:  # pragma: no cover
            log.exception("could not load session %s", session_id)
            self._status.setText(f"⚠ {exc}")
            return
        if session is None:
            return
        self._loading = True
        try:
            self._name_edit.setText(session.name)
            self._notes.setPlainText(session.notes)
            meta = f"{session.arch or '?'}/{session.bits or '?'}-bit"
            if session.libc:
                meta += f" · libc {elide(session.libc, 24)}"
            self._meta.setText(meta)
            self._load_findings(session_id)
        finally:
            self._loading = False
        self._dirty = False

    def _rename_current(self) -> None:
        store = self._ensure_store()
        if store is None or self._session_id is None or self._loading:
            return
        name = self._name_edit.text().strip()
        if not name:
            return
        with suppress(Exception):
            store.rename(self._session_id, name)
            self._refresh_sessions()

    def _delete_session(self) -> None:
        store = self._ensure_store()
        if store is None or self._session_id is None:
            return
        session_id = self._session_id
        with suppress(Exception):
            store.delete(session_id)
        self._session_id = None
        self._name_edit.clear()
        self._notes.clear()
        self._findings.setRowCount(0)
        self._refresh_sessions()
        self._status.setText("Session deleted.")

    # ------------------------------------------------------------------- notes
    def _notes_changed(self) -> None:
        if self._loading:
            return
        self._dirty = True
        if self._panel is not None:
            self._save_timer.start()

    def _save_notes(self, *, force: bool = False) -> None:
        store = self._store
        if store is None or self._session_id is None:
            return
        if not self._dirty and not force:
            return
        text = self._notes.toPlainText()
        with suppress(Exception):
            store.set_notes(self._session_id, text)
            self._dirty = False
            if force:
                return
            self._status.setText("Notes saved.")

    # ---------------------------------------------------------------- findings
    def _load_findings(self, session_id: int) -> None:
        store = self._store
        if store is None:
            return
        self._findings.setRowCount(0)
        try:
            findings = store.list_findings(session_id)
        except Exception as exc:  # pragma: no cover
            log.exception("could not list findings")
            self._status.setText(f"⚠ {exc}")
            return
        self._findings.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            set_row(
                self._findings,
                row,
                [finding.severity, finding.title, finding.address],
                addr=parse_int(finding.address),
            )
            item = self._findings.item(row, 0)
            if item is not None:
                item.setData(Qt.ItemDataRole.UserRole, finding.id)

    def _add_finding(self) -> None:
        store = self._ensure_store()
        if store is None or self._session_id is None:
            self._status.setText("Pick or create a session first.")
            return
        title = self._finding_title.text().strip()
        if not title:
            self._status.setText("Give the finding a title.")
            return
        address = self._finding_addr.text().strip()
        parsed = parse_int(address)
        if parsed:
            address = hex(parsed)
        try:
            store.add_finding(
                self._session_id,
                title,
                self._severity.currentText(),
                address,
                self._finding_detail.text().strip(),
            )
        except Exception as exc:  # pragma: no cover
            log.exception("could not add finding")
            self._status.setText(f"⚠ {exc}")
            return
        self._finding_title.clear()
        self._finding_addr.clear()
        self._finding_detail.clear()
        self._load_findings(self._session_id)
        self._status.setText("Finding recorded.")

    def _fill_last_offset(self) -> None:
        if self._last_offset:
            self._finding_addr.setText(hex(self._last_offset))
            self._status.setText(f"Using Pattern Tool offset {self._last_offset}.")
        else:
            self._status.setText("No Pattern Tool offset yet — run a lookup first.")

    def _finding_clicked(self, item: Any, _column: int = 0) -> None:
        row = item.row()
        address_cell = self._findings.item(row, 2)
        address = parse_int(address_cell.text() if address_cell else "")
        if address:
            with suppress(Exception):
                self.ctx.bus.publish(ADDRESS_SELECTED, {"address": address})

    # ------------------------------------------------------------------ export
    def _export(self, kind: str) -> None:
        store = self._ensure_store()
        if store is None or self._session_id is None:
            self._status.setText("Pick a session first.")
            return
        self._save_notes(force=True)
        try:
            if kind == "md":
                text = store.export_markdown(self._session_id)
                suffix = ".md"
                filters = "Markdown (*.md)"
            else:
                text = store.export_json(self._session_id)
                suffix = ".json"
                filters = "JSON (*.json)"
        except Exception as exc:  # pragma: no cover
            log.exception("export failed")
            self._status.setText(f"⚠ {exc}")
            return
        session = store.get(self._session_id)
        stem = (session.name if session else "session") or "session"
        stem = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stem)[:60]
        path, _filter = QFileDialog.getSaveFileName(
            self._panel, "Export session", f"{stem}{suffix}", filters
        )
        if not path:
            return
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError as exc:
            self._status.setText(f"⚠ {exc}")
            return
        self._status.setText(f"Exported {path}")

    def _copy_markdown(self) -> None:
        store = self._store
        if store is None or self._session_id is None:
            return
        self._save_notes(force=True)
        with suppress(Exception):
            copy_text(store.export_markdown(self._session_id))
            self._status.setText("Markdown copied.")
