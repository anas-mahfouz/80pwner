# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Challenge library: SQLite sessions, notes and findings (Step 9 B).

One database per installation under the platform session directory. Each
"session" is one challenge/binary with notes, target fingerprint, checksec
snapshot and a list of findings; everything exports to Markdown for a writeup
or a HackerOne/Bugcrowd report.

Uses one short-lived SQLite connection per operation — worker-thread safe by
construction and no global state. Pure engine: no Qt.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eightypwner.platform.paths import session_dir

SEVERITIES = ("critical", "high", "medium", "low", "info")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    target_path   TEXT NOT NULL DEFAULT '',
    target_sha256 TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    bits          INTEGER NOT NULL DEFAULT 0,
    checksec      TEXT NOT NULL DEFAULT '[]',
    libc          TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'info',
    address    TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target_sha256)
    WHERE target_sha256 != '';
"""


@dataclass(frozen=True)
class SessionRow:
    id: int
    name: str
    target_path: str
    target_sha256: str
    arch: str
    bits: int
    notes: str
    libc: str
    created_at: float
    updated_at: float
    checksec: list[dict[str, str]]


@dataclass(frozen=True)
class FindingRow:
    id: int
    session_id: int
    title: str
    severity: str
    address: str
    detail: str
    created_at: float


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


class SessionStore:
    """CRUD over the session database. Every call opens its own connection."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else session_dir() / "80pwner.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------- sessions
    def create(
        self,
        name: str,
        target_path: str = "",
        target_sha256: str = "",
    ) -> int:
        now = time.time()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO sessions (name, target_path, target_sha256, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (name.strip() or "Untitled", target_path, target_sha256, now, now),
            )
            return int(cursor.lastrowid)

    def find_by_target(self, target_sha256: str) -> SessionRow | None:
        if not target_sha256:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE target_sha256 = ?", (target_sha256,)
            ).fetchone()
        return _to_session(row) if row else None

    def find_or_create_for_file(self, path: str | Path, name: str = "") -> int:
        """Session for this binary (by hash), created on first use."""
        digest = sha256_file(path)
        if digest:
            existing = self.find_by_target(digest)
            if existing is not None:
                return existing.id
        label = name or Path(path).name or "Untitled"
        return self.create(label, str(path), digest)

    def list_sessions(self) -> list[SessionRow]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY updated_at DESC, id DESC"
            ).fetchall()
        return [_to_session(row) for row in rows]

    def get(self, session_id: int) -> SessionRow | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (int(session_id),)
            ).fetchone()
        return _to_session(row) if row else None

    def rename(self, session_id: int, name: str) -> None:
        self._touch(session_id, "name = ?", (name.strip() or "Untitled",))

    def delete(self, session_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE id = ?", (int(session_id),))

    def set_notes(self, session_id: int, notes: str) -> None:
        self._touch(session_id, "notes = ?", (notes,))

    def set_meta(
        self,
        session_id: int,
        *,
        arch: str | None = None,
        bits: int | None = None,
        checksec: list[dict[str, str]] | None = None,
        libc: str | None = None,
    ) -> None:
        fields: list[str] = []
        values: list[Any] = []
        if arch is not None:
            fields.append("arch = ?")
            values.append(arch)
        if bits is not None:
            fields.append("bits = ?")
            values.append(int(bits))
        if checksec is not None:
            fields.append("checksec = ?")
            values.append(json.dumps(checksec, ensure_ascii=False))
        if libc is not None:
            fields.append("libc = ?")
            values.append(libc)
        if not fields:
            return
        self._touch(session_id, ", ".join(fields), tuple(values), touch=False)

    def _touch(
        self,
        session_id: int,
        assignment: str,
        values: tuple[Any, ...],
        *,
        touch: bool = True,
    ) -> None:
        if touch:
            assignment = f"{assignment}, updated_at = ?"
            values = (*values, time.time())
        with self._connect() as conn:
            conn.execute(
                f"UPDATE sessions SET {assignment} WHERE id = ?", (*values, int(session_id))
            )

    # ------------------------------------------------------------- findings
    def add_finding(
        self,
        session_id: int,
        title: str,
        severity: str = "info",
        address: str = "",
        detail: str = "",
    ) -> int:
        severity = severity.lower().strip()
        if severity not in SEVERITIES:
            severity = "info"
        now = time.time()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO findings (session_id, title, severity, address, detail, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (int(session_id), title.strip() or "Finding", severity, address, detail, now),
            )
            conn.execute(
                "UPDATE sessions SET updated_at = ? WHERE id = ?", (now, int(session_id))
            )
            return int(cursor.lastrowid)

    def list_findings(self, session_id: int) -> list[FindingRow]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ?"
                " ORDER BY CASE severity"
                "   WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
                "   WHEN 'low' THEN 3 ELSE 4 END, id",
                (int(session_id),),
            ).fetchall()
        return [_to_finding(row) for row in rows]

    def update_finding(
        self,
        finding_id: int,
        *,
        title: str | None = None,
        severity: str | None = None,
        address: str | None = None,
        detail: str | None = None,
    ) -> None:
        fields: list[str] = []
        values: list[Any] = []
        if title is not None:
            fields.append("title = ?")
            values.append(title)
        if severity is not None and severity.lower() in SEVERITIES:
            fields.append("severity = ?")
            values.append(severity.lower())
        if address is not None:
            fields.append("address = ?")
            values.append(address)
        if detail is not None:
            fields.append("detail = ?")
            values.append(detail)
        if not fields:
            return
        with self._connect() as conn:
            conn.execute(
                f"UPDATE findings SET {', '.join(fields)} WHERE id = ?",
                (*values, int(finding_id)),
            )

    def delete_finding(self, finding_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM findings WHERE id = ?", (int(finding_id),))

    # --------------------------------------------------------------- export
    def export_markdown(self, session_id: int) -> str:
        session = self.get(session_id)
        if session is None:
            raise KeyError(f"No session {session_id}")
        findings = self.list_findings(session_id)
        lines: list[str] = [
            f"# {session.name}",
            "",
            f"- **Target:** `{session.target_path or 'n/a'}`",
            f"- **SHA-256:** `{session.target_sha256 or 'n/a'}`",
            f"- **Arch:** {session.arch or '?'} / {session.bits or '?'}-bit",
            f"- **Libc:** {session.libc or 'n/a'}",
            "",
        ]
        if session.checksec:
            lines += ["## Checksec", "", "| Mitigation | Status |", "|---|---|"]
            for item in session.checksec:
                lines.append(
                    f"| {item.get('name', '?')} | {item.get('status', '?')} |"
                )
            lines.append("")
        lines += ["## Notes", "", session.notes.strip() or "_No notes yet._", ""]
        lines += ["## Findings", ""]
        if not findings:
            lines.append("_No findings recorded._")
        for finding in findings:
            head = f"### [{finding.severity.upper()}] {finding.title}"
            lines.append(head)
            lines.append("")
            if finding.address:
                lines.append(f"- Address: `{finding.address}`")
            if finding.detail:
                lines.append("")
                lines.append(finding.detail.strip())
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def export_json(self, session_id: int) -> str:
        session = self.get(session_id)
        if session is None:
            raise KeyError(f"No session {session_id}")
        payload = {
            "app": "80PWNER",
            "author": "The 80",
            "session": {
                "id": session.id,
                "name": session.name,
                "target_path": session.target_path,
                "target_sha256": session.target_sha256,
                "arch": session.arch,
                "bits": session.bits,
                "checksec": session.checksec,
                "libc": session.libc,
                "notes": session.notes,
                "created_at": session.created_at,
                "updated_at": session.updated_at,
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "address": f.address,
                    "detail": f.detail,
                    "created_at": f.created_at,
                }
                for f in self.list_findings(session_id)
            ],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)


def _to_session(row: sqlite3.Row) -> SessionRow:
    try:
        checksec = json.loads(row["checksec"] or "[]")
    except (ValueError, TypeError):
        checksec = []
    if not isinstance(checksec, list):
        checksec = []
    return SessionRow(
        id=int(row["id"]),
        name=str(row["name"]),
        target_path=str(row["target_path"]),
        target_sha256=str(row["target_sha256"]),
        arch=str(row["arch"]),
        bits=int(row["bits"]),
        notes=str(row["notes"]),
        libc=str(row["libc"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        checksec=checksec,
    )


def _to_finding(row: sqlite3.Row) -> FindingRow:
    return FindingRow(
        id=int(row["id"]),
        session_id=int(row["session_id"]),
        title=str(row["title"]),
        severity=str(row["severity"]),
        address=str(row["address"]),
        detail=str(row["detail"]),
        created_at=float(row["created_at"]),
    )
