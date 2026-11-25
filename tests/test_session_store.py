# 80PWNER — by Anas Mahfouz (The 80)
# Copyright (c) 2026 Anas Mahfouz (The 80). MIT License.

"""Session database tests: CRUD, ordering, hashing and exports."""

from __future__ import annotations

import json
from pathlib import Path

from eightypwner.core.session_store import SessionStore, sha256_file


def make_store(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "sessions.db")


def test_schema_created(tmp_path):
    store = make_store(tmp_path)
    assert store.path.exists()
    assert store.list_sessions() == []


def test_create_and_get(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("babyrop", "/tmp/babyrop", "abc123")
    session = store.get(session_id)
    assert session is not None
    assert session.name == "babyrop"
    assert session.target_path == "/tmp/babyrop"
    assert session.target_sha256 == "abc123"
    assert session.created_at > 0
    assert session.updated_at >= session.created_at


def test_rename_and_notes(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("x")
    store.rename(session_id, "real name")
    store.set_notes(session_id, "offset 72\nwin = 0x4011a9")
    session = store.get(session_id)
    assert session is not None
    assert session.name == "real name"
    assert "win = 0x4011a9" in session.notes


def test_meta_roundtrip(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("meta")
    store.set_meta(
        session_id,
        arch="x86_64",
        bits=64,
        checksec=[{"name": "NX", "status": "disabled"}],
        libc="libc-2.31.so",
    )
    session = store.get(session_id)
    assert session.arch == "x86_64"
    assert session.bits == 64
    assert session.libc == "libc-2.31.so"
    assert session.checksec == [{"name": "NX", "status": "disabled"}]


def test_find_by_target(tmp_path):
    store = make_store(tmp_path)
    store.create("a", "/bin/a", "hash-a")
    found = store.find_by_target("hash-a")
    assert found is not None and found.name == "a"
    assert store.find_by_target("") is None
    assert store.find_by_target("missing") is None


def test_find_or_create_for_file(tmp_path):
    target = tmp_path / "chall"
    target.write_bytes(b"\x7fELF fake")
    store = make_store(tmp_path)
    digest = sha256_file(target)
    assert digest
    first = store.find_or_create_for_file(target, "chall")
    second = store.find_or_create_for_file(target, "chall")
    assert first == second
    session = store.get(first)
    assert session is not None
    assert session.target_sha256 == digest
    assert session.target_path == str(target)


def test_findings_ordered_and_cascaded(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("findings")
    store.add_finding(session_id, "low bug", "low", "0x1")
    store.add_finding(session_id, "critical bug", "critical", "0x2")
    store.add_finding(session_id, "info note", "info")
    store.add_finding(session_id, "medium bug", "medium")
    store.add_finding(session_id, "weird", "nonsense")  # clamped to info
    findings = store.list_findings(session_id)
    assert [f.severity for f in findings][:3] == ["critical", "medium", "low"]
    assert findings[-1].severity == "info"

    store.delete(session_id)
    assert store.get(session_id) is None
    assert store.list_findings(session_id) == []


def test_finding_update_and_delete(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("edit")
    finding_id = store.add_finding(session_id, "title", "low", "0x1", "detail")
    store.update_finding(
        finding_id, title="new title", severity="HIGH", address="0x2", detail="new"
    )
    finding = store.list_findings(session_id)[0]
    assert finding.title == "new title"
    assert finding.severity == "high"
    assert finding.address == "0x2"
    assert finding.detail == "new"
    store.delete_finding(finding_id)
    assert store.list_findings(session_id) == []


def test_export_markdown(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("writeup", "/tmp/chall", "deadbeef")
    store.set_meta(
        session_id,
        arch="x86_64",
        bits=64,
        checksec=[{"name": "PIE", "status": "disabled"}],
        libc="2.31",
    )
    store.set_notes(session_id, "Plan: ret2libc via puts leak.")
    store.add_finding(session_id, "stack overflow", "high", "0x4011a9", "gets(buf)")
    text = store.export_markdown(session_id)
    assert text.startswith("# writeup")
    assert "`deadbeef`" in text
    assert "| PIE | disabled |" in text
    assert "ret2libc via puts leak" in text
    assert "[HIGH] stack overflow" in text
    assert "`0x4011a9`" in text
    assert "2.31" in text


def test_export_markdown_empty_session(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("empty")
    text = store.export_markdown(session_id)
    assert "_No notes yet._" in text
    assert "_No findings recorded._" in text


def test_export_json(tmp_path):
    store = make_store(tmp_path)
    session_id = store.create("json", "/tmp/x", "cafe")
    store.add_finding(session_id, "bug", "critical", "0x1", "detail")
    payload = json.loads(store.export_json(session_id))
    assert payload["app"] == "80PWNER"
    assert payload["author"] == "The 80"
    assert payload["session"]["name"] == "json"
    assert payload["findings"][0]["severity"] == "critical"


def test_missing_session_export_raises(tmp_path):
    store = make_store(tmp_path)
    try:
        store.export_markdown(999)
    except KeyError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected KeyError")
