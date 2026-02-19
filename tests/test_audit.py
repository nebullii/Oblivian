import json
import os

import pytest

from oblivian.audit import write_audit


def test_write_audit_creates_file(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("OBLIVIAN_AUDIT_PATH", str(log))
    write_audit({"tool_name": "read_file", "status": "allowed"})
    assert log.exists()


def test_write_audit_has_timestamp(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("OBLIVIAN_AUDIT_PATH", str(log))
    write_audit({"tool_name": "read_file", "status": "allowed"})
    record = json.loads(log.read_text())
    assert "ts" in record


def test_write_audit_merges_fields(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("OBLIVIAN_AUDIT_PATH", str(log))
    write_audit({"tool_name": "write_file", "status": "denied", "reason": "blocked"})
    record = json.loads(log.read_text())
    assert record["tool_name"] == "write_file"
    assert record["status"] == "denied"
    assert record["reason"] == "blocked"


def test_write_audit_appends(tmp_path, monkeypatch):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("OBLIVIAN_AUDIT_PATH", str(log))
    write_audit({"status": "allowed"})
    write_audit({"status": "denied"})
    lines = log.read_text().splitlines()
    assert len(lines) == 2


def test_write_audit_creates_parent_dirs(tmp_path, monkeypatch):
    log = tmp_path / "nested" / "deep" / "audit.log"
    monkeypatch.setenv("OBLIVIAN_AUDIT_PATH", str(log))
    write_audit({"status": "allowed"})
    assert log.exists()
