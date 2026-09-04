"""Small SQLite-backed audit trail for API activity."""
from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
from pathlib import Path

AUDIT_DB = Path(os.getenv("AETHERMAP_AUDIT_DB", os.getenv("AETHERMAP_HISTORY_DB", "data/aethermap_history.sqlite3")))


def init_audit() -> None:
    AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(AUDIT_DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, status TEXT NOT NULL, request_id TEXT, details TEXT)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(occurred_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target)")


def record_audit(actor: str, action: str, target: str | None, outcome: str, request_id: str, details: dict | None = None) -> None:
    init_audit()
    with sqlite3.connect(AUDIT_DB) as db:
        db.execute("INSERT INTO audit_log(occurred_at, actor, action, target, status, request_id, details) VALUES(?,?,?,?,?,?,?)", (dt.datetime.now(dt.timezone.utc).isoformat(), actor, action, target, outcome, request_id, json.dumps(details or {}, sort_keys=True)))
