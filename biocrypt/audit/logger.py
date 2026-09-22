"""Anti-Replay Audit Logger — Bio-Crypt Lock.

Writes one immutable row per authentication event to SQLite
(`biocrypt_audit.db`) capturing the full decision trace:

    session_id -> inputs -> component risks -> risk score -> tier ->
    OTP issued/entered/verdict -> replay flag -> unlock status

Each row is chained to the previous one with SHA-256 (hash-chained,
tamper-evident ledger): altering any historical row breaks every later
chain link, which `verify_chain()` detects. Also supports CSV export for
the report appendix.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

DB_NAME = "biocrypt_audit.db"
GENESIS = "0" * 64


@dataclass
class AuditRecord:
    """One complete authentication event."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = ""
    fp_score: float = 0.0
    rssi_dbm: float = 0.0
    failed_attempts: int = 0
    biometric_risk: float = 0.0
    proximity_risk: float = 0.0
    history_risk: float = 0.0
    risk_score: float = 0.0
    tier: str = ""
    otp_issued: bool = False
    otp_digits: int = 0
    otp_entered: str = ""
    otp_valid: bool = False
    otp_reason: str = ""
    token_replay: bool = False
    status: str = ""
    details: str = ""
    prev_hash: str = GENESIS
    row_hash: str = ""

    def core(self) -> dict[str, Any]:
        """Fields covered by the chain hash (everything but row_hash).
        Bools are cast to int to match how SQLite stores them, so the
        write-time hash and the verify-time recompute agree byte-for-byte."""
        out: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k == "row_hash":
                continue
            out[k] = int(v) if isinstance(v, bool) else v
        return out


def _hash_row(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLogger:
    """SQLite-backed, hash-chained audit trail."""

    def __init__(self, db_path: str = DB_NAME):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id       TEXT    NOT NULL,
                timestamp        TEXT    NOT NULL,
                fp_score         REAL,
                rssi_dbm         REAL,
                failed_attempts  INTEGER,
                biometric_risk   REAL,
                proximity_risk   REAL,
                history_risk     REAL,
                risk_score       REAL,
                tier             TEXT,
                otp_issued       INTEGER,
                otp_digits       INTEGER,
                otp_entered      TEXT,
                otp_valid        INTEGER,
                otp_reason       TEXT,
                token_replay     INTEGER,
                status           TEXT,
                details          TEXT,
                prev_hash        TEXT    NOT NULL,
                row_hash         TEXT    NOT NULL
            )
        """)
        self._conn.commit()

    def _last_row_hash(self) -> str:
        cur = self._conn.execute(
            "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row["row_hash"] if row else GENESIS

    # ---- write path -------------------------------------------------------

    def log(self, record: AuditRecord) -> int:
        """Persist one event and return its row id."""
        if not record.timestamp:
            record.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        record.prev_hash = self._last_row_hash()
        record.row_hash = _hash_row(record.core())

        cur = self._conn.execute(
            """INSERT INTO audit_log
               (session_id, timestamp, fp_score, rssi_dbm, failed_attempts,
                biometric_risk, proximity_risk, history_risk, risk_score,
                tier, otp_issued, otp_digits, otp_entered, otp_valid,
                otp_reason, token_replay, status, details,
                prev_hash, row_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (record.session_id, record.timestamp, record.fp_score,
             record.rssi_dbm, record.failed_attempts, record.biometric_risk,
             record.proximity_risk, record.history_risk, record.risk_score,
             record.tier, int(record.otp_issued), record.otp_digits,
             record.otp_entered, int(record.otp_valid), record.otp_reason,
             int(record.token_replay), record.status, record.details,
             record.prev_hash, record.row_hash))
        self._conn.commit()
        return int(cur.lastrowid)

    # ---- read path --------------------------------------------------------

    def fetch_all(self) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY id ASC")
        return [dict(r) for r in cur.fetchall()]

    def verify_chain(self) -> tuple[bool, str]:
        """Recompute the hash chain; return (ok, message)."""
        prev = GENESIS
        for row in self.fetch_all():
            if row["prev_hash"] != prev:
                return False, (f"Chain broken at row {row['id']} — "
                               f"previous-hash link mismatch")
            core = {k: row[k] for k in row if k not in ("id", "row_hash")}
            if _hash_row(core) != row["row_hash"]:
                return False, (f"Chain broken at row {row['id']} — "
                               f"row content was altered")
            prev = row["row_hash"]
        return True, f"Chain intact — {len(self.fetch_all())} rows verified"

    def export_csv(self, csv_path: str) -> int:
        rows = self.fetch_all()
        if not rows:
            return 0
        fieldnames = list(rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)

    def close(self) -> None:
        self._conn.close()
