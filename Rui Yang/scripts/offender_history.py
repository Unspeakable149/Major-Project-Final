"""Repeat-offender IP history — persistent store for Enhancement Idea 6.

Gives the Historical component real memory ACROSS uploads, not just within a
single PCAP. Backed by a tiny SQLite file (offender_history.db) that lives in the
Rui Yang project root. SQLite is used because it ships with Python (no install),
is a single portable file, and is safe for the single-user Streamlit use case.

Schema (one row per source IP):
    ip              TEXT PRIMARY KEY
    offence_count   INTEGER   -- total alert flows ever attributed to this IP
    first_seen      TEXT      -- ISO timestamp of first offence
    last_seen       TEXT      -- ISO timestamp of most recent offence

Typical flow per PCAP analysis:
    hist = OffenderHistory()
    prior = hist.get_count(ip)          # how many times seen BEFORE this upload
    ... score the flow using `prior` ...
    hist.record(ip)                     # persist this new offence
"""
import os
import sqlite3
from datetime import datetime

# Anchor the DB to the Rui Yang project root (this file is .../scripts/offender_history.py)
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.path.join(_BASE_DIR, "offender_history.db")


class OffenderHistory:
    """Thin wrapper over a SQLite table of repeat-offender IPs."""

    def __init__(self, db_path=DEFAULT_DB):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        # check_same_thread=False so Streamlit's threads can share the connection
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS offenders (
                    ip            TEXT PRIMARY KEY,
                    offence_count INTEGER NOT NULL DEFAULT 0,
                    first_seen    TEXT,
                    last_seen     TEXT
                )
                """
            )

    def get_count(self, ip):
        """Return how many prior offences this IP has on record (0 if new)."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT offence_count FROM offenders WHERE ip = ?", (ip,)
            )
            row = cur.fetchone()
            return row[0] if row else 0

    def record(self, ip, count=1):
        """Add `count` offences for this IP, creating the row if needed."""
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO offenders (ip, offence_count, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    offence_count = offence_count + excluded.offence_count,
                    last_seen     = excluded.last_seen
                """,
                (ip, count, now, now),
            )

    def top_offenders(self, limit=10):
        """Return the worst repeat offenders as a list of dicts (for reporting)."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT ip, offence_count, first_seen, last_seen
                FROM offenders
                ORDER BY offence_count DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [
                {
                    "ip": r[0],
                    "offences": r[1],
                    "first_seen": r[2],
                    "last_seen": r[3],
                }
                for r in cur.fetchall()
            ]

    def reset(self):
        """Wipe all history (useful for a clean demo)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM offenders")
