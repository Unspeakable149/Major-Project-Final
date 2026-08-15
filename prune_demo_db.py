"""Prune old demo rows from the Hybrid IDS database and reclaim disk space.

Keeps the most recent N minutes of capture in ``live_threat_logs`` and
``protocol_breakdown`` and deletes the rest, then VACUUMs so the file actually
shrinks and dashboard reads stay fast.

Only rows are removed. Table definitions are never dropped or recreated, so the
MITRE ATT&CK columns (and every other migrated column) survive untouched - the
script verifies this and aborts if the schema differs afterwards.

Usage
-----
    python prune_demo_db.py                 # keep last 15 min (asks first)
    python prune_demo_db.py --minutes 5     # keep last 5 min
    python prune_demo_db.py --dry-run       # report only, change nothing
    python prune_demo_db.py --yes           # skip the confirmation prompt
    python prune_demo_db.py --db path/to/ids_logs.db

Stop the capture backend before running: VACUUM needs exclusive access to the
database file and will fail while the backend holds a write lock.

A note on the timestamp column
------------------------------
The backend stores ``timestamp`` as ``HH:MM:SS`` - a time of day with no date.
"Older than 15 minutes" therefore has to be evaluated against a wall clock that
wraps at midnight. Both bounds are zero-padded, so lexicographic string
comparison is chronological, and the window is applied as:

    normal  (cutoff <= now):  keep  cutoff <= ts <= now
    wrapped (cutoff >  now):  keep  ts >= cutoff OR ts <= now

Without the wrapped case, running this at 00:05 with a 15-minute window would
compute a cutoff of 23:50 and delete the entire table.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta

TABLES = ("live_threat_logs", "protocol_breakdown")
DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "Aalok", "Dashboard", "ids_logs.db")


def human(n_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n_bytes) < 1024 or unit == "GB":
            return f"{n_bytes:,.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:,.1f} GB"


def build_window(minutes: int) -> tuple[str, str, bool]:
    """Return (cutoff, now, wrapped) as HH:MM:SS strings."""
    now_dt = datetime.now()
    cutoff_dt = now_dt - timedelta(minutes=minutes)
    now_s = now_dt.strftime("%H:%M:%S")
    cutoff_s = cutoff_dt.strftime("%H:%M:%S")
    return cutoff_s, now_s, cutoff_s > now_s


def where_clause(wrapped: bool) -> str:
    """SQL selecting the rows to DELETE (i.e. those outside the keep window)."""
    if wrapped:
        # Keep ts >= cutoff OR ts <= now  ->  delete the complement.
        return "NOT (timestamp >= ? OR timestamp <= ?)"
    return "NOT (timestamp >= ? AND timestamp <= ?)"


def snapshot_schema(conn: sqlite3.Connection) -> dict[str, list[tuple]]:
    return {t: list(conn.execute(f"PRAGMA table_info({t})")) for t in TABLES}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Prune old rows from the Hybrid IDS demo database and VACUUM.")
    ap.add_argument("--db", default=DEFAULT_DB, help="path to ids_logs.db")
    ap.add_argument("--minutes", type=int, default=15,
                    help="how many minutes of capture to KEEP (default: 15)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be deleted, change nothing")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    if args.minutes < 1:
        print("[X] --minutes must be at least 1.")
        return 2
    if not os.path.exists(args.db):
        print(f"[X] Database not found: {args.db}")
        return 2

    size_before = os.path.getsize(args.db)
    cutoff, now_s, wrapped = build_window(args.minutes)

    print("=" * 68)
    print("  Hybrid IDS - demo database prune")
    print("=" * 68)
    print(f"  database   : {args.db}")
    print(f"  size       : {human(size_before)}")
    print(f"  keeping    : last {args.minutes} min  ({cutoff} -> {now_s})"
          + ("   [window wraps midnight]" if wrapped else ""))
    print()

    # isolation_level=None -> autocommit, required so VACUUM is not run inside
    # an implicit transaction.
    conn = sqlite3.connect(args.db, timeout=15, isolation_level=None)
    try:
        present = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        missing = [t for t in TABLES if t not in present]
        if missing:
            print(f"[X] Missing expected table(s): {missing}")
            return 2

        schema_before = snapshot_schema(conn)
        mitre_before = [c[1] for c in schema_before["live_threat_logs"]
                        if c[1].startswith("mitre")]

        clause = where_clause(wrapped)
        plan = {}
        for table in TABLES:
            total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            doomed = conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE {clause}", (cutoff, now_s)
            ).fetchone()[0]
            plan[table] = (total, doomed)
            print(f"  {table:20} {total:>9,} rows -> delete {doomed:>9,}"
                  f"  keep {total - doomed:>8,}")

        total_doomed = sum(d for _, d in plan.values())
        print()

        if total_doomed == 0:
            print("  Nothing older than the keep window. Database unchanged.")
            return 0

        if args.dry_run:
            print("  --dry-run: no rows deleted, no VACUUM performed.")
            return 0

        if not args.yes:
            reply = input(f"  Delete {total_doomed:,} rows and VACUUM? [y/N] ").strip().lower()
            if reply not in ("y", "yes"):
                print("  Aborted. Database unchanged.")
                return 1

        deleted = {}
        for table in TABLES:
            cur = conn.execute(f"DELETE FROM {table} WHERE {clause}", (cutoff, now_s))
            deleted[table] = cur.rowcount

        print("\n  Reclaiming space (VACUUM)...")
        try:
            conn.execute("VACUUM")
        except sqlite3.OperationalError as exc:
            print(f"  [!] VACUUM failed: {exc}")
            print("      Rows were still deleted. Stop the capture backend "
                  "(it holds a write lock) and re-run to reclaim disk space.")
            return 1

        # Prove the schema - and specifically the MITRE columns - survived.
        schema_after = snapshot_schema(conn)
        mitre_after = [c[1] for c in schema_after["live_threat_logs"]
                       if c[1].startswith("mitre")]
        schema_ok = schema_after == schema_before
    finally:
        conn.close()

    size_after = os.path.getsize(args.db)
    reclaimed = size_before - size_after

    print()
    print("=" * 68)
    print("  SUMMARY")
    print("=" * 68)
    for table in TABLES:
        kept = plan[table][0] - deleted[table]
        print(f"  {table:20} deleted {deleted[table]:>9,}   kept {kept:>8,}")
    print(f"  {'TOTAL':20} deleted {sum(deleted.values()):>9,}")
    print()
    print(f"  size before  : {human(size_before)}")
    print(f"  size after   : {human(size_after)}")
    pct = (reclaimed / size_before * 100) if size_before else 0
    print(f"  reclaimed    : {human(reclaimed)}  ({pct:.1f}%)")
    print()
    print(f"  schema preserved : {'YES' if schema_ok else 'NO - MISMATCH!'}")
    print(f"  MITRE columns    : {len(mitre_after)}/{len(mitre_before)} intact "
          f"{mitre_after if mitre_after else ''}")
    if not schema_ok or mitre_after != mitre_before:
        print("  [X] Schema changed unexpectedly - investigate before presenting.")
        return 1
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
