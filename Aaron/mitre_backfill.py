"""One-shot MITRE ATT&CK backfill for existing ids_logs.db rows.

Run ONCE after upgrading to add the MITRE columns to an already-populated
database.  Safe to re-run; only updates rows where mitre_technique_id IS NULL.

Usage:
    python mitre_backfill.py              # uses ids_logs.db in cwd
    python mitre_backfill.py mypath.db    # explicit DB path
"""

import sqlite3
import sys
import os

from mitre_mapping import tag_mitre

DB_FILE = sys.argv[1] if len(sys.argv) > 1 else "ids_logs.db"

if not os.path.exists(DB_FILE):
    print(f"[!] Database not found: {DB_FILE}")
    sys.exit(1)

print(f"[*] Opening {DB_FILE} ...")
conn = sqlite3.connect(DB_FILE, timeout=30)
cur = conn.cursor()

# ── Ensure MITRE columns exist (idempotent) ─────────────────────────────────
for col, defn in [
    ("mitre_technique_id",     "TEXT DEFAULT NULL"),
    ("mitre_sub_technique_id", "TEXT DEFAULT NULL"),
    ("mitre_technique_name",   "TEXT DEFAULT NULL"),
    ("mitre_tactic",           "TEXT DEFAULT NULL"),
    ("mitre_tactic_id",        "TEXT DEFAULT NULL"),
]:
    try:
        cur.execute(f"ALTER TABLE live_threat_logs ADD COLUMN {col} {defn}")
        print(f"    [+] Added column: {col}")
    except sqlite3.OperationalError:
        pass  # already exists

conn.commit()

# ── Fetch rows needing tagging ───────────────────────────────────────────────
cur.execute(
    "SELECT id, traffic_profile FROM live_threat_logs WHERE mitre_technique_id IS NULL"
)
rows = cur.fetchall()
total = len(rows)
print(f"[*] Rows to back-fill: {total}")

if total == 0:
    print("[+] Nothing to do — all rows already tagged.")
    conn.close()
    sys.exit(0)

updates = []
tactic_counter: dict[str, int] = {}

for row_id, profile in rows:
    tid, sub, name, tactic, tac_id = tag_mitre(profile or "")
    updates.append((tid, sub, name, tactic, tac_id, row_id))
    tactic_counter[tactic] = tactic_counter.get(tactic, 0) + 1

cur.executemany(
    "UPDATE live_threat_logs "
    "SET mitre_technique_id=?, mitre_sub_technique_id=?, mitre_technique_name=?, "
    "    mitre_tactic=?, mitre_tactic_id=? "
    "WHERE id=?",
    updates,
)
conn.commit()
conn.close()

print(f"\n[+] Done. {total} rows tagged.\n")
print("  Tactic breakdown:")
for tactic, count in sorted(tactic_counter.items(), key=lambda x: -x[1]):
    bar = "█" * min(count, 40)
    print(f"    {tactic:<30} {count:>5}  {bar}")
