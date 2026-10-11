"""
MAG (Memory-Augmented Generation) store.

SQLite is used deliberately instead of a vector store: "has this client
failed before" is a structured lookup, not a semantic-similarity
question, and SQL gives exact, cheap answers where embeddings would be
slower and less reliable.

Ingest is idempotent: re-parsing the same test_id replaces that test's
rows and recomputes each client's cross-test aggregates, so counts never
drift upward when a log is uploaded twice.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "hostapd_memory.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.reason_codes import REASON_CODE_MEANINGS  # noqa: E402

# Columns added after the first release -- applied to existing DBs by _migrate().
_MIGRATIONS = {
    "tests": {"parser_version": "TEXT", "log_format": "TEXT", "log_start": "TEXT",
              "log_end": "TEXT", "driver_errors": "INTEGER DEFAULT 0"},
    "test_clients": {"failure_count": "INTEGER DEFAULT 0", "failure_score": "INTEGER DEFAULT 0",
                     "reason_codes_json": "TEXT"},
    "events": {"subtype": "TEXT", "initiator": "TEXT", "interface": "TEXT"},
}


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    for table, cols in _MIGRATIONS.items():
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for col, decl in cols.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_connection(db_path)
    with conn:
        # Create base tables first, migrate old ones, then indexes (which may
        # reference migrated columns).
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        _migrate(conn)
        for code, meaning in REASON_CODE_MEANINGS.items():
            conn.execute(
                "INSERT INTO reason_codes (code, meaning) VALUES (?, ?) "
                "ON CONFLICT(code) DO UPDATE SET meaning = excluded.meaning",
                (code, meaning),
            )
    conn.close()


def _delete_test_rows(conn: sqlite3.Connection, test_id: str) -> list[str]:
    macs = [r["client_mac"] for r in conn.execute(
        "SELECT client_mac FROM test_clients WHERE test_id = ?", (test_id,))]
    for table in ("events", "issues", "findings", "test_clients"):
        conn.execute(f"DELETE FROM {table} WHERE test_id = ?", (test_id,))
    return macs


def _recompute_clients(conn: sqlite3.Connection, macs) -> None:
    """Rebuild clients.* aggregates from test_clients (the source of truth)."""
    for mac in set(macs):
        rows = conn.execute(
            """SELECT tc.test_id, tc.failure_count, t.created_at
               FROM test_clients tc JOIN tests t ON t.test_id = tc.test_id
               WHERE tc.client_mac = ? ORDER BY t.created_at, tc.test_id""",
            (mac,),
        ).fetchall()
        if not rows:
            conn.execute("DELETE FROM clients WHERE client_mac = ?", (mac,))
            continue
        conn.execute(
            """INSERT INTO clients (client_mac, first_seen_test, first_seen_at, last_seen_test,
                   last_seen_at, total_tests, total_failures)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(client_mac) DO UPDATE SET
                   first_seen_test = excluded.first_seen_test, first_seen_at = excluded.first_seen_at,
                   last_seen_test = excluded.last_seen_test, last_seen_at = excluded.last_seen_at,
                   total_tests = excluded.total_tests, total_failures = excluded.total_failures""",
            (mac, rows[0]["test_id"], rows[0]["created_at"], rows[-1]["test_id"], rows[-1]["created_at"],
             len(rows), sum(r["failure_count"] or 0 for r in rows)),
        )


def ingest_analysis(analysis: dict, conn: sqlite3.Connection | None = None) -> None:
    """Persist one parser analysis.json into MAG (idempotent per test_id)."""
    own_conn = conn is None
    conn = conn or get_connection()
    meta = analysis["metadata"]
    stats = analysis["statistics"]
    test_id = meta["test_id"]
    now = datetime.now(timezone.utc).isoformat()

    with conn:
        old_macs = _delete_test_rows(conn, test_id)
        conn.execute(
            """INSERT INTO tests
               (test_id, created_at, ap_name, ssid, security, channel, client_count,
                authentication_failures, association_failures, handshake_failures,
                deauthentication_events, disassociation_events, reconnections,
                raw_statistics_json, parser_version, log_format, log_start, log_end, driver_errors)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(test_id) DO UPDATE SET
                 created_at=excluded.created_at, ap_name=excluded.ap_name, ssid=excluded.ssid,
                 security=excluded.security, channel=excluded.channel, client_count=excluded.client_count,
                 authentication_failures=excluded.authentication_failures,
                 association_failures=excluded.association_failures,
                 handshake_failures=excluded.handshake_failures,
                 deauthentication_events=excluded.deauthentication_events,
                 disassociation_events=excluded.disassociation_events,
                 reconnections=excluded.reconnections, raw_statistics_json=excluded.raw_statistics_json,
                 parser_version=excluded.parser_version, log_format=excluded.log_format,
                 log_start=excluded.log_start, log_end=excluded.log_end,
                 driver_errors=excluded.driver_errors""",
            (
                test_id, meta.get("generated_at", now), meta.get("ap_name"),
                meta.get("ssid"), meta.get("security"), meta.get("channel"),
                stats.get("clients", 0), stats.get("authentication_failures", 0),
                stats.get("association_failures", 0), stats.get("handshake_failures", 0),
                stats.get("deauthentication_events", 0), stats.get("disassociation_events", 0),
                stats.get("reconnections", 0), json.dumps(stats),
                meta.get("parser_version", "1.0"), meta.get("log_format"),
                meta.get("log_start"), meta.get("log_end"), stats.get("driver_errors", 0),
            ),
        )

        new_macs = []
        for client in analysis.get("clients", []):
            mac = client["client_mac"]
            new_macs.append(mac)
            # Parser v1 JSONs have no failure_count -> fall back to #issues.
            failures = client.get("failure_count", len(client.get("issues", [])))
            conn.execute(
                "INSERT OR IGNORE INTO clients (client_mac, total_tests, total_failures) VALUES (?, 0, 0)",
                (mac,),
            )
            conn.execute(
                """INSERT INTO test_clients
                   (test_id, client_mac, authentication, association, handshake,
                    deauth_count, disassoc_count, reconnect_count, issues_json,
                    failure_count, failure_score, reason_codes_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    test_id, mac, client.get("authentication"), client.get("association"),
                    client.get("handshake"), client.get("deauth_count", 0),
                    client.get("disassoc_count", 0), client.get("reconnect_count", 0),
                    json.dumps(client.get("issues", [])), failures,
                    client.get("failure_score", failures), json.dumps(client.get("reason_codes", [])),
                ),
            )
            for issue in client.get("issues", []):
                conn.execute(
                    "INSERT INTO issues (test_id, client_mac, issue_type, count) VALUES (?, ?, ?, 1)",
                    (test_id, mac, issue),
                )

        conn.executemany(
            """INSERT INTO events (test_id, client_mac, timestamp, event_type, reason_code, message,
                   subtype, initiator, interface)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (test_id, e.get("client_mac"), e.get("timestamp"), e.get("event"), e.get("reason_code"),
                 e.get("message"), e.get("subtype"), e.get("initiator"), e.get("interface"))
                for e in analysis.get("events", [])
            ],
        )
        conn.executemany(
            "INSERT INTO findings (test_id, finding_id, severity, observation, metrics_json) VALUES (?, ?, ?, ?, ?)",
            [
                (test_id, f["id"], f.get("severity"), f.get("observation"), json.dumps(f.get("metrics", {})))
                for f in analysis.get("findings", [])
            ],
        )
        _recompute_clients(conn, set(old_macs) | set(new_macs))

    if own_conn:
        conn.close()


def delete_test(test_id: str) -> bool:
    conn = get_connection()
    with conn:
        macs = _delete_test_rows(conn, test_id)
        cur = conn.execute("DELETE FROM tests WHERE test_id = ?", (test_id,))
        _recompute_clients(conn, macs)
    conn.close()
    return cur.rowcount > 0


def list_tests(conn: sqlite3.Connection | None = None) -> list[dict]:
    own_conn = conn is None
    conn = conn or get_connection()
    rows = conn.execute(
        """SELECT test_id, created_at, ap_name, ssid, security, channel, client_count,
                  authentication_failures, handshake_failures, deauthentication_events,
                  driver_errors, log_format, log_start, log_end
           FROM tests ORDER BY created_at DESC"""
    ).fetchall()
    result = [dict(r) for r in rows]
    if own_conn:
        conn.close()
    return result


def latest_test_id() -> str | None:
    tests = list_tests()
    return tests[0]["test_id"] if tests else None


def get_client_history(mac: str, conn: sqlite3.Connection | None = None) -> dict:
    own_conn = conn is None
    conn = conn or get_connection()
    mac = mac.strip().upper().replace("-", ":")

    client_row = conn.execute("SELECT * FROM clients WHERE client_mac = ?", (mac,)).fetchone()
    if client_row is None:
        result = {"client_mac": mac, "found": False, "message": "No historical record for this client."}
    else:
        per_test = conn.execute(
            """SELECT tc.test_id, t.created_at AS test_created_at, tc.authentication, tc.association,
                      tc.handshake, tc.deauth_count, tc.disassoc_count, tc.reconnect_count,
                      tc.failure_count, tc.failure_score, tc.issues_json, tc.reason_codes_json
               FROM test_clients tc JOIN tests t ON t.test_id = tc.test_id
               WHERE tc.client_mac = ? ORDER BY t.created_at""",
            (mac,),
        ).fetchall()
        history = []
        for row in per_test:
            d = dict(row)
            d["issues"] = json.loads(d.pop("issues_json") or "[]")
            d["reason_codes"] = json.loads(d.pop("reason_codes_json") or "[]")
            history.append(d)
        result = {
            "client_mac": mac,
            "found": True,
            "total_tests": client_row["total_tests"],
            "total_failures": client_row["total_failures"],
            "first_seen_test": client_row["first_seen_test"],
            "last_seen_test": client_row["last_seen_test"],
            "history": history,
        }

    if own_conn:
        conn.close()
    return result


def get_test_summary(test_id: str, conn: sqlite3.Connection | None = None) -> dict:
    own_conn = conn is None
    conn = conn or get_connection()

    row = conn.execute("SELECT * FROM tests WHERE test_id = ?", (test_id,)).fetchone()
    if row is None:
        result = {"test_id": test_id, "found": False}
    else:
        result = dict(row)
        result.pop("raw_statistics_json", None)
        result["found"] = True
        result["raw_statistics"] = json.loads(row["raw_statistics_json"] or "{}")
        result["findings"] = [
            {"id": f["finding_id"], "severity": f["severity"], "observation": f["observation"]}
            for f in conn.execute(
                "SELECT finding_id, severity, observation FROM findings WHERE test_id = ? ORDER BY id",
                (test_id,))
        ]

    if own_conn:
        conn.close()
    return result


def get_top_unstable_clients(limit: int = 5, conn: sqlite3.Connection | None = None) -> list[dict]:
    own_conn = conn is None
    conn = conn or get_connection()

    rows = conn.execute(
        """SELECT client_mac, total_tests, total_failures, first_seen_test, last_seen_test
           FROM clients WHERE total_failures > 0
           ORDER BY total_failures DESC, total_tests DESC LIMIT ?""",
        (int(limit),),
    ).fetchall()
    result = [dict(row) for row in rows]

    if own_conn:
        conn.close()
    return result


def get_finding_history(finding_id: str) -> dict:
    """Which tests on record raised a given deterministic finding (e.g. BEACON_SET_FAILURES)."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT f.test_id, t.created_at, t.ap_name, f.severity, f.observation
           FROM findings f JOIN tests t ON t.test_id = f.test_id
           WHERE f.finding_id = ? ORDER BY t.created_at""",
        (finding_id.upper(),),
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM tests").fetchone()[0]
    conn.close()
    return {"finding_id": finding_id.upper(), "tests_with_finding": len(rows), "total_tests": total,
            "occurrences": [dict(r) for r in rows]}


def compare_tests(test_id_a: str, test_id_b: str) -> dict:
    conn = get_connection()
    a = get_test_summary(test_id_a, conn)
    b = get_test_summary(test_id_b, conn)
    conn.close()
    delta = {}
    if a.get("found") and b.get("found"):
        sa, sb = a["raw_statistics"], b["raw_statistics"]
        for k in sorted(set(sa) | set(sb)):
            va, vb = sa.get(k), sb.get(k)
            if isinstance(va, (int, float)) and isinstance(vb, (int, float)) and va != vb:
                delta[k] = {"test_a": va, "test_b": vb, "change": round(vb - va, 3)}
    fa = {f["id"] for f in a.get("findings", [])}
    fb = {f["id"] for f in b.get("findings", [])}
    def header(t):
        return {k: v for k, v in t.items() if k not in ("raw_statistics", "findings")}

    return {
        "test_a": header(a), "test_b": header(b), "changed_statistics": delta,
        "findings_only_in_a": sorted(fa - fb), "findings_only_in_b": sorted(fb - fa),
        "findings_in_both": sorted(fa & fb),
    }


def rebuild_from_json(json_dir: Path, backup: bool = True) -> list[str]:
    """Drop and rebuild the whole MAG DB from output/json/*.analysis.json."""
    if backup and DB_PATH.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.copy2(DB_PATH, DB_PATH.with_name(f"hostapd_memory.backup_{stamp}.db"))
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()
    ingested = []
    for path in sorted(json_dir.glob("*.analysis.json")):
        analysis = json.loads(path.read_text(encoding="utf-8"))
        ingest_analysis(analysis)
        ingested.append(analysis["metadata"]["test_id"])
    return ingested


def main():
    ap = argparse.ArgumentParser(description="MAG memory database utility")
    ap.add_argument("--rebuild", action="store_true",
                    help="Back up and rebuild the DB from output/json/*.analysis.json")
    ap.add_argument("--list", action="store_true", help="List stored tests")
    ap.add_argument("--delete", metavar="TEST_ID", help="Remove one test from memory")
    args = ap.parse_args()

    if args.rebuild:
        ids = rebuild_from_json(Path(__file__).resolve().parent.parent / "output" / "json")
        print(f"Rebuilt MAG database with {len(ids)} test(s): {', '.join(ids)}")
        return
    init_db()
    if args.delete:
        print("deleted" if delete_test(args.delete) else "not found")
    elif args.list:
        for t in list_tests():
            print(f"{t['test_id']:20} {t['created_at'][:19]}  clients={t['client_count']}  "
                  f"auth_fail={t['authentication_failures']}  hs_fail={t['handshake_failures']}  "
                  f"driver_err={t['driver_errors']}")
    else:
        print(f"Initialized MAG database at {DB_PATH}")


if __name__ == "__main__":
    main()
