"""SQLite database initialization and query helpers (WAL mode for concurrent access)."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", "/data/db/honeypot.db")

CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    source_ip       TEXT NOT NULL,
    source_port     INTEGER,
    username        TEXT,
    password        TEXT,
    connection_type TEXT NOT NULL DEFAULT 'interactive',
    duration_seconds REAL,
    command_count   INTEGER DEFAULT 0,
    high_interest   INTEGER DEFAULT 0,
    geo_country     TEXT DEFAULT '',
    geo_country_code TEXT DEFAULT '',
    geo_city        TEXT DEFAULT '',
    geo_asn         TEXT DEFAULT '',
    geo_isp         TEXT DEFAULT '',
    geo_lat         REAL DEFAULT 0,
    geo_lon         REAL DEFAULT 0,
    is_cloud        INTEGER DEFAULT 0,
    abuse_confidence INTEGER DEFAULT 0,
    rdns            TEXT DEFAULT '',
    mitre_tags      TEXT DEFAULT '[]',
    commands        TEXT DEFAULT '[]'
)
"""

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}'
)
"""

CREATE_IP_CACHE = """
CREATE TABLE IF NOT EXISTS ip_cache (
    ip          TEXT PRIMARY KEY,
    cached_at   TEXT NOT NULL,
    data        TEXT NOT NULL
)
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_country ON sessions(geo_country)",
    "CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)",
]


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(CREATE_SESSIONS)
        conn.execute(CREATE_EVENTS)
        conn.execute(CREATE_IP_CACHE)
        for idx in CREATE_INDEXES:
            conn.execute(idx)


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_session(s: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, started_at, ended_at, source_ip, source_port,
                username, password, connection_type, duration_seconds,
                command_count, high_interest,
                geo_country, geo_country_code, geo_city, geo_asn, geo_isp,
                geo_lat, geo_lon, is_cloud, abuse_confidence, rdns,
                mitre_tags, commands
            ) VALUES (
                :session_id, :started_at, :ended_at, :source_ip, :source_port,
                :username, :password, :connection_type, :duration_seconds,
                :command_count, :high_interest,
                :geo_country, :geo_country_code, :geo_city, :geo_asn, :geo_isp,
                :geo_lat, :geo_lon, :is_cloud, :abuse_confidence, :rdns,
                :mitre_tags, :commands
            )
            """,
            {
                **s,
                "high_interest": int(s.get("high_interest", False)),
                "is_cloud": int(s.get("is_cloud", False)),
                "mitre_tags": json.dumps(s.get("mitre_tags", [])),
                "commands": json.dumps(s.get("commands", [])),
            },
        )


def insert_event(session_id: str, event_type: str, data: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (session_id, event_type, timestamp, data) VALUES (?, ?, ?, ?)",
            (session_id, event_type, datetime.now(timezone.utc).isoformat(), json.dumps(data)),
        )


def get_ip_cache(ip: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT data FROM ip_cache WHERE ip = ?", (ip,)).fetchone()
        return json.loads(row["data"]) if row else None


def set_ip_cache(ip: str, data: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ip_cache (ip, cached_at, data) VALUES (?, ?, ?)",
            (ip, datetime.now(timezone.utc).isoformat(), json.dumps(data)),
        )


# ── Dashboard query helpers ──────────────────────────────────────────────────

def stats_today() -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_conn() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE started_at >= ?", (today,)
        ).fetchone()[0]
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM sessions WHERE started_at >= ?", (today,)
        ).fetchone()[0]
        high_interest = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE started_at >= ? AND high_interest = 1", (today,)
        ).fetchone()[0]
        commands_today = conn.execute(
            "SELECT SUM(command_count) FROM sessions WHERE started_at >= ?", (today,)
        ).fetchone()[0] or 0
    return {
        "connections_today": total,
        "unique_ips_today": unique_ips,
        "high_interest_today": high_interest,
        "commands_today": commands_today,
    }


def top_countries(limit: int = 10) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT geo_country, geo_country_code, COUNT(*) as count
            FROM sessions
            WHERE geo_country != ''
            GROUP BY geo_country
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def top_asns(limit: int = 10) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT geo_asn, geo_isp, is_cloud, COUNT(*) as count
            FROM sessions
            WHERE geo_asn != ''
            GROUP BY geo_asn
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def top_credentials(limit: int = 10) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT username, password, COUNT(*) as count
            FROM sessions
            GROUP BY username, password
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def command_frequency(limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT commands FROM sessions WHERE commands != '[]'"
        ).fetchall()

    freq: dict[str, int] = {}
    for row in rows:
        cmds = json.loads(row["commands"])
        for c in cmds:
            base = c["command"].strip().split()[0] if c["command"].strip() else ""
            if base:
                freq[base] = freq.get(base, 0) + 1

    sorted_cmds = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"command": k, "count": v} for k, v in sorted_cmds]


def mitre_frequency(limit: int = 15) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT mitre_tags FROM sessions WHERE mitre_tags != '[]'"
        ).fetchall()

    freq: dict[str, dict] = {}
    for row in rows:
        tags = json.loads(row["mitre_tags"])
        for t in tags:
            tid = t["id"]
            if tid not in freq:
                freq[tid] = {"id": tid, "name": t["name"], "tactic": t["tactic"], "count": 0}
            freq[tid]["count"] += 1

    return sorted(freq.values(), key=lambda x: x["count"], reverse=True)[:limit]


def hourly_volume(hours: int = 24) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00', started_at) as hour,
                   COUNT(*) as count
            FROM sessions
            WHERE started_at >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
            """,
            (f"-{hours} hours",),
        ).fetchall()
    return [dict(r) for r in rows]


def recent_sessions(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT session_id, started_at, ended_at, source_ip, username, password,
                   connection_type, duration_seconds, command_count, high_interest,
                   geo_country, geo_country_code, geo_city, geo_asn, geo_isp,
                   geo_lat, geo_lon, is_cloud, abuse_confidence, rdns,
                   mitre_tags, commands
            FROM sessions
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["mitre_tags"] = json.loads(d["mitre_tags"])
        d["commands"] = json.loads(d["commands"])
        d["high_interest"] = bool(d["high_interest"])
        d["is_cloud"] = bool(d["is_cloud"])
        result.append(d)
    return result


def all_ips_with_coords() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT source_ip, geo_lat, geo_lon, geo_country, COUNT(*) as count
            FROM sessions
            WHERE geo_lat != 0 OR geo_lon != 0
            GROUP BY source_ip
            """
        ).fetchall()
    return [dict(r) for r in rows]


def high_interest_sessions(limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT session_id, started_at, source_ip, username, password,
                   duration_seconds, command_count, geo_country, geo_city,
                   geo_asn, is_cloud, mitre_tags, commands
            FROM sessions
            WHERE high_interest = 1
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["mitre_tags"] = json.loads(d["mitre_tags"])
        d["commands"] = json.loads(d["commands"])
        result.append(d)
    return result
