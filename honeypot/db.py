"""SQLite database initialization and query helpers (WAL mode for concurrent access)."""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", "/data/db/honeypot.db")

CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id           TEXT PRIMARY KEY,
    started_at           TEXT NOT NULL,
    ended_at             TEXT,
    source_ip            TEXT NOT NULL,
    source_port          INTEGER,
    username             TEXT,
    password             TEXT,
    connection_type      TEXT NOT NULL DEFAULT 'interactive',
    duration_seconds     REAL,
    command_count        INTEGER DEFAULT 0,
    high_interest        INTEGER DEFAULT 0,
    geo_country          TEXT DEFAULT '',
    geo_country_code     TEXT DEFAULT '',
    geo_city             TEXT DEFAULT '',
    geo_asn              TEXT DEFAULT '',
    geo_isp              TEXT DEFAULT '',
    geo_lat              REAL DEFAULT 0,
    geo_lon              REAL DEFAULT 0,
    is_cloud             INTEGER DEFAULT 0,
    abuse_confidence     INTEGER DEFAULT 0,
    rdns                 TEXT DEFAULT '',
    mitre_tags           TEXT DEFAULT '[]',
    commands             TEXT DEFAULT '[]',
    sophistication_score INTEGER DEFAULT 0,
    password_pattern     TEXT DEFAULT '',
    is_return_visitor    INTEGER DEFAULT 0,
    visit_number         INTEGER DEFAULT 1,
    first_cmd_category   TEXT DEFAULT '',
    easter_eggs_triggered TEXT DEFAULT '[]'
)
"""

CREATE_EASTER_EGG_HITS = """
CREATE TABLE IF NOT EXISTS easter_egg_hits (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    egg_name         TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    source_ip        TEXT NOT NULL,
    geo_country      TEXT DEFAULT '',
    geo_country_code TEXT DEFAULT '',
    geo_hour         INTEGER DEFAULT 0
)
"""

_SESSION_MIGRATIONS = [
    "ALTER TABLE sessions ADD COLUMN sophistication_score INTEGER DEFAULT 0",
    "ALTER TABLE sessions ADD COLUMN password_pattern TEXT DEFAULT ''",
    "ALTER TABLE sessions ADD COLUMN is_return_visitor INTEGER DEFAULT 0",
    "ALTER TABLE sessions ADD COLUMN visit_number INTEGER DEFAULT 1",
    "ALTER TABLE sessions ADD COLUMN first_cmd_category TEXT DEFAULT ''",
    "ALTER TABLE sessions ADD COLUMN easter_eggs_triggered TEXT DEFAULT '[]'",
]

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


def _compute_soph_from_row(commands: list, duration_seconds: float, mitre_tags: list) -> int:
    """Compute sophistication score from raw session data (used in backfill)."""
    import re as _re
    if not commands:
        return 1
    score = 1
    combined = " ".join(commands).lower()
    score += min(3, len(commands) // 5)
    if any(w in combined for w in ("histfile=", "histsize=0", "history -c", "unset histfile")):
        score += 2
    if "/dev/tcp" in combined:
        score += 2
    if _re.search(r"\b(wget|curl)\s+https?://", combined):
        score += 1
    if (duration_seconds or 0) > 120:
        score += 1
    bases = {c.strip().split()[0] for c in commands if c.strip()}
    if len(commands) >= 5 and len(bases) / len(commands) > 0.6:
        score += 1
    if len({t.get("tactic", "") for t in mitre_tags}) >= 3:
        score += 1
    return min(10, max(1, score))


def _backfill_new_metrics() -> None:
    """Backfill password_pattern, first_cmd_category, and sophistication_score for historical sessions."""
    from .session import categorize_first_command, classify_password

    with get_conn() as conn:
        rows = conn.execute(
            """SELECT session_id, password, commands, command_count,
                      duration_seconds, mitre_tags, sophistication_score,
                      password_pattern, first_cmd_category
               FROM sessions
               WHERE (password_pattern = '' OR password_pattern IS NULL)
                  OR (sophistication_score = 0 AND command_count > 0)"""
        ).fetchall()

        if not rows:
            return

        updates = []
        for row in rows:
            password = row["password"] or ""
            try:
                commands_raw = json.loads(row["commands"] or "[]")
            except Exception:
                commands_raw = []
            try:
                mitre_tags = json.loads(row["mitre_tags"] or "[]")
            except Exception:
                mitre_tags = []

            cmd_strings = [c.get("command", "") for c in commands_raw if isinstance(c, dict)]

            pattern = row["password_pattern"] or ""
            if not pattern:
                pattern = classify_password(password) if password else "custom"

            first_cat = row["first_cmd_category"] or ""
            if not first_cat and (row["command_count"] or 0) > 0 and cmd_strings:
                first_cat = categorize_first_command(cmd_strings[0]) if cmd_strings[0] else "other"

            soph = row["sophistication_score"] or 0
            if soph == 0 and cmd_strings:
                soph = _compute_soph_from_row(cmd_strings, row["duration_seconds"], mitre_tags)

            updates.append((pattern, first_cat, soph, row["session_id"]))

        conn.executemany(
            """UPDATE sessions
               SET password_pattern = ?, first_cmd_category = ?, sophistication_score = ?
               WHERE session_id = ?""",
            updates,
        )


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(CREATE_SESSIONS)
        conn.execute(CREATE_EVENTS)
        conn.execute(CREATE_IP_CACHE)
        conn.execute(CREATE_EASTER_EGG_HITS)
        for idx in CREATE_INDEXES:
            conn.execute(idx)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_easter_eggs_name ON easter_egg_hits(egg_name)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_easter_eggs_ts ON easter_egg_hits(timestamp)"
        )
        for stmt in _SESSION_MIGRATIONS:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass

    _backfill_new_metrics()


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
                mitre_tags, commands,
                sophistication_score, password_pattern,
                is_return_visitor, visit_number, first_cmd_category,
                easter_eggs_triggered
            ) VALUES (
                :session_id, :started_at, :ended_at, :source_ip, :source_port,
                :username, :password, :connection_type, :duration_seconds,
                :command_count, :high_interest,
                :geo_country, :geo_country_code, :geo_city, :geo_asn, :geo_isp,
                :geo_lat, :geo_lon, :is_cloud, :abuse_confidence, :rdns,
                :mitre_tags, :commands,
                :sophistication_score, :password_pattern,
                :is_return_visitor, :visit_number, :first_cmd_category,
                :easter_eggs_triggered
            )
            """,
            {
                **s,
                "high_interest": int(s.get("high_interest", False)),
                "is_cloud": int(s.get("is_cloud", False)),
                "is_return_visitor": int(s.get("is_return_visitor", False)),
                "mitre_tags": json.dumps(s.get("mitre_tags", [])),
                "commands": json.dumps(s.get("commands", [])),
                "easter_eggs_triggered": json.dumps(s.get("easter_eggs_triggered", [])),
                "sophistication_score": s.get("sophistication_score", 0),
                "password_pattern": s.get("password_pattern", ""),
                "visit_number": s.get("visit_number", 1),
                "first_cmd_category": s.get("first_cmd_category", ""),
            },
        )


def insert_easter_egg_hit(egg_name: str, session_id: str, source_ip: str,
                          geo_country: str, geo_country_code: str, hour: int) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO easter_egg_hits
               (egg_name, session_id, timestamp, source_ip, geo_country, geo_country_code, geo_hour)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (egg_name, session_id, datetime.now(timezone.utc).isoformat(),
             source_ip, geo_country, geo_country_code, hour),
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


# ── Time-filter helper ────────────────────────────────────────────────────────

def _tf(since: str | None, col: str = "started_at") -> tuple[str, dict]:
    """Return (extra WHERE fragment, named-param dict) for an optional time floor."""
    if since:
        return f"AND {col} >= :since", {"since": since}
    return "", {}


# ── Dashboard query helpers ──────────────────────────────────────────────────

def stats(since: str | None = None) -> dict:
    tw, tp = _tf(since)
    tw_egg, tp_egg = _tf(since, "timestamp")
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM sessions WHERE 1=1 {tw}", tp
        ).fetchone()[0]
        unique_ips = conn.execute(
            f"SELECT COUNT(DISTINCT source_ip) FROM sessions WHERE 1=1 {tw}", tp
        ).fetchone()[0]
        high_interest = conn.execute(
            f"SELECT COUNT(*) FROM sessions WHERE high_interest = 1 {tw}", tp
        ).fetchone()[0]
        commands_total = conn.execute(
            f"SELECT SUM(command_count) FROM sessions WHERE 1=1 {tw}", tp
        ).fetchone()[0] or 0
        abandoned = conn.execute(
            f"SELECT COUNT(*) FROM sessions WHERE command_count = 0 {tw}", tp
        ).fetchone()[0]
        return_count = conn.execute(
            f"SELECT COUNT(*) FROM sessions WHERE is_return_visitor = 1 {tw}", tp
        ).fetchone()[0]
        avg_soph = conn.execute(
            f"SELECT AVG(sophistication_score) FROM sessions "
            f"WHERE sophistication_score > 0 {tw}", tp
        ).fetchone()[0]
        egg_hits = conn.execute(
            f"SELECT COUNT(*) FROM easter_egg_hits WHERE 1=1 {tw_egg}", tp_egg
        ).fetchone()[0]
    abandonment_rate = round(abandoned / max(1, total) * 100, 1)
    return {
        "connections_today": total,
        "unique_ips_today": unique_ips,
        "high_interest_today": high_interest,
        "commands_today": commands_total,
        "abandonment_rate": abandonment_rate,
        "return_visitors_today": return_count,
        "avg_sophistication": round(avg_soph or 0.0, 1),
        "easter_egg_hits_today": egg_hits,
    }


def top_countries(limit: int = 10, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT geo_country, geo_country_code, COUNT(*) as count
                FROM sessions WHERE geo_country != '' {tw}
                GROUP BY geo_country ORDER BY count DESC LIMIT :limit""",
            {**tp, "limit": limit},
        ).fetchall()
    return [dict(r) for r in rows]


def top_asns(limit: int = 10, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT geo_asn, geo_isp, is_cloud, COUNT(*) as count
                FROM sessions WHERE geo_asn != '' {tw}
                GROUP BY geo_asn ORDER BY count DESC LIMIT :limit""",
            {**tp, "limit": limit},
        ).fetchall()
    return [dict(r) for r in rows]


def top_credentials(limit: int = 10, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT username, password, COUNT(*) as count
                FROM sessions WHERE 1=1 {tw}
                GROUP BY username, password ORDER BY count DESC LIMIT :limit""",
            {**tp, "limit": limit},
        ).fetchall()
    return [dict(r) for r in rows]


def command_frequency(limit: int = 20, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT commands FROM sessions WHERE commands != '[]' {tw}", tp
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


def mitre_frequency(limit: int = 15, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT mitre_tags FROM sessions WHERE mitre_tags != '[]' {tw}", tp
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
                   mitre_tags, commands,
                   sophistication_score, password_pattern,
                   is_return_visitor, visit_number, first_cmd_category,
                   easter_eggs_triggered
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
        d["easter_eggs_triggered"] = json.loads(d.get("easter_eggs_triggered") or "[]")
        d["high_interest"] = bool(d["high_interest"])
        d["is_cloud"] = bool(d["is_cloud"])
        d["is_return_visitor"] = bool(d.get("is_return_visitor", 0))
        result.append(d)
    return result


def all_ips_with_coords(since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT source_ip, geo_lat, geo_lon, geo_country, COUNT(*) as count
                FROM sessions WHERE (geo_lat != 0 OR geo_lon != 0) {tw}
                GROUP BY source_ip""",
            tp,
        ).fetchall()
    return [dict(r) for r in rows]


def high_interest_sessions(limit: int = 20, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT session_id, started_at, source_ip, username, password,
                       duration_seconds, command_count, geo_country, geo_city,
                       geo_asn, is_cloud, mitre_tags, commands,
                       sophistication_score, first_cmd_category, easter_eggs_triggered,
                       is_return_visitor, visit_number
                FROM sessions WHERE high_interest = 1 {tw}
                ORDER BY started_at DESC LIMIT :limit""",
            {**tp, "limit": limit},
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["mitre_tags"] = json.loads(d["mitre_tags"])
        d["commands"] = json.loads(d["commands"])
        d["easter_eggs_triggered"] = json.loads(d.get("easter_eggs_triggered") or "[]")
        result.append(d)
    return result


def get_visit_number(ip: str) -> int:
    """Return number of prior sessions from this IP (0 = first visit)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE source_ip = ?", (ip,)
        ).fetchone()[0]


def credential_patterns(since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT password_pattern, COUNT(*) as count
                FROM sessions WHERE password_pattern != '' {tw}
                GROUP BY password_pattern ORDER BY count DESC""",
            tp,
        ).fetchall()
    return [dict(r) for r in rows]


def hourly_heatmap(since: str | None = None) -> list[dict]:
    """Attack count by UTC hour of day."""
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT CAST(strftime('%H', started_at) AS INTEGER) as hour,
                       COUNT(*) as count
                FROM sessions WHERE 1=1 {tw}
                GROUP BY hour ORDER BY hour""",
            tp,
        ).fetchall()
    by_hour = {r["hour"]: r["count"] for r in rows}
    return [{"hour": h, "count": by_hour.get(h, 0)} for h in range(24)]


def first_cmd_stats(since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT first_cmd_category, COUNT(*) as count
                FROM sessions WHERE first_cmd_category != '' AND command_count > 0 {tw}
                GROUP BY first_cmd_category ORDER BY count DESC""",
            tp,
        ).fetchall()
    return [dict(r) for r in rows]


def abandonment_stats(since: str | None = None) -> dict:
    tw, tp = _tf(since)
    with get_conn() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM sessions WHERE 1=1 {tw}", tp
        ).fetchone()[0]
        abandoned = conn.execute(
            f"SELECT COUNT(*) FROM sessions WHERE command_count = 0 {tw}", tp
        ).fetchone()[0]
    explored = total - abandoned
    return {
        "total": total,
        "abandoned": abandoned,
        "explored": explored,
        "rate": round(abandoned / max(1, total) * 100, 1),
    }


def easter_egg_leaderboard(limit: int = 17, since: str | None = None) -> list[dict]:
    tw_egg, tp_egg = _tf(since, "timestamp")
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT egg_name,
                       COUNT(*) as hit_count,
                       COUNT(DISTINCT source_ip) as unique_ips,
                       COUNT(DISTINCT geo_country) as country_count
                FROM easter_egg_hits WHERE 1=1 {tw_egg}
                GROUP BY egg_name ORDER BY hit_count DESC LIMIT :limit""",
            {**tp_egg, "limit": limit},
        ).fetchall()
    return [dict(r) for r in rows]


def sophistication_distribution(since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT sophistication_score as score, COUNT(*) as count
                FROM sessions WHERE sophistication_score > 0 {tw}
                GROUP BY sophistication_score ORDER BY sophistication_score""",
            tp,
        ).fetchall()
    by_score = {r["score"]: r["count"] for r in rows}
    return [{"score": s, "count": by_score.get(s, 0)} for s in range(1, 11)]


def return_visitors(limit: int = 20, since: str | None = None) -> list[dict]:
    tw, tp = _tf(since)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT source_ip,
                       geo_country, geo_country_code,
                       COUNT(*) as total_visits,
                       MIN(started_at) as first_seen,
                       MAX(started_at) as last_seen,
                       SUM(command_count) as total_commands,
                       MAX(sophistication_score) as max_sophistication
                FROM sessions WHERE 1=1 {tw}
                GROUP BY source_ip HAVING total_visits > 1
                ORDER BY total_visits DESC LIMIT :limit""",
            {**tp, "limit": limit},
        ).fetchall()
    return [dict(r) for r in rows]


def ip_session_history(ip: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT session_id, started_at, ended_at, username, password,
                   duration_seconds, command_count, high_interest,
                   sophistication_score, first_cmd_category, easter_eggs_triggered,
                   mitre_tags, commands
            FROM sessions
            WHERE source_ip = ?
            ORDER BY started_at ASC
            """,
            (ip,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["mitre_tags"] = json.loads(d["mitre_tags"])
        d["commands"] = json.loads(d["commands"])
        d["easter_eggs_triggered"] = json.loads(d.get("easter_eggs_triggered") or "[]")
        d["high_interest"] = bool(d["high_interest"])
        result.append(d)
    return result


# ── Live command feed ─────────────────────────────────────────────────────────

def initial_cmd_event_id(lookback: int = 50) -> int:
    """Return the event id to start the live feed from, giving ~lookback initial entries."""
    with get_conn() as conn:
        row = conn.execute(
            """SELECT MIN(id) FROM (
                 SELECT id FROM events WHERE event_type = 'command'
                 ORDER BY id DESC LIMIT ?
               )""",
            (lookback,),
        ).fetchone()
        val = row[0] if row else None
        return (val - 1) if val else 0


def new_commands_since(last_id: int, limit: int = 50) -> tuple[list[dict], int]:
    """Return command events with id > last_id (oldest-first) and the new max id."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, data FROM events
               WHERE event_type = 'command' AND id > ?
               ORDER BY id ASC LIMIT ?""",
            (last_id, limit),
        ).fetchall()
    if not rows:
        return [], last_id
    result = []
    new_max_id = last_id
    for row in rows:
        try:
            d = json.loads(row["data"])
            result.append({
                "timestamp": d.get("timestamp", ""),
                "source_ip": d.get("source_ip", ""),
                "command": d.get("command", ""),
                "mitre_tags": d.get("mitre_tags", []),
            })
            new_max_id = row["id"]
        except Exception:
            pass
    return result, new_max_id
