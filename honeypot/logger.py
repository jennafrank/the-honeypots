"""Structured JSON logging — writes to SQLite and a JSONL flat file."""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from .db import insert_event, upsert_session
from .session import SessionState

LOG_PATH = os.environ.get("LOG_PATH", "/data/logs/events.jsonl")
_log = logging.getLogger(__name__)


def _ensure_log_dir() -> None:
    Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)


def _append_jsonl(record: dict) -> None:
    _ensure_log_dir()
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        _log.warning("JSONL write failed: %s", exc)


def log_connect(session: SessionState) -> None:
    data = {
        "event": "connect",
        "session_id": session.session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": session.source_ip,
        "source_port": session.source_port,
        "username": session.username,
        "password": session.password,
        "connection_type": session.connection_type,
    }
    _append_jsonl(data)
    insert_event(session.session_id, "connect", data)
    # Write initial session row so dashboard sees it immediately
    upsert_session(session.to_dict())


def log_command(session: SessionState, command: str, mitre_tags: list[dict]) -> None:
    data = {
        "event": "command",
        "session_id": session.session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": session.source_ip,
        "command": command,
        "mitre_tags": mitre_tags,
    }
    _append_jsonl(data)
    insert_event(session.session_id, "command", data)
    upsert_session(session.to_dict())


def log_disconnect(session: SessionState) -> None:
    data = {
        "event": "disconnect",
        "session_id": session.session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": session.source_ip,
        "duration_seconds": round(session.duration_seconds, 2),
        "command_count": session.command_count,
        "high_interest": session.high_interest,
    }
    _append_jsonl(data)
    insert_event(session.session_id, "disconnect", data)
    upsert_session(session.to_dict())


def log_enrichment(session: SessionState) -> None:
    data = {
        "event": "enrichment",
        "session_id": session.session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": session.source_ip,
        "geo_country": session.geo_country,
        "geo_city": session.geo_city,
        "geo_asn": session.geo_asn,
        "geo_isp": session.geo_isp,
        "is_cloud": session.is_cloud,
        "abuse_confidence": session.abuse_confidence,
        "rdns": session.rdns,
    }
    _append_jsonl(data)
    insert_event(session.session_id, "enrichment", data)
    upsert_session(session.to_dict())


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
