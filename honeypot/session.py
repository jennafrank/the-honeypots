"""Session state management for active SSH connections."""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CommandEntry:
    command: str
    timestamp: str = field(default_factory=_now_iso)
    mitre_tags: list[dict] = field(default_factory=list)
    output_lines: int = 0


@dataclass
class SessionState:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=_now_iso)
    ended_at: Optional[str] = None

    source_ip: str = ""
    source_port: int = 0
    username: str = ""
    password: str = ""
    connection_type: str = "interactive"  # 'interactive' | 'exec'

    commands: list[CommandEntry] = field(default_factory=list)
    high_interest: bool = False

    # IP enrichment — filled in asynchronously
    geo_country: str = ""
    geo_country_code: str = ""
    geo_city: str = ""
    geo_asn: str = ""
    geo_isp: str = ""
    geo_lat: float = 0.0
    geo_lon: float = 0.0
    is_cloud: bool = False
    abuse_confidence: int = 0
    rdns: str = ""

    # All unique MITRE tags across all commands
    mitre_tags: list[dict] = field(default_factory=list)

    # Files "self-destructed" during this session
    deleted_files: set = field(default_factory=set)

    @property
    def duration_seconds(self) -> float:
        if self.ended_at:
            end = datetime.fromisoformat(self.ended_at)
        else:
            end = datetime.now(timezone.utc)
        start = datetime.fromisoformat(self.started_at)
        return (end - start).total_seconds()

    @property
    def command_count(self) -> int:
        return len(self.commands)

    def add_command(self, cmd: str, tags: list[dict], output_lines: int = 0) -> CommandEntry:
        entry = CommandEntry(command=cmd, mitre_tags=tags, output_lines=output_lines)
        self.commands.append(entry)
        for tag in tags:
            if not any(t["id"] == tag["id"] for t in self.mitre_tags):
                self.mitre_tags.append(tag)
        return entry

    def mark_ended(self):
        self.ended_at = _now_iso()
        if self.duration_seconds > 60:
            self.high_interest = True

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "username": self.username,
            "password": self.password,
            "connection_type": self.connection_type,
            "duration_seconds": round(self.duration_seconds, 2),
            "command_count": self.command_count,
            "high_interest": self.high_interest,
            "geo_country": self.geo_country,
            "geo_country_code": self.geo_country_code,
            "geo_city": self.geo_city,
            "geo_asn": self.geo_asn,
            "geo_isp": self.geo_isp,
            "geo_lat": self.geo_lat,
            "geo_lon": self.geo_lon,
            "is_cloud": self.is_cloud,
            "abuse_confidence": self.abuse_confidence,
            "rdns": self.rdns,
            "mitre_tags": self.mitre_tags,
            "commands": [
                {
                    "command": c.command,
                    "timestamp": c.timestamp,
                    "mitre_tags": c.mitre_tags,
                    "output_lines": c.output_lines,
                }
                for c in self.commands
            ],
        }


class SessionRegistry:
    """Thread-safe registry of active sessions, limited to max_sessions."""

    def __init__(self, max_sessions: int = 50):
        self._sessions: dict[str, SessionState] = {}
        self._lock = asyncio.Lock()
        self._max = max_sessions

    async def add(self, session: SessionState) -> bool:
        async with self._lock:
            if len(self._sessions) >= self._max:
                return False
            self._sessions[session.session_id] = session
            return True

    async def remove(self, session_id: str) -> Optional[SessionState]:
        async with self._lock:
            return self._sessions.pop(session_id, None)

    async def get(self, session_id: str) -> Optional[SessionState]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def count(self) -> int:
        async with self._lock:
            return len(self._sessions)

    async def all(self) -> list[SessionState]:
        async with self._lock:
            return list(self._sessions.values())
