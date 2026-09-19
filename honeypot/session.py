"""Session state management for active SSH connections."""

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── First-command category classifier ────────────────────────────────────────

_RECON_CMDS = frozenset({
    "uname", "whoami", "id", "hostname", "ps", "w", "last",
    "uptime", "lscpu", "lsb_release", "arch", "cat", "head",
})
_CRYPTO_CMDS = frozenset({"solana", "solana-keygen", "solana-validator"})
_DOWNLOAD_CMDS = frozenset({"wget", "curl", "apt", "apt-get", "yum", "pip", "pip3", "git"})
_PERSIST_CMDS = frozenset({"ssh-keygen", "crontab", "systemctl", "chkconfig", "at"})
_LATERAL_CMDS = frozenset({"ssh", "nc", "ncat", "telnet", "scp", "ftp"})
_ESCALATION_CMDS = frozenset({"sudo", "su", "passwd", "chattr", "chmod"})
_ENUM_CMDS = frozenset({"ls", "find", "grep", "locate", "which", "file", "stat"})


def categorize_first_command(cmd: str) -> str:
    if not cmd:
        return "other"
    parts = cmd.strip().split()
    base = parts[0].lower() if parts else ""
    combined = cmd.lower()

    if base in _DOWNLOAD_CMDS:
        return "download"
    if any(w in combined for w in ("solana", "wallet", "keypair", "bitcoin", "crypto", "mnemonic")):
        return "crypto_hunting"
    if base in _CRYPTO_CMDS:
        return "crypto_hunting"
    if base in _PERSIST_CMDS or any(w in combined for w in (".ssh/", "authorized_keys")):
        return "persistence"
    if base in _LATERAL_CMDS:
        return "lateral_movement"
    if any(w in combined for w in ("histfile=", "histsize=0", "history -c")):
        return "anti_forensics"
    if base in _ESCALATION_CMDS:
        return "escalation"
    if base in _RECON_CMDS or any(w in combined for w in ("/etc/passwd", "/proc/", "uname", "whoami")):
        return "recon"
    if base in _ENUM_CMDS:
        return "enumeration"
    return "other"


# ── Password pattern classifier ───────────────────────────────────────────────

_SERVICE_DEFAULTS = frozenset({
    "root", "admin", "administrator", "user", "test", "guest", "default",
    "ubuntu", "debian", "centos", "oracle", "postgres", "mysql", "ftp",
    "apache", "nginx", "vagrant", "pi", "raspberry", "pass", "passwd",
    "password", "login", "changeme", "letmein", "openwrt", "admin1",
    "1234", "123", "12345", "1234567890", "123456789",
})
_IOT_DEFAULTS = frozenset({
    "admin123", "admin1234", "hikadmin", "xmhdipc", "vizxv", "dvr2580222",
    "support", "service", "supervisor", "system", "7ujMko0admin", "7ujMko0vizxv",
    "realtek", "jauntech", "Zte521", "huigu309", "888888", "666666",
    "ipcam", "camera", "ikwb", "000000",
})
_KEYBOARD_WALKS = frozenset({
    "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "1qaz2wsx", "q1w2e3r4", "1q2w3e4r", "qazwsx",
    "!qaz2wsx", "1qaz@wsx", "qwe123", "abc123", "abcdef",
    "pass123", "pass1234", "!@#$%^",
})
_CRYPTO_WORDS = frozenset({
    "wallet", "bitcoin", "crypto", "solana", "ethereum", "btc", "eth",
    "seed", "mnemonic", "keypair", "validator", "stake", "defi", "nft",
    "metamask", "ledger", "trezor", "blockchain", "satoshi",
})


def classify_password(password: str) -> str:
    if not password or password.startswith("pubkey:"):
        return "pubkey"
    lower = password.lower()
    if lower in _SERVICE_DEFAULTS:
        return "service_default"
    if password in _IOT_DEFAULTS or lower in _IOT_DEFAULTS:
        return "iot_default"
    if any(w in lower for w in _CRYPTO_WORDS):
        return "crypto_related"
    if lower in _KEYBOARD_WALKS or re.match(r"^(qwerty|asdf|zxcv|abcd|0987|4321)", lower):
        return "keyboard_walk"
    if re.match(r"^\d+$", password):
        return "numeric_only"
    if re.match(r"^[a-zA-Z]{4,15}$", password):
        return "dictionary_word"
    return "custom"


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

    # Advanced tracking metrics
    sophistication_score: int = 0
    password_pattern: str = ""
    is_return_visitor: bool = False
    visit_number: int = 1
    first_cmd_category: str = ""
    easter_eggs_triggered: list = field(default_factory=list)

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
        if len(self.commands) == 1:
            self.first_cmd_category = categorize_first_command(cmd)
        return entry

    def compute_sophistication_score(self) -> int:
        cmds = [c.command for c in self.commands]
        if not cmds:
            return 1
        score = 1
        combined = " ".join(cmds).lower()
        # Command volume (+1 per 5 commands, max +3)
        score += min(3, len(cmds) // 5)
        # Anti-forensics
        if any(w in combined for w in ("histfile=", "histsize=0", "history -c", "unset histfile")):
            score += 2
        # Network tunneling via /dev/tcp
        if "/dev/tcp" in combined:
            score += 2
        # Active download
        if re.search(r"\b(wget|curl)\s+https?://", combined):
            score += 1
        # Extended session = deliberate exploration
        if self.duration_seconds > 120:
            score += 1
        # Command diversity (many unique tools)
        bases = {c.strip().split()[0] for c in cmds if c.strip()}
        if len(cmds) >= 5 and len(bases) / len(cmds) > 0.6:
            score += 1
        # MITRE tactic breadth
        if len({t.get("tactic", "") for t in self.mitre_tags}) >= 3:
            score += 1
        return min(10, max(1, score))

    def mark_ended(self):
        self.ended_at = _now_iso()
        if self.duration_seconds > 60:
            self.high_interest = True
        self.sophistication_score = self.compute_sophistication_score()

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
            "sophistication_score": self.sophistication_score,
            "password_pattern": self.password_pattern,
            "is_return_visitor": self.is_return_visitor,
            "visit_number": self.visit_number,
            "first_cmd_category": self.first_cmd_category,
            "easter_eggs_triggered": list(self.easter_eggs_triggered),
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
