"""asyncssh SSH honeypot server — handles auth, exec, and interactive sessions."""

import asyncio
import logging
import os
import random
from datetime import datetime, timezone
from typing import Optional

import asyncssh

from .enrichment import enrich_ip
from .logger import log_command, log_connect, log_disconnect, log_enrichment
from .session import SessionRegistry, SessionState
from .shell import FakeShell

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", 300))
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", 50))

_registry = SessionRegistry(max_sessions=MAX_CONNECTIONS)

# ── Temporary IP ban list (ip → expiry timestamp) ─────────────────────────────
_ip_bans: dict[str, float] = {}


def ban_ip(ip: str, duration: float = 60.0) -> None:
    """Ban an IP from authenticating for `duration` seconds."""
    import time
    _ip_bans[ip] = time.monotonic() + duration
    logger.info("Banned %s for %.0fs", ip, duration)


def _is_banned(ip: str) -> bool:
    import time
    expiry = _ip_bans.get(ip)
    if expiry is None:
        return False
    if time.monotonic() < expiry:
        return True
    del _ip_bans[ip]
    return False

# ── MOTD ──────────────────────────────────────────────────────────────────────
_MOTD = (
    "\r\n"
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-75-generic x86_64)\r\n"
    "\r\n"
    " * Solana Validator Node  [validator-node-01]\r\n"
    " * Network: mainnet-beta | Version: 1.17.6\r\n"
    "\r\n"
    "  System load:  2.43             Processes:             147\r\n"
    "  Memory usage: 67%              IPv4 address for eth0: 10.0.1.5\r\n"
    "  Swap usage:   0%\r\n"
    "\r\n"
    "  Validator: ACTIVE | Vote credits: 19,847,234 | Last vote: slot 287,834,521\r\n"
    "\r\n"
    "Last login: {last_login} from {last_ip}\r\n"
    "\r\n"
)

_LAST_LOGINS = [
    ("Sun Jan 14 18:41:33 2024", "198.51.100.7"),
    ("Sat Jan 13 09:12:05 2024", "203.0.113.55"),
    ("Fri Jan 12 22:30:44 2024", "192.0.2.88"),
]


# ── Auth server ───────────────────────────────────────────────────────────────

class HoneypotServer(asyncssh.SSHServer):
    """Accept every auth attempt after a realistic 1-3 second delay."""

    def __init__(self):
        self._conn: Optional[asyncssh.SSHServerConnection] = None
        self._pending_session: Optional[SessionState] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        logger.debug("TCP connect from %s:%s", peer[0], peer[1])

    def connection_lost(self, exc) -> None:
        if exc:
            logger.debug("Connection lost: %s", exc)
        # Final log for the whole SSH connection (covers all channels/execs on it)
        if self._pending_session:
            self._pending_session.mark_ended()
            asyncio.create_task(_finish_session(self._pending_session))
            self._pending_session = None

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return False

    async def begin_auth(self, username: str) -> bool:
        return True  # proceed to auth challenge

    async def validate_password(self, username: str, password: str) -> bool:
        return await self._accept_auth(username, password)

    async def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        fp = key.get_fingerprint()
        return await self._accept_auth(username, f"pubkey:{fp}")

    async def _accept_auth(self, username: str, credential: str) -> bool:
        await asyncio.sleep(random.uniform(1.0, 3.0))

        if not self._conn:
            return False
        peer = self._conn.get_extra_info("peername") or ("0.0.0.0", 0)
        ip, port = peer[0], peer[1]

        if _is_banned(ip):
            logger.info("Rejected banned IP %s", ip)
            return False

        session = SessionState(
            source_ip=ip,
            source_port=port,
            username=username,
            password=credential,
        )

        if not await _registry.add(session):
            logger.warning("Connection limit reached, dropping %s", ip)
            return False

        self._pending_session = session
        log_connect(session)
        asyncio.create_task(_enrich_and_log(session))
        logger.info("Login accepted: %s@%s (cred=%s)", username, ip, credential)
        return True

    def session_requested(self):
        if not self._pending_session:
            return False
        return HoneypotSession(self._pending_session)


# ── Session handler ───────────────────────────────────────────────────────────

class HoneypotSession(asyncssh.SSHServerSession):
    """One SSH session — handles both exec and interactive shell."""

    def __init__(self, session: SessionState):
        self._session = session
        self._chan: Optional[asyncssh.SSHServerChannel] = None
        self._input_queue: asyncio.Queue = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None
        self._shell: Optional[FakeShell] = None

    # asyncssh callbacks ──────────────────────────────────────────────────────

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan

    def shell_requested(self) -> bool:
        self._session.connection_type = "interactive"
        self._task = asyncio.create_task(self._run_interactive())
        return True

    def exec_requested(self, command: str) -> bool:
        self._session.connection_type = "exec"
        self._task = asyncio.create_task(self._run_exec(command))
        return True

    def pty_requested(self, term_type, term_size, term_modes) -> bool:
        return True

    def window_change_requested(self, *args) -> bool:
        return True

    def data_received(self, data: str, datatype) -> None:
        self._input_queue.put_nowait(data)

    def eof_received(self) -> bool:
        self._input_queue.put_nowait(None)
        return False

    def connection_lost(self, exc) -> None:
        self._input_queue.put_nowait(None)
        if self._task and not self._task.done():
            self._task.cancel()

    # Internal helpers ────────────────────────────────────────────────────────

    def _write(self, data: str) -> None:
        if self._chan and not self._chan.is_closing():
            try:
                self._chan.write(data)
            except Exception:
                pass

    def _exit(self, code: int = 0) -> None:
        if self._chan and not self._chan.is_closing():
            try:
                self._chan.exit(code)
            except Exception:
                pass

    async def _run_exec(self, command: str) -> None:
        shell = FakeShell(self._session, self._session.username, input_queue=self._input_queue)
        try:
            async with asyncio.timeout(SESSION_TIMEOUT):
                await shell.execute(command, self._write)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.debug("Exec error: %s", exc)
        self._exit(0)

    async def _run_interactive(self) -> None:
        shell = FakeShell(self._session, self._session.username, input_queue=self._input_queue)
        last_login = random.choice(_LAST_LOGINS)
        self._write(_MOTD.format(last_login=last_login[0], last_ip=last_login[1]))
        self._write(shell.prompt())

        line_buf = ""
        in_escape = ""

        try:
            async with asyncio.timeout(SESSION_TIMEOUT):
                while True:
                    chunk = await self._input_queue.get()
                    if chunk is None:
                        break

                    for ch in chunk:
                        # Absorb multi-byte ANSI escape sequences
                        if in_escape:
                            in_escape += ch
                            if len(in_escape) >= 3 or (len(in_escape) >= 2 and ch.isalpha()):
                                in_escape = ""
                            continue
                        if ch == "\x1b":
                            in_escape = ch
                            continue

                        if ch in ("\r", "\n"):
                            self._write("\r\n")
                            cmd = line_buf.strip()
                            line_buf = ""
                            if cmd:
                                keep_going = await shell.execute(cmd, self._write)
                                if not keep_going:
                                    self._exit(0)
                                    return
                            self._write(shell.prompt())

                        elif ch in ("\x7f", "\x08"):
                            if line_buf:
                                line_buf = line_buf[:-1]
                                self._write("\x08 \x08")

                        elif ch == "\x03":
                            self._write("^C\r\n")
                            line_buf = ""
                            self._write(shell.prompt())

                        elif ch == "\x04":
                            if not line_buf:
                                self._exit(0)
                                return

                        elif ch == "\x0c":
                            self._write("\x1b[2J\x1b[H")
                            self._write(shell.prompt())
                            if line_buf:
                                self._write(line_buf)

                        elif ch == "\t":
                            pass  # no completion

                        elif ord(ch) >= 32:
                            line_buf += ch
                            self._write(ch)

        except asyncio.TimeoutError:
            self._write("\r\nSession timeout — connection closed.\r\n")
            self._exit(0)
        except (asyncio.CancelledError, Exception) as exc:
            if not isinstance(exc, asyncio.CancelledError):
                logger.debug("Interactive shell error: %s", exc)


# ── Background helpers ────────────────────────────────────────────────────────

async def _enrich_and_log(session: SessionState) -> None:
    try:
        data = await enrich_ip(session.source_ip)
        session.geo_country     = data.get("geo_country", "")
        session.geo_country_code = data.get("geo_country_code", "")
        session.geo_city        = data.get("geo_city", "")
        session.geo_asn         = data.get("geo_asn", "")
        session.geo_isp         = data.get("geo_isp", "")
        session.geo_lat         = data.get("geo_lat", 0.0)
        session.geo_lon         = data.get("geo_lon", 0.0)
        session.is_cloud        = data.get("is_cloud", False)
        session.abuse_confidence = data.get("abuse_confidence", 0)
        session.rdns            = data.get("rdns", "")
        log_enrichment(session)
    except Exception as exc:
        logger.debug("Enrichment failed for %s: %s", session.source_ip, exc)


async def _finish_session(session: SessionState) -> None:
    await _registry.remove(session.session_id)
    log_disconnect(session)
    logger.info(
        "Session closed  ip=%s user=%s duration=%.1fs cmds=%d hi=%s",
        session.source_ip,
        session.username,
        session.duration_seconds,
        session.command_count,
        session.high_interest,
    )


# ── Server startup ────────────────────────────────────────────────────────────

async def start_server(
    host: str = "",
    port: int = 22,
    key_path: str = "/data/ssh/host_key",
):
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    if not os.path.exists(key_path):
        logger.info("Generating RSA host key → %s", key_path)
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(key_path)

    server = await asyncssh.create_server(
        HoneypotServer,
        host,
        port,
        server_host_keys=[key_path],
        allow_pty=True,
        # Disable asyncssh's built-in line editor so every keystroke is
        # delivered immediately to data_received() without buffering or echo.
        # Our _run_interactive loop handles echo and line editing itself.
        line_editor=False,
        x11_forwarding=False,
        agent_forwarding=False,
        login_timeout=30,
        keepalive_interval=30,
        keepalive_count_max=3,
    )
    logger.info("SSH honeypot listening on %s:%d", host or "0.0.0.0", port)
    return server
