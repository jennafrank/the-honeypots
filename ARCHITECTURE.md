# Architecture

A technical breakdown of every module in Sable Saint-Claire & The Honeypots.

## High-Level Design

The system is a single Docker Compose stack with two services: the honeypot SSH server and the analytics dashboard. They share a SQLite database via a mounted volume.

```
./data/
├── db/honeypot.db       ← shared SQLite database
├── logs/events.jsonl    ← append-only JSONL event log
└── ssh/host_key         ← persistent SSH host key (survives rebuilds)
```

All source code is baked into the Docker image at build time. Code changes require `docker-compose up --build`.

---

## Module Reference

### `honeypot/server.py` — SSH Server

Built on **asyncssh** (not paramiko). Asyncssh runs the full SSH protocol stack asynchronously, which means the entire server — including every active attacker session — runs in a single Python event loop with no threads.

**Auth handling:**
- All username/password combinations are accepted
- All public key auth is accepted (fingerprint logged, no real key verification)
- `begin_auth()` is called first; auth decisions happen in `validate_password()` / `validate_public_key()`
- Login events are logged with timestamp, IP, username, and credential

**Session lifecycle:**
- `SSHServerProcess.run()` launches `FakeShell` for each connection
- Interactive sessions (real TTY) get full Easter egg support including the Snake game and REPL
- Non-interactive sessions (exec mode: `ssh host cmd`) get limited responses
- Each session gets its own `SessionState` instance

**Connection metadata:**
- IP address extracted at connection time
- IP enrichment (GeoIP + AbuseIPDB + rDNS) runs async via `enrichment.py`
- Enrichment results are attached to the session before first prompt

---

### `honeypot/shell.py` — Fake Shell

The largest and most complex module (~1,800 lines). Implements a convincing Bash shell with ~50 commands and 17 Easter eggs.

**Execution flow:**

```
FakeShell.execute(raw_cmd)
  → strip sudo prefix
  → tag_command() for MITRE
  → is_high_interest() flag check
  → is_tripwire() check → _send_easter_egg() if matched
  → _dispatch(cmd)
      → check special cases (./exec, bash -i, wget, chmod +x, cat wallet, ...)
      → dispatch table lookup
      → handler(args, write)
  → log command + tags
```

**The `write` callable:**
Every shell handler receives a `write` function that sends bytes directly to the attacker's terminal. This is raw terminal output — `\r\n` line endings required, ANSI codes fully supported.

**Easter egg architecture:**
Easter eggs are async module-level functions (`async def _fake_*`). They are not class methods. This keeps the theatrical sequences independent and composable. Each one:
1. Writes convincing output at human-readable speed via `asyncio.sleep`
2. Optionally sets `session.high_interest = True`
3. Optionally sets `self._close_session = True` to terminate after completion

**Tripwire system:**
`is_tripwire()` in `mitre.py` matches a set of patterns (credential stuffing patterns, `chattr +i`, `curl | bash`, etc.). A tripwire match fires `_send_easter_egg()` (the ACCESS GRANTED sequence) and may silently escalate the session to root.

**Command table (partial):**

| Command | Handler | Notes |
|---|---|---|
| `ls` | `_cmd_ls` | Full `-l`, `-a`, `-la` support; colored output |
| `cat` / `less` / `more` | `_cmd_cat` | Wallet gotcha + key self-destruct intercepts before normal handling |
| `top` / `htop` | `_cmd_top` | Snake game in interactive mode; fake output in exec mode |
| `rm` | `_cmd_rm` | `rm -rf <dangerous>` → `_fake_rm_rf` |
| `python` / `python3` | `_cmd_python_repl` | Interactive REPL with MemoryError crashes |
| `vim` / `vi` / `nano` | `_cmd_editor` | Functional editor UI; saves fail with read-only error |
| `passwd` | `_cmd_passwd` | Captures and logs typed passwords |
| `ssh-keygen` | `_cmd_ssh_keygen` | Infinite overwrite loop |
| `solana` | `_cmd_solana` | Subcommands: balance, validators, catchup, version |
| `whoami --verbose` | `_cmd_winner` | Coin rain celebration |

---

### `honeypot/filesystem.py` — Fake Filesystem

Two data structures drive the entire fake filesystem:

**`DIRECTORY_TREE`** — `dict[str, list[tuple[str, bool]]]`
Maps absolute paths to a list of `(name, is_directory)` entries. Powers `ls`, `cd`, `find`, and path resolution.

**`FILES`** — `dict[str, str]`
Maps absolute paths to file content strings. Powers `cat`, `less`, `more`, `head`, `tail`, `vim`, `nano`.

**`resolve_path(cwd, path)`** — resolves relative or absolute paths against the current working directory, handling `.` and `..` correctly.

Notable fake files:
- `/home/solana/wallet.json` — 47,832 SOL, triggers the gotcha
- `/home/solana/private_keys_backup.txt` — self-destructs on first read
- `/home/solana/DO_NOT_OPEN.zip` — triggers the corrupted archive sequence
- `/root/.bash_history` — pre-seeded with realistic attacker-style commands
- `/root/.aws/credentials` — fake AWS credentials (canary token)
- `/home/solana/validator-keypair.json` — convincing Solana keypair format
- `/etc/passwd`, `/etc/shadow` — fake but realistic system files

---

### `honeypot/mitre.py` — MITRE ATT&CK Tagger

A rule engine that maps shell commands to MITRE ATT&CK techniques using regex patterns.

**Structure:**
```python
RULES: list[tuple[re.Pattern, Technique]] = [
    (re.compile(r"cat\s+/etc/(passwd|shadow)"), Technique("T1003.008", ...)),
    ...
]
```

`tag_command(cmd)` scans all rules against the command string and returns a deduplicated list of matched technique dicts. Tags are stored per-command in the database.

**`is_high_interest(cmd)`** — returns True for commands that indicate post-exploitation activity: credential files, exfiltration patterns, reverse shells, persistence mechanisms.

**`is_tripwire(cmd)`** — returns True for commands that specifically warrant the ACCESS GRANTED Easter egg: `su root`, `sudo su`, certain `chattr`/`curl|bash` patterns.

---

### `honeypot/enrichment.py` — IP Enrichment

Runs three async lookups concurrently for every new source IP:

1. **GeoIP** via `ip-api.com` (free, no key required) — country, city, region, lat/lon, ASN, ISP
2. **AbuseIPDB** via their v2 API (key required) — abuse confidence score, number of reports
3. **Reverse DNS** — Python's `asyncio.get_event_loop().run_in_executor` wrapping `socket.gethostbyaddr`

Results are cached in SQLite (`ip_cache` table) to avoid re-querying the same IP across multiple sessions.

**Cloud provider detection:**
ASN strings are checked against a known list of cloud provider patterns to flag scans originating from cloud infrastructure (common for botnets and automated tooling).

---

### `honeypot/logger.py` — Event Logger

Writes structured JSONL events to disk. Every event is one JSON object per line, immediately flushed.

Event types:
- `login` — username, password/pubkey, IP, timestamp
- `command` — command string, MITRE tags, session ID
- `logout` — session duration, total commands

Also writes to the SQLite database via `db.py` for dashboard queries.

---

### `honeypot/db.py` — Database Layer

SQLite schema:

```sql
sessions   (id, ip, username, credential, started_at, ended_at,
            high_interest, connection_type, geo_*, asn, isp,
            abuse_score, rdns, is_cloud)

commands   (id, session_id, command, mitre_tags_json, line_count,
            executed_at)

ip_cache   (ip, enrichment_json, cached_at)
```

Analytics query functions used by the dashboard and report generator:
- `stats_today()` — session count, command count, unique IPs
- `top_credentials(n)` — most common username/password pairs
- `top_countries(n)` / `top_asns(n)` — geographic distribution
- `mitre_frequency(n)` — technique ID → count
- `command_frequency(n)` — most-run commands
- `hourly_volume(hours)` — time series for the attack timeline chart
- `high_interest_sessions(n)` — sessions flagged for review
- `all_ips_with_coords()` — lat/lon points for the world map

---

### `dashboard/app.py` — Analytics Dashboard

Flask app serving a single-page dashboard. Auth is HTTP Basic Auth.

**Routes:**

| Route | Description |
|---|---|
| `GET /` | Dashboard HTML |
| `GET /api/stats` | Today's totals |
| `GET /api/countries` | Top countries |
| `GET /api/asns` | Top ASNs |
| `GET /api/credentials` | Top credentials |
| `GET /api/commands` | Top commands |
| `GET /api/mitre` | Technique frequency |
| `GET /api/hourly` | Hourly attack volume |
| `GET /api/sessions` | Recent sessions |
| `GET /api/sessions/high-interest` | Flagged sessions |
| `GET /api/map` | GeoIP coordinates for map |
| `GET /api/events` | **SSE stream** (main real-time feed) |

The SSE endpoint (`/api/events`) pushes a full dashboard data packet every 3 seconds. The frontend subscribes once and updates all widgets live with no page refresh.

---

### `generate_report.py` — Report Generator

Standalone script (also runnable inside the container) that queries the database and produces:

1. A **Markdown report** with sections for executive summary, statistics, credentials, MITRE breakdown, geographic distribution, and high-interest sessions
2. An optional **PDF** generated via `markdown2` → HTML → `weasyprint` → PDF

```bash
python generate_report.py --hours 720 --pdf --out /data/reports/30day.md
```

---

## Data Flow Diagram

```
SSH Connection
     │
     ▼
asyncssh (server.py)
     │ validates auth (always accept)
     │ creates SessionState
     │ spawns enrichment coroutine ──► ip-api.com
     │                           └──► AbuseIPDB
     │                           └──► rDNS
     ▼
FakeShell (shell.py)
     │ parses command
     │ MITRE tagging (mitre.py)
     │ tripwire check
     │ Easter egg dispatch
     │ normal command dispatch
     │ write() → attacker terminal
     ▼
Logger (logger.py)
     │ JSONL append → events.jsonl
     │ SQLite insert → honeypot.db
     ▼
Dashboard (app.py)        Report (generate_report.py)
     │ SSE stream               │ Markdown + PDF
     ▼                          ▼
Browser (live)          /data/reports/
```

---

## Design Decisions

**Why asyncssh instead of paramiko?**
asyncssh is fully async — a single event loop handles all concurrent attacker sessions with no threads, no GIL contention, and no per-session overhead. Paramiko is synchronous and would require threads.

**Why SQLite instead of Postgres?**
Zero operational overhead. A honeypot is a single-node deployment; SQLite is sufficient for the query volume and the data fits comfortably in a single file that's easy to copy, back up, and inspect.

**Why one Docker container per service?**
The honeypot and dashboard are kept separate so a crash in the dashboard doesn't take down data collection, and vice versa. They share only the data volume.

**Why JSONL in addition to SQLite?**
JSONL is grep-able, cat-able, and easy to ship to a SIEM or S3 bucket. SQLite is queryable and dashboard-friendly. Both are maintained in parallel.

**Why weasyprint for PDF?**
It generates PDFs from HTML+CSS, which means the report style is controlled with CSS rather than a proprietary PDF API. The output is professional and easily customizable.
