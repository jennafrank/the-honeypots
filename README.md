```
 ██████╗ ██████╗██╗    ███████╗    ██████╗ ████████╗      ██████╗██╗      █████╗ ██╗██████╗ ███████╗
██╔════╝██╔════╝██║    ██╔════╝   ██╔════╝╚══██╔══╝     ██╔════╝██║     ██╔══██╗██║██╔══██╗██╔════╝
╚█████╗ ███████╗██║    ███████╗   ╚█████╗    ██║   █████╗██║     ██║     ███████║██║██████╔╝█████╗
 ╚═══██╗██╔══╝ ██║    ██╔════╝    ╚═══██╗   ██║         ██║     ██║     ██╔══██║██║██╔══██╗██╔══╝
██████╔╝███████╗██║    ███████╗   ██████╔╝   ██║          ╚██████╗███████╗██║  ██║██║██║  ██║███████╗
╚═════╝ ╚══════╝╚═╝    ╚══════╝   ╚═════╝    ╚═╝           ╚═════╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝

  ♦ ♦ ♦   S A I N T - C L A I R E   &   T H E   H O N E Y P O T S   ♦ ♦ ♦
```

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![asyncssh](https://img.shields.io/badge/asyncssh-2.14%2B-orange?style=flat-square)](https://asyncssh.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square&logo=linux)](https://linux.org)

**A Python SSH honeypot disguised as a Solana validator node, with 17 Easter eggs, real-time analytics dashboard, and MITRE ATT&CK mapping.**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Easter Eggs](#easter-eggs)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Dashboard](#dashboard)
- [Report Generation](#report-generation)
- [Legal & Ethics](#legal--ethics)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## Overview

Sable Saint-Claire & The Honeypots is a **production-grade SSH honeypot** that impersonates a high-value Solana validator node. Attackers who connect are dropped into a fully convincing fake Bash shell — complete with realistic process lists, wallet balances, validator logs, and canary files — while every keystroke is silently logged, GeoIP-enriched, AbuseIPDB-checked, and MITRE ATT&CK-tagged in real time.

Then the Easter eggs fire. And they *will* find them.

Designed as a 30-day threat intelligence research platform. Built to be studied, starred, and forked.

---

## Features

### 🎭 Deception Layer
- **Fake Solana Validator Identity** — complete with a `solana-validator` process, RPC port 8899, vote accounts, staking balance (47,832 SOL), epoch data, and a live-looking `journalctl` feed
- **50+ Simulated Commands** — `ls`, `cat`, `ps aux`, `netstat`, `ss`, `top`, `find`, `grep`, `history`, `crontab`, `systemctl`, `journalctl`, `solana balance`, `solana validators`, and more — all returning contextually accurate fake output
- **Realistic Filesystem** — 60+ files across `/home/solana/`, `/root/`, `/etc/`, `/var/log/`, and validator-specific paths
- **Canary Token Files** — `wallet.json`, `private_keys_backup.txt`, and `DO_NOT_OPEN.zip` act as tripwires with different behaviors on access

### 🥚 17 Easter Eggs
See the [Easter Eggs](#easter-eggs) section — triggers listed, effects hidden. Discover them yourself.

### 📊 Real-Time Analytics Dashboard
- **Server-Sent Events (SSE)** stream pushing live updates every 3 seconds
- **World Map** of attacker origins with GeoIP coordinates
- **Attack Timeline** — hourly volume chart
- **MITRE ATT&CK Heatmap** — live technique frequency across all sessions
- **Credential Table** — top username/password combos being sprayed
- **High-Interest Sessions** — flagged sessions with full command history
- **ASN & Country Breakdown** — where are they coming from and who owns the IP block

### 🌐 GeoIP Enrichment
- Country, city, region, latitude/longitude via **ip-api.com**
- ISP and ASN identification
- Cloud provider detection (AWS, GCP, Azure, DigitalOcean, Vultr, etc.)
- Reverse DNS lookup

### 🚨 AbuseIPDB Integration
- Confidence score for known malicious IPs
- Automatic flagging of repeat offenders
- Enrichment stored per-session for reporting

### 🗺 MITRE ATT&CK Mapping
Every command is automatically tagged against the MITRE ATT&CK framework. Techniques currently mapped include:

| Tactic | Techniques |
|---|---|
| Credential Access | T1003.008, T1552.001, T1552.007 |
| Command & Control | T1105, T1071.001 |
| Persistence | T1053.003, T1136.001, T1098.004 |
| Defense Evasion | T1070.003, T1222.002, T1562.004 |
| Privilege Escalation | T1548.001, T1548.003 |
| Execution | T1059.004, T1059.006 |
| Discovery | T1016, T1033, T1049, T1057, T1082, T1083, T1654 |

### 📋 Automated Report Generation
- **Markdown + PDF reports** from any time window (`--hours 48`, `--hours 720`)
- Sections: executive summary, attack statistics, credential analysis, MITRE breakdown, top commands, high-interest sessions, geographic distribution
- Powered by `weasyprint` for professional PDF output
- Designed for a 30-day research methodology

---

## Screenshots

| | |
|:---:|:---:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Login Screen](docs/screenshots/login_screen.png) |
| **[Dashboard]** Real-time SSE analytics | **[Login Screen]** What attackers see on connect |
| ![Wallet Gotcha](docs/screenshots/wallet_gotcha.png) | ![Snake Game](docs/screenshots/snake_game.png) |
| **[Wallet Gotcha]** The Sable Saint-Claire reveal | **[Snake Game]** `top` isn't what they expected |
| ![Malware Scare](docs/screenshots/malware_scare.png) | ![30-Day Report](docs/screenshots/report.png) |
| **[Malware Scare]** `wget` consequences | **[30-Day Report]** Automated PDF output |

---

## Easter Eggs

There are **17** of them. Some fire immediately. Some take a sequence. Some are traps that never end.

Below are the trigger commands — but **not** what they do. That's for you to find out.

| # | Trigger | Hint |
|:---:|---|---|
| 1 | `cat wallet.json` | The crown jewel. The whole reason this thing exists. |
| 2 | `top` | This is not a process list. |
| 3 | `whoami --verbose` | The secret flag that nobody expects. |
| 4 | `rm -rf /` | Classic. They always try it. |
| 5 | `unzip DO_NOT_OPEN.zip` | The name is right there. |
| 6 | `wget <url>` | Ingress tool transfer? Sure. |
| 7 | `curl <url>` | Same energy, different command. |
| 8 | `chmod +x <file>` | Making things executable has consequences. |
| 9 | `bash -i` | Spawning an interactive shell. Bold move. |
| 10 | `./<anything>` | Running executables goes exactly how you'd expect. |
| 11 | `su root` / `sudo su` | The privilege escalation attempt. |
| 12 | `cat private_keys_backup.txt` | This file has a very short lifespan. |
| 13 | `python3` (interactive) | The REPL is real. Mostly. |
| 14 | `ssh-keygen` | Persistence attempt. It goes sideways. |
| 15 | `passwd` | Someone's trying to change the password. We noticed. |
| 16 | `mkfs.ext4 /dev/sda` | The nuclear option. |
| 17 | `exit` | *"You can check out any time you like..."* |

> 💡 Want to add one? See [CONTRIBUTING.md](CONTRIBUTING.md) and [EASTER_EGGS.md](EASTER_EGGS.md).

---

## Architecture

```
                         ┌─────────────────────────────────────────┐
    Internet             │           Docker Container              │
       │                 │                                         │
       ▼                 │   ┌───────────────────────────────┐    │
  Port 22 (SSH) ────────────►│    asyncssh Server            │    │
                         │   │    server.py                  │    │
                         │   └──────────────┬────────────────┘    │
                         │                  │                      │
                         │   ┌──────────────▼────────────────┐    │
                         │   │    Fake Shell                 │    │
                         │   │    shell.py                   │    │
                         │   │  ┌──────────┐ ┌───────────┐  │    │
                         │   │  │ 50+ Cmds │ │ 17 Eggs   │  │    │
                         │   │  └──────────┘ └───────────┘  │    │
                         │   │  ┌──────────────────────────┐ │    │
                         │   │  │  MITRE Tagger (mitre.py) │ │    │
                         │   │  └──────────────────────────┘ │    │
                         │   └──────────────┬────────────────┘    │
                         │                  │                      │
                         │   ┌──────────────▼────────────────┐    │
                         │   │    Logger + Enrichment        │    │
                         │   │    logger.py / enrichment.py  │    │
                         │   │  ┌──────────┐ ┌────────────┐  │    │
                         │   │  │  GeoIP   │ │ AbuseIPDB  │  │    │
                         │   │  └──────────┘ └────────────┘  │    │
                         │   └──────────────┬────────────────┘    │
                         │                  │                      │
                         │   ┌──────────────▼────────────────┐    │
                         │   │    SQLite Database            │    │
                         │   │    db.py                      │    │
                         │   │  Sessions │ Commands │ Cache   │    │
                         │   └──────────────┬────────────────┘    │
                         │                  │                      │
                         └──────────────────┼──────────────────────┘
                                            │
                         ┌──────────────────▼──────────────────────┐
                         │    Dashboard (Port 8080)                 │
                         │    dashboard/app.py (Flask + SSE)        │
                         │  ┌──────────┐ ┌──────────┐ ┌─────────┐ │
                         │  │ World Map│ │  MITRE   │ │Timeline │ │
                         │  └──────────┘ └──────────┘ └─────────┘ │
                         └─────────────────────────────────────────┘
```

### Module Summary

| File | Purpose |
|---|---|
| `honeypot/server.py` | asyncssh server, auth handling, session lifecycle |
| `honeypot/shell.py` | Fake Bash shell — commands, Easter eggs, tripwires |
| `honeypot/filesystem.py` | Fake filesystem (60+ files, directory tree) |
| `honeypot/mitre.py` | MITRE ATT&CK auto-tagger (20+ technique rules) |
| `honeypot/enrichment.py` | Async GeoIP + AbuseIPDB + rDNS enrichment |
| `honeypot/logger.py` | Structured JSONL event logging |
| `honeypot/db.py` | SQLite persistence + analytics queries |
| `honeypot/session.py` | Session state model |
| `dashboard/app.py` | Flask dashboard with SSE stream |
| `generate_report.py` | Markdown + PDF report generator |

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full technical breakdown.

---

## Quick Start

### Prerequisites

- Linux VM (Azure, AWS, GCP, DigitalOcean, or bare metal)
- Docker + Docker Compose
- Port 22 exposed (or any port — configure in `.env`)

### Deploy

```bash
# Clone the repo
git clone https://github.com/yourusername/sable-saint-claire.git
cd sable-saint-claire

# Copy and configure environment
cp .env.example .env
nano .env   # set ABUSEIPDB_KEY and DASHBOARD_PASSWORD at minimum

# Build and launch
docker-compose up --build -d

# Verify it's running
docker-compose logs -f honeypot
```

The honeypot will be live on port 22. The dashboard runs on port 8080.

### First Login (confirm it works)

```bash
ssh root@your-server-ip
# Password: anything — it accepts all credentials
```

### Rebuild After Code Changes

```bash
# Always rebuild — code is baked into the image at build time
docker-compose up --build -d
```

### View Logs

```bash
# Live event stream
tail -f data/logs/events.jsonl | python3 -m json.tool

# Container logs
docker-compose logs -f honeypot
```

---

## Configuration

All configuration lives in `.env`. Copy `.env.example` to get started.

```env
# SSH server port (set to 22 for production; use 2222 for testing)
HONEYPOT_PORT=22

# AbuseIPDB API key — free tier works fine
# https://www.abuseipdb.com/account/api
ABUSEIPDB_KEY=your_key_here

# Dashboard credentials (Basic Auth)
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=change_this_in_production

# Data paths (mapped via Docker volume to ./data/)
DB_PATH=/data/db/honeypot.db
LOG_PATH=/data/logs/events.jsonl
SSH_HOST_KEY=/data/ssh/host_key
```

| Variable | Default | Description |
|---|---|---|
| `HONEYPOT_PORT` | `22` | SSH listen port |
| `ABUSEIPDB_KEY` | *(empty)* | AbuseIPDB API key (optional — enrichment skipped if absent) |
| `DASHBOARD_USERNAME` | `admin` | Dashboard Basic Auth username |
| `DASHBOARD_PASSWORD` | `changeme` | Dashboard Basic Auth password — **change this** |

---

## Dashboard

Access the real-time dashboard at `http://your-server:8080`.

```
┌─────────────────────────────────────────────────────────┐
│  Sable Saint-Claire & The Honeypots   [Live ● ]        │
├──────────────┬──────────────┬────────────┬──────────────┤
│  Sessions    │  Commands    │  Countries │  Unique IPs  │
│  Today: 142  │  Today: 891  │     38     │      67      │
├──────────────┴──────────────┴────────────┴──────────────┤
│                    World Map                            │
│  [ ... attack origin dots ... ]                        │
├─────────────────────────┬───────────────────────────────┤
│  MITRE ATT&CK Heatmap  │  Hourly Attack Volume         │
│  Discovery     ████████ │  ▂▄▆█▄▃▂▁▄▇█▅▃▂▁▄▆█          │
│  Credential    ████████ │                               │
│  Execution     ████     │                               │
├─────────────────────────┼───────────────────────────────┤
│  Top Credentials        │  Top Countries                │
│  root / 123456   ███    │  China          ████████      │
│  admin / admin   ██     │  Russia         █████         │
│  root / password ██     │  United States  ████          │
└─────────────────────────┴───────────────────────────────┘
```

The dashboard uses **Server-Sent Events** — no polling, no WebSocket dependency. Data refreshes every 3 seconds automatically.

---

## Report Generation

Generate a threat intelligence report for any time window:

```bash
# 48-hour Markdown report (default)
docker-compose exec honeypot python generate_report.py

# 30-day report with PDF output
docker-compose exec honeypot python generate_report.py --hours 720 --pdf

# Custom output path
docker-compose exec honeypot python generate_report.py \
    --hours 168 \
    --out /data/reports/week1.md \
    --pdf
```

Reports include:
- Executive summary with key metrics
- Credential spray analysis (top username/password pairs)
- MITRE ATT&CK technique breakdown with percentages
- Top 10 attacking ASNs and countries
- Command frequency heatmap
- Flagged high-interest sessions with full command history
- Geographic distribution

See [REPORT_TEMPLATE.md](REPORT_TEMPLATE.md) for the full report structure and research methodology.

---

## Legal & Ethics

> **This software is intended for authorized security research, education, and threat intelligence gathering on systems you own or have explicit permission to monitor.**

**Do not deploy this on infrastructure you do not own.** Capturing credentials and session data from unauthorized users may violate computer fraud laws in your jurisdiction. Consult applicable laws (CFAA, Computer Misuse Act, etc.) before deployment.

**What this honeypot does collect:**
- Source IP address
- All typed commands
- All credential attempts (usernames and passwords)
- Session timing and duration
- Geolocation data (via third-party APIs)

**What this honeypot does not do:**
- Execute any real commands
- Provide any actual system access
- Exfiltrate data from the host system
- Perform any active offensive actions

Deploy responsibly. Log ethically. Research rigorously.

---

## Contributing

Contributions welcome — especially new Easter eggs.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
To suggest a new Easter egg, open an issue using the [Easter Egg Suggestion](.github/ISSUE_TEMPLATE/easter_egg_suggestion.md) template.

---

## Author

**Built by Jenna Frank — Cybersecurity Student & Researcher**

*"The best way to understand attackers is to let them think they've won."*

---

## License

MIT © Jenna Frank — see [LICENSE](LICENSE) for details.
