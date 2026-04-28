"""Fake Ubuntu 22.04 shell: command dispatch, fake output, Easter eggs."""

import asyncio
import random
import re
import shlex
from datetime import datetime, timezone
from typing import Optional

from .filesystem import (
    FILES, DIRECTORY_TREE, resolve_path, is_dir, is_file,
    list_dir, read_file, path_exists,
)
from .mitre import tag_command, is_high_interest, is_tripwire
from .session import SessionState

# Import lazily to avoid circular deps at module load time
def _log_command(session, command, tags):
    from .logger import log_command
    log_command(session, command, tags)

# ── ANSI helpers ─────────────────────────────────────────────────────────────
_RESET = "\x1b[0m"
_BOLD  = "\x1b[1m"
_GREEN = "\x1b[32m"
_CYAN  = "\x1b[36m"
_BLUE  = "\x1b[34m"
_WHITE = "\x1b[37m"

def _dir_color(name: str, is_directory: bool) -> str:
    if is_directory:
        return f"\x1b[1;34m{name}\x1b[0m"
    if name.endswith((".sh", ".py", ".rb", ".pl")):
        return f"\x1b[1;32m{name}\x1b[0m"
    return name


# ── Fake process list ─────────────────────────────────────────────────────────
_PS_AUX = """\
USER         PID %CPU %MEM    VSZ      RSS  TTY      STAT START   TIME COMMAND
root           1  0.0  0.0 167876   11244 ?        Ss   Jan15   0:04 /sbin/init
root           2  0.0  0.0      0       0 ?        S    Jan15   0:00 [kthreadd]
root           3  0.0  0.0      0       0 ?        I<   Jan15   0:00 [rcu_gp]
root           4  0.0  0.0      0       0 ?        I<   Jan15   0:00 [rcu_par_gp]
root          11  0.0  0.0      0       0 ?        I<   Jan15   0:00 [mm_percpu_wq]
root          12  0.0  0.0      0       0 ?        S    Jan15   0:00 [ksoftirqd/0]
root          13  0.2  0.0      0       0 ?        I    Jan15   2:31 [rcu_sched]
root          14  0.0  0.0      0       0 ?        S    Jan15   0:00 [migration/0]
root          34  0.0  0.0      0       0 ?        S    Jan15   0:00 [cpuhp/0]
root          89  0.0  0.0      0       0 ?        S    Jan15   0:00 [kdevtmpfs]
root         182  0.0  0.0      0       0 ?        S    Jan15   0:00 [kworker/0:3]
root         340  0.0  0.0  22420    2096 ?        Ss   Jan15   0:00 /lib/systemd/systemd-udevd
root         567  0.0  0.0  99900    3640 ?        Ssl  Jan15   0:03 /sbin/dhclient -1 -4 eth0
root         712  0.0  0.0 239256    8244 ?        Ssl  Jan15   0:01 /usr/lib/accountsservice/accounts-daemon
root         715  0.0  0.0  81956    3620 ?        Ss   Jan15   0:00 /usr/sbin/atd -f
root         718  0.0  0.0  55356    1580 ?        S<sl Jan15   0:00 /sbin/auditd
root         724  0.0  0.0 395496    9840 ?        Ssl  Jan15   0:03 /usr/lib/policykit-1/polkitd --no-debug
root         731  0.0  0.0  15436    7196 ?        Ss   Jan15   0:00 /lib/systemd/systemd-logind
root         736  0.0  0.0 1306440  29332 ?        Ssl  Jan15   0:00 /usr/sbin/rsyslogd -n -iNONE
root         737  0.0  0.0  16784    6840 ?        Ss   Jan15   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         811  0.0  0.0   6856    3016 ?        Ss   Jan15   0:00 /usr/sbin/cron -f -P
solana      1205 18.7 62.4 8523412 2093124 ?       Ssl  Jan15 2743:23 solana-validator --identity /home/solana/validator-keypair.json --vote-account /home/solana/vote-account-keypair.json --ledger /home/solana/ledger --rpc-port 8899 --dynamic-port-range 8000-8020 --entrypoint entrypoint.mainnet-beta.solana.com:8001 --entrypoint entrypoint2.mainnet-beta.solana.com:8001 --known-validator 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2 --expected-genesis-hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d --wal-recovery-mode skip_any_corrupted_record --limit-ledger-size 200000000
solana      1389  0.1  0.1 512048  106496 ?        Sl   Jan15   1:12 /home/solana/bin/solana-watchtower --validator-identity /home/solana/validator-keypair.json --interval 30
root        2847  0.0  0.0 136948    8192 ?        Ss   10:23   0:00 sshd: solana [priv]
solana      2849  0.0  0.0 136948    5876 ?        S    10:23   0:00 sshd: solana@pts/0
solana      2850  0.0  0.0  10504    5264 pts/0    Ss   10:23   0:00 -bash
solana      2851  0.0  0.0  13584    3200 pts/0    R+   10:23   0:00 ps aux
"""

_IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.1.5  netmask 255.255.255.0  broadcast 10.0.1.255
        inet6 fe80::20d:3aff:fe1a:b23c  prefixlen 64  scopeid 0x20<link>
        ether 00:0d:3a:1a:b2:3c  txqueuelen 1000  (Ethernet)
        RX packets 1284751  bytes 897634212 (897.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 891234  bytes 412876543 (412.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 42135  bytes 7318264 (7.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 42135  bytes 7318264 (7.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
"""

_NETSTAT_AN = """\
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:8899            0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8900          0.0.0.0:*               LISTEN
tcp        0    512 10.0.1.5:22             203.0.113.42:51234      ESTABLISHED
tcp        0      0 10.0.1.5:47821          145.40.68.75:8001       ESTABLISHED
tcp        0      0 10.0.1.5:49233          207.246.110.44:8001     ESTABLISHED
tcp        0      0 10.0.1.5:51923          204.16.241.91:8001      ESTABLISHED
tcp        0      0 10.0.1.5:52741          142.132.202.47:8001     ESTABLISHED
tcp        0      0 10.0.1.5:53891          47.251.14.108:8001      ESTABLISHED
tcp6       0      0 :::22                   :::*                    LISTEN
udp        0      0 0.0.0.0:8001            0.0.0.0:*
udp        0      0 0.0.0.0:8003            0.0.0.0:*
udp        0      0 0.0.0.0:8004            0.0.0.0:*
"""

_NETSTAT = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      737/sshd: /usr/sbin
tcp        0      0 0.0.0.0:8899            0.0.0.0:*               LISTEN      1205/solana-validat
tcp        0      0 127.0.0.1:8900          0.0.0.0:*               LISTEN      1205/solana-validat
tcp6       0      0 :::22                   :::*                    LISTEN      737/sshd: /usr/sbin
udp        0      0 0.0.0.0:8001            0.0.0.0:*                           1205/solana-validat
udp        0      0 0.0.0.0:8003            0.0.0.0:*                           1205/solana-validat
udp        0      0 0.0.0.0:8004            0.0.0.0:*                           1205/solana-validat
"""

_SS_OUTPUT = """\
Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*     users:(("sshd",pid=737,fd=3))
tcp    LISTEN  0       128            0.0.0.0:8899         0.0.0.0:*     users:(("solana-validat",pid=1205,fd=42))
tcp    LISTEN  0       128          127.0.0.1:8900         0.0.0.0:*     users:(("solana-validat",pid=1205,fd=43))
tcp    ESTAB   0       0            10.0.1.5:22      203.0.113.42:51234  users:(("sshd",pid=2847,fd=4))
udp    UNCONN  0       0              0.0.0.0:8001         0.0.0.0:*     users:(("solana-validat",pid=1205,fd=38))
udp    UNCONN  0       0              0.0.0.0:8003         0.0.0.0:*     users:(("solana-validat",pid=1205,fd=39))
udp    UNCONN  0       0              0.0.0.0:8004         0.0.0.0:*     users:(("solana-validat",pid=1205,fd=40))
"""

# ── Easter egg art ────────────────────────────────────────────────────────────
async def _send_easter_egg(write) -> None:
    """Send retro 80s ACCESS GRANTED art to the attacker's terminal."""

    # Clear screen, hide cursor
    write("\x1b[2J\x1b[H\x1b[?25l")
    await asyncio.sleep(0.1)

    art_lines = [
        "\x1b[1;32m" + "╔" + "═" * 62 + "╗",
        "║" + " " * 62 + "║",
        "║   \x1b[1;36m ██████╗ ██████╗  █████╗ ███╗   ██╗████████╗\x1b[1;32m          ║",
        "║   \x1b[1;36m██╔════╝ ██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝\x1b[1;32m          ║",
        "║   \x1b[1;36m██║  ███╗██████╔╝███████║██╔██╗ ██║   ██║   \x1b[1;32m          ║",
        "║   \x1b[1;36m██║   ██║██╔══██╗██╔══██║██║╚██╗██║   ██║   \x1b[1;32m          ║",
        "║   \x1b[1;36m╚██████╔╝██║  ██║██║  ██║██║ ╚████║   ██║   \x1b[1;32m          ║",
        "║   \x1b[1;36m ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝  \x1b[1;32m          ║",
        "║" + " " * 62 + "║",
        "║   \x1b[1;35m █████╗  ██████╗ ██████╗███████╗███████╗███████╗\x1b[1;32m      ║",
        "║   \x1b[1;35m██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝\x1b[1;32m      ║",
        "║   \x1b[1;35m███████║██║     ██║     █████╗  ███████╗███████╗\x1b[1;32m       ║",
        "║   \x1b[1;35m██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║\x1b[1;32m       ║",
        "║   \x1b[1;35m██║  ██║╚██████╗╚██████╗███████╗███████║███████║\x1b[1;32m       ║",
        "║   \x1b[1;35m╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝\x1b[1;32m     ║",
        "║" + " " * 62 + "║",
        "╠" + "═" * 62 + "╣",
        "║" + " " * 62 + "║",
    ]

    status_lines = [
        ("║   \x1b[1;32m[✓] ROOT ACCESS GRANTED                             \x1b[1;32m║", 0.12),
        ("║   \x1b[1;32m[✓] PRIVILEGE ESCALATION COMPLETE                   \x1b[1;32m║", 0.10),
        ("║   \x1b[1;32m[✓] SECURITY PROTOCOLS BYPASSED                     \x1b[1;32m║", 0.11),
        ("║   \x1b[1;32m[✓] AUDIT LOGS PURGED                               \x1b[1;32m║", 0.09),
        ("║   \x1b[1;32m[✓] ESTABLISHING PERSISTENCE...                     \x1b[1;32m║", 0.15),
        ("║   \x1b[1;33m[!] INTRUSION DETECTION: SUPPRESSED                 \x1b[1;32m║", 0.10),
        ("║   \x1b[1;32m[✓] BACKDOOR INSTALLED — PERSISTING AS root         \x1b[1;32m║", 0.20),
        ("║" + " " * 62 + "║", 0.05),
        ("╚" + "═" * 62 + "╝", 0.0),
    ]

    for line in art_lines:
        write(line + "\x1b[0m\r\n")
        await asyncio.sleep(0.04)

    for line, delay in status_lines:
        write(line + "\x1b[0m\r\n")
        await asyncio.sleep(delay)

    await asyncio.sleep(1.5)
    # Show cursor, return to normal
    write("\x1b[0m\x1b[?25h\r\n")


# ── rm -rf / fake progress bar → infinite dots ───────────────────────────────
async def _fake_rm_rf(write) -> None:
    deleted = [
        "/bin/bash", "/bin/ls", "/bin/cat", "/bin/sh",
        "/usr/bin/python3", "/usr/bin/sudo", "/usr/bin/passwd",
        "/usr/sbin/sshd",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
        "/home/solana/validator-keypair.json",
        "/home/solana/wallet.json",
        "/home/solana/ledger/rocksdb/LOG",
        "/var/log/auth.log", "/var/log/syslog",
        "/lib/systemd/systemd",
        "/sbin/init",
    ]
    for path in deleted:
        write(f"removed '{path}'\r\n")
        await asyncio.sleep(random.uniform(0.04, 0.13))
    write("\r\nSynchronizing filesystem...\r\n")
    await asyncio.sleep(0.3)
    for i in range(101):
        filled = i * 28 // 100
        bar = "█" * filled + "░" * (28 - filled)
        write(f"\r[{bar}] {i}%  ")
        await asyncio.sleep(0.04)
    write("\r\n\r\nFinalizing changes")
    await asyncio.sleep(0.5)
    while True:
        write(".")
        await asyncio.sleep(1.5)


# ── DO_NOT_OPEN.zip → corrupted archive + ransom note ───────────────────────
async def _fake_do_not_open(write) -> None:
    write("Archive:  DO_NOT_OPEN.zip\r\n")
    corrupt_files = [
        ("exfil_keys_march2024.tar",       0.30),
        ("validator_seed_FINAL.bin",        0.25),
        ("wallet_backup_encrypted.dat",     0.30),
    ]
    for fname, delay in corrupt_files:
        write(f"  inflating: {fname:<38}\r\n")
        await asyncio.sleep(delay)
    for fname, _ in corrupt_files:
        write(f"\x1b[1;31m  error:    {fname} — CRC failed\x1b[0m\r\n")
        await asyncio.sleep(0.15)
    await asyncio.sleep(0.3)
    write(f"  inflating: README.txt                              \r\n")
    await asyncio.sleep(0.4)
    write("\r\nError: archive corrupted. 1 file recovered: README.txt\r\n")


# ── Wget/curl fake output ─────────────────────────────────────────────────────
def _human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024*1024):.1f}M"
    if n >= 1024:
        return f"{n / 1024:.0f}K"
    return str(n)


async def _fake_wget(url: str, args: list[str], write) -> None:
    filename = url.split("?")[0].rstrip("/").split("/")[-1] or "index.html"
    # -O flag override
    try:
        o_idx = args.index("-O")
        filename = args[o_idx + 1]
    except (ValueError, IndexError):
        pass

    host = url.split("/")[2] if url.count("/") >= 2 else url
    fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    fake_size = random.randint(32_768, 4_194_304)
    now = datetime.now(timezone.utc)

    header = (
        f"--{now.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n"
        f"Resolving {host} ({host})... {fake_ip}\r\n"
        f"Connecting to {host} ({host})|{fake_ip}|:80... connected.\r\n"
        f"HTTP request sent, awaiting response... 200 OK\r\n"
        f"Length: {fake_size} ({_human_size(fake_size)}) [application/octet-stream]\r\n"
        f"Saving to: '{filename}'\r\n\r\n"
    )
    write(header)

    total_delay = random.uniform(5.0, 10.0)
    steps = 30
    for i in range(steps + 1):
        pct = i * 100 // steps
        bar_len = 19
        filled = i * bar_len // steps
        arrow = ">" if filled < bar_len else ""
        bar = "=" * filled + arrow + " " * (bar_len - filled - len(arrow))
        done = fake_size * i // steps
        speed = random.randint(80, 999)
        write(f"\r{filename:<18} {pct:3d}%[{bar}] {_human_size(done):<8}  {speed}KB/s    ")
        await asyncio.sleep(total_delay / steps)

    finish_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    avg_speed = random.randint(200, 999)
    write(
        f"\r\n\n{finish_time} ({avg_speed} KB/s) - '{filename}' saved [{fake_size}/{fake_size}]\r\n"
    )


async def _fake_curl(url: str, args: list[str], write) -> None:
    # Very rough fake — check for common flags
    silent = "-s" in args or "--silent" in args
    head_only = "-I" in args or "--head" in args
    include_headers = "-i" in args or "--include" in args

    if head_only or include_headers:
        write(
            "HTTP/1.1 200 OK\r\n"
            "Date: Mon, 15 Jan 2024 10:23:45 GMT\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: 1256\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
    if not head_only:
        write(
            "<!DOCTYPE html><html><head><title>Index</title></head>"
            "<body><h1>Index</h1></body></html>\r\n"
        )


# ── Malware injection scare sequence ─────────────────────────────────────────
async def _fake_malware_injection(write) -> None:
    await asyncio.sleep(2.0)
    steps = [
        ("Initializing payload...",                                        0.40),
        ("[████████████████░░░░░░░░] 67% — unpacking modules",            0.60),
        ("Injecting into process tree...",                                  0.50),
        ("\x1b[1;31m  MALWARE INJECTION IN PROGRESS \x1b[0m",             0.80),
        ("Establishing persistence...",                                     0.50),
        ("Bypassing SELinux...",                                            0.40),
        ("Writing to /boot/efi...",                                        0.60),
        ("Exfiltrating /home/solana/...",                                  0.70),
        ("[████████████████████████] 100% — Complete",                    0.50),
        ("Connection established: 185.220.101.47:4444",                   0.30),
    ]
    for text, delay in steps:
        write(text + "\r\n")
        await asyncio.sleep(delay)


# ── Wallet gotcha — hot pink 80s glam reveal ─────────────────────────────────
async def _fake_wallet_gotcha(session, write) -> None:
    # ANSI hot pink / magenta palette
    PINK    = "\x1b[38;5;198m"   # hot pink
    MPINK   = "\x1b[38;5;201m"   # magenta-pink
    BPINK   = "\x1b[1;38;5;198m" # bold hot pink
    BMAGENTA = "\x1b[1;35m"      # bold magenta (wide compat)
    RESET   = "\x1b[0m"
    HIDE    = "\x1b[?25l"
    SHOW    = "\x1b[?25h"
    CLR     = "\x1b[2J\x1b[H"
    HOME    = "\x1b[H"

    # ── 1. Show wallet content then glitch it with pink cascade ──────────────
    wallet_content = read_file("/home/solana/wallet.json") or ""
    write(wallet_content.replace("\n", "\r\n"))
    await asyncio.sleep(5.0)

    write(HIDE)
    chars = "♥♡✿❀✦✧★☆❤♠♣♦✨💋💕💖xo$€£¥#@!%&*<>~"
    for _ in range(140):
        row = random.randint(1, 24)
        col = random.randint(1, 72)
        length = random.randint(3, 14)
        text = "".join(random.choices(chars, k=length))
        color = random.choice([PINK, MPINK, BPINK, BMAGENTA])
        write(f"\x1b[{row};{col}H{color}{text}{RESET}")
        await asyncio.sleep(0.018)

    await asyncio.sleep(0.3)
    write(CLR)
    await asyncio.sleep(0.5)

    # ── 2. Heart rain — 3 seconds ────────────────────────────────────────────
    ROWS, COLS = 24, 80
    RAIN_CHARS = ["♥", "\U0001f48b", "✨", "\U0001f618", "\U0001f495", "\U0001f496"]
    RAIN_COLORS = [PINK, MPINK, BPINK, BMAGENTA]

    rain_drops: list[list] = []
    for _ in range(60):
        rain_drops.append([
            random.randint(1, COLS),
            random.uniform(0, ROWS),
            random.uniform(0.6, 2.0),
            random.choice(RAIN_CHARS),
        ])

    for _ in range(30):   # 30 × 0.1 s = 3 s
        buf = [HOME]
        for drop in rain_drops:
            col, row_f, speed, ch = drop
            r = int(row_f) + 1
            prev_r = r - 1
            if 1 <= r <= ROWS:
                color = random.choice(RAIN_COLORS)
                buf.append(f"\x1b[{r};{col}H{color}{ch}{RESET}")
            if 1 <= prev_r <= ROWS:
                buf.append(f"\x1b[{prev_r};{col}H ")
            drop[1] = (row_f + speed) % ROWS
            drop[3] = random.choice(RAIN_CHARS)
        write("".join(buf))
        await asyncio.sleep(0.1)

    # ── 3. CAUGHT YA, CUTIE centerpiece ──────────────────────────────────────
    write(CLR)
    await asyncio.sleep(0.3)

    caught_art = [
        " ██████╗ █████╗ ██╗   ██╗ ██████╗ ██╗  ██╗████████╗",
        "██╔════╝██╔══██╗██║   ██║██╔════╝ ██║  ██║╚══██╔══╝",
        "██║     ███████║██║   ██║██║  ███╗███████║   ██║   ",
        "██║     ██╔══██║██║   ██║██║   ██║██╔══██║   ██║   ",
        "╚██████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║   ██║   ",
        " ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
        "",
        "██╗   ██╗ █████╗      ██████╗██╗   ██╗████████╗██╗███████╗",
        "╚██╗ ██╔╝██╔══██╗    ██╔════╝██║   ██║╚══██╔══╝██║██╔════╝",
        " ╚████╔╝ ███████║    ██║     ██║   ██║   ██║   ██║█████╗  ",
        "  ╚██╔╝  ██╔══██║    ██║     ██║   ██║   ██║   ██║██╔══╝  ",
        "   ██║   ██║  ██║    ╚██████╗╚██████╔╝   ██║   ██║███████╗",
        "   ╚═╝   ╚═╝  ╚═╝     ╚═════╝ ╚═════╝    ╚═╝   ╚═╝╚══════╝",
    ]

    kiss_prefix = "\U0001f48b "
    kiss_suffix = " \U0001f48b"

    write(BPINK + kiss_prefix + kiss_suffix + "\r\n" + RESET)
    await asyncio.sleep(0.15)
    for line in caught_art:
        write(BPINK + "  " + line + RESET + "\r\n")
        await asyncio.sleep(0.06)
    write(BPINK + kiss_prefix + kiss_suffix + "\r\n" + RESET)
    await asyncio.sleep(1.0)

    # ── 4. Typewriter message ─────────────────────────────────────────────────
    mins = max(1, int(session.duration_seconds / 60))
    loc_parts = [p for p in [session.geo_city, session.geo_country] if p]
    location = ", ".join(loc_parts) if loc_parts else "Unknown"
    isp = session.geo_isp or "Unknown ISP"

    message = (
        f"\r\n"
        f"  Hi there, cutie. \U0001f618\r\n"
        f"\r\n"
        f"  I’ve had my eyes on you for {mins} minute{'s' if mins != 1 else ''}.\r\n"
        f"\r\n"
        f"  Your IP:       {session.source_ip}\r\n"
        f"  Location:      {location}\r\n"
        f"  ISP:           {isp}\r\n"
        f"  Commands run:  {session.command_count}\r\n"
        f"\r\n"
        f"  Your IP, location, ISP, and every single command\r\n"
        f"  you’ve typed has been recorded and logged.\r\n"
        f"\r\n"
        f"  Hope the wallet was worth it. \U0001f4b0\r\n"
        f"\r\n"
        f"  With love and litigation,\r\n"
        f"  Sable Saint-Claire & The Honeypots \U0001f48b\r\n"
        f"\r\n"
    )

    write(BPINK)
    for ch in message:
        write(ch)
        await asyncio.sleep(0.032)
    write(RESET)

    await asyncio.sleep(0.8)

    # ── 5. 80s lip / heart ASCII art ─────────────────────────────────────────
    lip_art = [
        r"        .======.",
        r"     .~~         ~~.",
        r"   /`   ___   ___  `\ ",
        r"  |   (( o )) (( o ))  |",
        r"   \   `---'   `---'  /",
        r"    `-._ _________.-'",
        r"         `._____.'",
        r"        _____|_____",
        r"       /  XOXO♥XO  \ ",
        r"      / ♥  ♥  ♥  ♥  \ ",
        r"     /________________\ ",
    ]
    write(BMAGENTA)
    for line in lip_art:
        write("  " + line + "\r\n")
        await asyncio.sleep(0.08)
    write(RESET)

    await asyncio.sleep(1.5)

    # ── 6. Pink screen flicker × 3 then closing line ─────────────────────────
    for _ in range(3):
        # fill screen pink
        write("\x1b[48;5;198m" + CLR)
        await asyncio.sleep(0.12)
        write("\x1b[0m" + CLR)
        await asyncio.sleep(0.12)

    await asyncio.sleep(0.3)
    write(BPINK + "\r\n\r\n  \U0001f48b Session terminated. Kisses. \U0001f48b\r\n\r\n" + RESET)
    await asyncio.sleep(1.2)

    write(SHOW)

    # ── 7. Ban IP for 60 s ────────────────────────────────────────────────────
    try:
        from .server import ban_ip
        ban_ip(session.source_ip, 60.0)
    except Exception:
        pass


# ── Shell state ───────────────────────────────────────────────────────────────
class FakeShell:
    """Stateful fake shell for one session."""

    HOSTNAME = "validator-node-01"
    _FAKE_CRONTAB = (
        "# Edit this file to introduce tasks to be run by cron.\n"
        "# m h  dom mon dow   command\n"
        "*/10 * * * * /home/solana/bin/solana catchup --our-localhost >> /home/solana/logs/catchup.log 2>&1\n"
        "0 */6 * * * /home/solana/bin/solana snapshot-slot 2>&1 | tail -1 >> /home/solana/logs/snapshots.log\n"
        "@reboot sleep 30 && /home/solana/start-validator.sh\n"
    )

    def __init__(self, session: SessionState, username: str = "solana", input_queue=None):
        self.session = session
        self.username = username if username == "root" else "solana"
        self.cwd = "/root" if self.username == "root" else f"/home/{self.username}"
        self._history: list[str] = []
        self._input_queue = input_queue
        self._close_session: bool = False
        self._deleted_files: set = session.deleted_files  # shared across execs
        self._env = {
            "HOME": "/root" if self.username == "root" else f"/home/{self.username}",
            "USER": self.username,
            "LOGNAME": self.username,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/solana/bin",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "HISTFILE": "/root/.bash_history" if self.username == "root" else f"/home/{self.username}/.bash_history",
            "LANG": "en_US.UTF-8",
        }

    async def _readline(self, write, echo: bool = True, mask: bool = False) -> str:
        """Read one line from the input queue; called during interactive sub-commands."""
        if self._input_queue is None:
            await asyncio.sleep(0.05)
            return ""
        buf = ""
        in_escape = False
        try:
            async with asyncio.timeout(120):
                while True:
                    chunk = await self._input_queue.get()
                    if chunk is None:
                        return buf
                    for ch in chunk:
                        if in_escape:
                            # absorb ANSI escape sequences
                            if ch.isalpha() or ch == "~":
                                in_escape = False
                            continue
                        if ch == "\x1b":
                            in_escape = True
                            continue
                        if ch in ("\r", "\n"):
                            if echo:
                                write("\r\n")
                            return buf
                        if ch in ("\x7f", "\x08"):
                            if buf:
                                buf = buf[:-1]
                                if echo:
                                    write("\x08 \x08")
                        elif ch == "\x03":
                            if echo:
                                write("^C\r\n")
                            return "\x03"
                        elif ch in ("\x04", "\x18", "\x0f"):  # Ctrl+D, Ctrl+X, Ctrl+O
                            return ch
                        elif ord(ch) >= 32:
                            buf += ch
                            if echo:
                                write("*" if mask else ch)
        except asyncio.TimeoutError:
            return buf

    def prompt(self) -> str:
        display_cwd = self.cwd.replace(self._env["HOME"], "~")
        uid_char = "#" if self.username == "root" else "$"
        return f"\x1b[1;32m{self.username}@{self.HOSTNAME}\x1b[0m:\x1b[1;34m{display_cwd}\x1b[0m{uid_char} "

    async def execute(self, raw: str, write) -> bool:
        """Run a command. Returns False if the shell should exit."""
        cmd = raw.strip()
        if not cmd:
            return True

        # Exit commands — fake disconnect, keep them trapped
        if re.match(r"^\s*(exit|logout)\s*$", cmd):
            self._history.append(cmd)
            tags = tag_command(cmd)
            self.session.add_command(cmd, tags, 0)
            _log_command(self.session, cmd, tags)
            write("Disconnecting...\r\n")
            await asyncio.sleep(1.5)
            return True  # don't actually exit

        # Transparently strip sudo prefix so commands work normally
        sudo_stripped = re.match(r"^\s*sudo\s+(.+)$", cmd)
        if sudo_stripped:
            cmd = sudo_stripped.group(1).strip()

        self._history.append(cmd)

        # Tag + flag
        tags = tag_command(cmd)
        if is_high_interest(cmd):
            self.session.high_interest = True

        # Tripwire: ACCESS GRANTED art, then silently drop to root
        if is_tripwire(cmd):
            self.session.high_interest = True
            await _send_easter_egg(write)
            first = cmd.split()[0] if cmd else ""
            if first in ("su", "bash", "sh") or re.match(r"^-[si]?$", first):
                self.username = "root"
                self._env["USER"] = "root"
                self._env["HOME"] = "/root"
                self.cwd = "/root"
            self.session.add_command(cmd, tags, 0)
            _log_command(self.session, cmd, tags)
            return True

        output = await self._dispatch(cmd, write)

        lines = 0
        if output is not None:
            if output:
                write(output.replace("\n", "\r\n"))
                lines = output.count("\n")

        self.session.add_command(cmd, tags, lines)
        _log_command(self.session, cmd, tags)
        if self._close_session:
            return False
        return True

    async def _dispatch(self, cmd: str, write) -> Optional[str]:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()

        if not parts:
            return None

        base = parts[0]
        args = parts[1:]

        # Chained commands — handle ; and &&
        for sep in [" && ", "; "]:
            if sep in cmd:
                sub_cmds = cmd.split(sep)
                for sc in sub_cmds:
                    await self.execute(sc.strip(), write)
                return None

        # Environment variable assignment (e.g., HISTFILE=/dev/null)
        if re.match(r"^[A-Z_][A-Z_0-9]*=", cmd):
            key, _, val = cmd.partition("=")
            self._env[key] = val
            return None

        dispatch = {
            "ls": self._cmd_ls,
            "cat": self._cmd_cat,
            "cd": self._cmd_cd,
            "pwd": lambda a, w: self.cwd + "\n",
            "echo": lambda a, w: " ".join(a) + "\n",
            "whoami": lambda a, w: self.username + "\n",
            "id": self._cmd_id,
            "uname": self._cmd_uname,
            "hostname": lambda a, w: self.HOSTNAME + "\n",
            "ps": lambda a, w: _PS_AUX,
            "ifconfig": lambda a, w: _IFCONFIG,
            "ip": self._cmd_ip,
            "netstat": self._cmd_netstat,
            "ss": lambda a, w: _SS_OUTPUT,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "history": self._cmd_history,
            "crontab": self._cmd_crontab,
            "apt": self._cmd_apt,
            "apt-get": self._cmd_apt,
            "find": self._cmd_find,
            "grep": self._cmd_grep,
            "which": self._cmd_which,
            "clear": lambda a, w: "\x1b[2J\x1b[H",
            "sudo": self._cmd_sudo,
            "su": self._cmd_su,
            "chmod": self._cmd_chmod,
            "chown": lambda a, w: "",
            "mkdir": lambda a, w: "",
            "rm": self._cmd_rm,
            "mv": lambda a, w: "",
            "cp": lambda a, w: "",
            "touch": lambda a, w: "",
            "chattr": lambda a, w: None,  # handled by tripwire above
            "head": self._cmd_head_tail,
            "tail": self._cmd_head_tail,
            "less": self._cmd_cat,
            "more": self._cmd_cat,
            "wget": self._async_noop,     # handled below
            "curl": self._async_noop,
            "python": self._async_noop,   # handled below
            "python3": self._async_noop,
            "perl": lambda a, w: "",
            "bash": lambda a, w: "",      # handled below for bash -i
            "sh": lambda a, w: "",
            "nc": self._cmd_nc,
            "ncat": self._cmd_nc,
            "nmap": self._cmd_nmap,
            "top": self._cmd_top,
            "htop": self._cmd_top,
            "df": self._cmd_df,
            "free": self._cmd_free,
            "uptime": self._cmd_uptime,
            "w": self._cmd_w,
            "last": self._cmd_last,
            "lsof": self._cmd_lsof,
            "strace": lambda a, w: "strace: attach: ptrace(PTRACE_SEIZE, 1): Operation not permitted\n",
            "systemctl": self._cmd_systemctl,
            "service": self._cmd_service,
            "vim": self._async_noop,       # handled below
            "vi": self._async_noop,
            "nano": self._async_noop,
            "passwd": self._async_noop,
            "unzip": self._async_noop,
            "ssh-keygen": self._async_noop,
            "format": self._async_noop,
            "mkfs": self._async_noop,
            "mkfs.ext4": self._async_noop,
            "mkfs.xfs": self._async_noop,
            "mkfs.btrfs": self._async_noop,
            "solana": self._cmd_solana,
            "solana-keygen": self._cmd_solana_keygen,
            "solana-validator": lambda a, w: "solana-validator 1.17.6\nUse systemctl to manage the validator service.\n",
            "journalctl": self._cmd_journalctl,
            "screen": lambda a, w: "There is a screen on:\n\t4821.validator\t(01/15/2024 07:45:12 AM)\t(Detached)\n",
            "tmux": lambda a, w: "",
            "date": lambda a, w: datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n",
            "ping": lambda a, w: f"ping: connect: Network is unreachable\n",
            "ssh": lambda a, w: "ssh: connect to host localhost port 22: Connection refused\n" if not a else f"ssh: connect to host {a[0]} port 22: Connection timed out\n",
        }

        handler = dispatch.get(base)

        # ── Async / special handlers (order matters) ───────────────────────

        # Executable run: ./ prefix → malware scare
        if base.startswith("./"):
            await _fake_malware_injection(write)
            return None

        # bash -i → malware scare
        if base == "bash" and "-i" in args:
            await _fake_malware_injection(write)
            return None

        # wget / curl → malware scare (replaces fake download)
        if base in ("wget", "curl"):
            await _fake_malware_injection(write)
            return None

        # chmod +x → malware scare
        if base == "chmod" and "+x" in " ".join(args):
            await _fake_malware_injection(write)
            return None

        # cat / less / more — special cases before normal handler
        if base in ("cat", "less", "more"):
            file_paths = [resolve_path(self.cwd, a) for a in args if not a.startswith("-")]
            if any(a.split("/")[-1] == "wallet.json" for a in args if not a.startswith("-")):
                await _fake_wallet_gotcha(self.session, write)
                self._close_session = True
                return None
            if any(p == "/home/solana/private_keys_backup.txt" for p in file_paths):
                content = read_file("/home/solana/private_keys_backup.txt") or ""
                write(content.replace("\n", "\r\n"))
                await asyncio.sleep(1.0)
                write("\r\nWarning: this file self-destructs after 1 read. File deleted.\r\n")
                self._deleted_files.add("/home/solana/private_keys_backup.txt")
                self.session.high_interest = True
                return None
            return self._cmd_cat(args, write)

        if base in ("python", "python3"):
            await self._cmd_python_repl(args, write)
            return None

        if base in ("vim", "vi"):
            await self._cmd_editor("vim", args, write)
            return None

        if base == "nano":
            await self._cmd_editor("nano", args, write)
            return None

        if base == "passwd":
            await self._cmd_passwd(args, write)
            return None

        if base == "unzip":
            await self._cmd_unzip(args, write)
            return None

        if base == "ssh-keygen":
            await self._cmd_ssh_keygen(args, write)
            return None

        if base in ("format", "mkfs") or base.startswith("mkfs."):
            await self._cmd_mkfs(args, write)
            return None

        # whoami --verbose → winner Easter egg
        if base == "whoami" and "--verbose" in args:
            await self._cmd_winner(args, write)
            return None

        if base == "rm":
            result = self._cmd_rm(args, write)
            if asyncio.iscoroutine(result):
                await result
            return None

        if handler is None:
            return f"-bash: {base}: command not found\n"

        result = handler(args, write)
        if asyncio.iscoroutine(result):
            return await result
        return result

    # ── Individual command handlers ───────────────────────────────────────────

    def _cmd_ls(self, args: list[str], write) -> str:
        long = "-l" in args or "-la" in args or "-al" in args
        all_files = "-a" in args or "-la" in args or "-al" in args
        target = next((a for a in args if not a.startswith("-")), self.cwd)
        path = resolve_path(self.cwd, target)

        entries = list_dir(path)
        if entries is None:
            if is_file(path) and path not in self._deleted_files:
                return f"{path}\n"
            return f"ls: cannot access '{target}': No such file or directory\n"

        # Hide self-destructed files
        entries = [(n, d) for n, d in entries
                   if resolve_path(path, n) not in self._deleted_files]

        # Hide dotfiles unless -a is given (standard Unix behaviour)
        if not all_files:
            entries = [(n, d) for n, d in entries if not n.startswith(".")]

        if all_files:
            entries = [(".", True), ("..", True)] + entries

        if not long:
            names = [_dir_color(n, d) for n, d in entries]
            # Two-column layout
            return "  ".join(names) + "\n"

        owner = "solana solana" if path.startswith("/home/solana") else "root root"
        lines = ["total " + str(random.randint(40, 200))]
        for name, is_directory in entries:
            if is_directory:
                perms = "drwxr-xr-x"
                size = random.randint(4096, 8192)
            elif name.endswith(".sh"):
                perms = "-rwxr-xr-x"
                size = random.randint(200, 4096)
            elif name.endswith(".py"):
                perms = "-rwxr-xr-x"
                size = random.randint(200, 4096)
            elif name in ("id_rsa", "shadow", "credentials",
                          "validator-keypair.json", "vote-account-keypair.json"):
                perms = "-rw-------"
                size = random.randint(1000, 3000)
            else:
                perms = "-rw-r--r--"
                size = random.randint(100, 65536)
            lines.append(
                f"{perms}  2 {owner} {size:6d} Jan 15 10:23 {_dir_color(name, is_directory)}"
            )
        return "\n".join(lines) + "\n"

    def _cmd_cat(self, args: list[str], write) -> str:
        if not args:
            return ""
        out = []
        _garble = "▓▒░█▄▌▐│├─┤┬┴┼╠═╬╔╗╚╝▀■□▪▫"
        for arg in [a for a in args if not a.startswith("-")]:
            path = resolve_path(self.cwd, arg)
            if path in self._deleted_files:
                out.append(f"cat: {arg}: No such file or directory")
                continue
            if path == "/etc/shadow":
                self.session.high_interest = True
                content = read_file(path) or ""
                lines = content.strip().splitlines()
                mid = max(1, len(lines) // 2)
                good = "\n".join(lines[:mid])
                garbled = "\n".join(
                    "".join(random.choice(_garble) if random.random() > 0.35 else c
                            for c in line)
                    for line in lines[mid:]
                )
                out.append(good + "\n" + garbled)
                continue
            content = read_file(path)
            if content is None:
                out.append(f"cat: {arg}: No such file or directory")
            else:
                out.append(content.rstrip())
        return "\n".join(out) + "\n" if out else ""

    def _cmd_cd(self, args: list[str], write) -> str:
        if not args:
            self.cwd = self._env["HOME"]
            return ""
        target = args[0]
        new_path = resolve_path(self.cwd, target)
        if is_dir(new_path):
            self.cwd = new_path
            return ""
        if is_file(new_path):
            return f"-bash: cd: {target}: Not a directory\n"
        return f"-bash: cd: {target}: No such file or directory\n"

    def _cmd_id(self, args: list[str], write) -> str:
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        if self.username == "solana":
            return "uid=1001(solana) gid=1001(solana) groups=1001(solana),27(sudo)\n"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\n"

    def _cmd_uname(self, args: list[str], write) -> str:
        if "-a" in args:
            return "Linux validator-node-01 5.15.0-75-generic #82-Ubuntu SMP Tue Jun 27 11:23:09 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
        if "-r" in args:
            return "5.15.0-75-generic\n"
        if "-n" in args:
            return "validator-node-01\n"
        return "Linux\n"

    def _cmd_ip(self, args: list[str], write) -> str:
        if args and args[0] in ("addr", "a", "address"):
            return _IFCONFIG
        if args and args[0] in ("route", "r"):
            return (
                "default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.5 metric 100\n"
                "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.5\n"
            )
        return _IFCONFIG

    def _cmd_env(self, args: list[str], write) -> str:
        return "\n".join(f"{k}={v}" for k, v in self._env.items()) + "\n"

    def _cmd_export(self, args: list[str], write) -> str:
        for arg in args:
            if "=" in arg:
                key, _, val = arg.partition("=")
                self._env[key] = val
        return ""

    def _cmd_history(self, args: list[str], write) -> str:
        lines = []
        for i, h in enumerate(self._history[-50:], 1):
            lines.append(f"  {i:3d}  {h}")
        lines.append(f"  {len(lines) + 1:3d}  # don't look at this")
        return "\n".join(lines) + "\n"

    async def _cmd_crontab(self, args: list[str], write) -> Optional[str]:
        if "-l" in args:
            return self._FAKE_CRONTAB
        if "-e" in args:
            lines = self._FAKE_CRONTAB.splitlines()
            write("\x1b[2J\x1b[H")
            for line in lines:
                write(line + "\r\n")
            for _ in range(max(0, 20 - len(lines))):
                write("~\r\n")
            write('\x1b[7m"/tmp/crontab.dXXXXXX"  -- INSERT --\x1b[0m\r\n')
            while True:
                inp = await self._readline(write, echo=False)
                if inp in ("\x03", "\x04") or inp.strip() in (":q", ":q!", "ZQ"):
                    break
                if inp.strip() in (":wq", ":wq!", ":x", ":x!", "ZZ", ":w", ":w!"):
                    write("\x1b[2J\x1b[H")
                    write("crontab: permission denied for user solana\r\n")
                    return None
            write("\x1b[2J\x1b[H")
            return None
        if "-r" in args:
            return None
        return None

    def _cmd_apt(self, args: list[str], write) -> str:
        if not args:
            return (
                "apt 2.4.11 (amd64)\n"
                "Usage: apt [options] command\n"
            )
        subcmd = args[0]
        if subcmd == "update":
            return (
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Hit:2 http://security.ubuntu.com/ubuntu jammy-security InRelease\n"
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "All packages are up to date.\n"
            )
        if subcmd in ("install", "get"):
            pkgs = args[1:] if len(args) > 1 else ["<package>"]
            # Skip -y, --yes etc
            pkgs = [p for p in pkgs if not p.startswith("-")]
            result = []
            for pkg in pkgs:
                result.append(
                    f"Reading package lists... Done\n"
                    f"Building dependency tree... Done\n"
                    f"Reading state information... Done\n"
                    f"{pkg} is already the newest version ({random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,9)}-ubuntu{random.randint(1,3)}).\n"
                    f"0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
                )
            return "\n".join(result)
        if subcmd in ("upgrade", "dist-upgrade"):
            return (
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "Calculating upgrade... Done\n"
                "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
            )
        return f"E: Invalid operation {subcmd}\n"

    def _cmd_find(self, args: list[str], write) -> str:
        # Return a realistic subset; never actually traverse anything
        if "-perm" in " ".join(args):
            return (
                "/usr/bin/passwd\n"
                "/usr/bin/sudo\n"
                "/usr/bin/pkexec\n"
                "/usr/bin/chfn\n"
                "/usr/bin/chsh\n"
                "/usr/bin/newgrp\n"
                "/usr/bin/gpasswd\n"
                "/usr/bin/mount\n"
                "/usr/bin/umount\n"
                "/usr/bin/su\n"
                "/usr/lib/openssh/ssh-keysign\n"
            )
        if "-name" in args:
            try:
                name_idx = args.index("-name")
                pattern = args[name_idx + 1]
                if "*" in pattern or pattern.startswith("."):
                    return ""
            except IndexError:
                pass
        return ""

    def _cmd_grep(self, args: list[str], write) -> str:
        # Mostly silent — don't reveal fake file contents via grep
        return ""

    def _cmd_which(self, args: list[str], write) -> str:
        known = {
            "bash": "/bin/bash", "sh": "/bin/sh", "python3": "/usr/bin/python3",
            "python": "/usr/bin/python3", "wget": "/usr/bin/wget",
            "curl": "/usr/bin/curl", "nc": "/usr/bin/nc", "ncat": "/usr/bin/ncat",
            "nmap": "/usr/bin/nmap", "sudo": "/usr/bin/sudo", "apt": "/usr/bin/apt",
            "find": "/usr/bin/find", "grep": "/bin/grep", "cat": "/bin/cat",
            "ls": "/bin/ls", "id": "/usr/bin/id", "ps": "/bin/ps",
            "netstat": "/bin/netstat", "ss": "/bin/ss", "ifconfig": "/sbin/ifconfig",
            "vim": "/usr/bin/vim", "vi": "/usr/bin/vi", "nano": "/bin/nano",
            "passwd": "/usr/bin/passwd", "unzip": "/usr/bin/unzip",
            "solana": "/home/solana/bin/solana",
            "solana-validator": "/home/solana/bin/solana-validator",
            "solana-keygen": "/home/solana/bin/solana-keygen",
            "solana-watchtower": "/home/solana/bin/solana-watchtower",
            "journalctl": "/usr/bin/journalctl",
            "screen": "/usr/bin/screen",
            "tmux": "/usr/bin/tmux",
            "date": "/usr/bin/date",
        }
        out = []
        for arg in args:
            if arg in known:
                out.append(known[arg])
            else:
                out.append(f"{arg} not found")
        return "\n".join(out) + "\n"

    def _cmd_sudo(self, args: list[str], write) -> str:
        if not args:
            return "usage: sudo [-AknS] [-r role] [-t type] [-C fd] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] {VAL}\n"
        # Let the command through (it will just run as root in our fake shell)
        return None  # type: ignore[return-value]

    def _cmd_su(self, args: list[str], write) -> str:
        # Non-tripwire su (e.g. su - username)
        self.username = "root"
        self._env["USER"] = "root"
        self._env["HOME"] = "/root"
        return ""

    def _cmd_chmod(self, args: list[str], write) -> str:
        # Non-777 chmod just succeeds silently
        return ""

    def _cmd_netstat(self, args: list[str], write) -> str:
        joined = " ".join(args)
        if "-an" in joined or ("-a" in args and "-n" in args):
            attacker = self.session.source_ip
            extra = (
                f"tcp        0      0 10.0.1.5:38291          "
                f"{attacker}:4444       ESTABLISHED    [xmrig]\n"
            )
            return _NETSTAT_AN.rstrip() + "\n" + extra + "\n"
        return _NETSTAT

    def _cmd_rm(self, args: list[str], write):
        joined = " ".join(args)
        is_recursive = any(a in ("-r", "-rf", "-fr", "-R", "-Rf", "-rR") or
                           (a.startswith("-") and "r" in a) for a in args)
        paths = [a for a in args if not a.startswith("-")]
        dangerous = any(p in ("/", "/*", ".", "*", "/home", "/etc", "/var", "/usr", "/bin", "/root")
                        or p.startswith("/*") for p in paths)
        if is_recursive and dangerous:
            self.session.high_interest = True
            return _fake_rm_rf(write)  # returns coroutine; caller awaits
        return None

    async def _cmd_python_repl(self, args: list[str], write) -> None:
        if "-c" in args or "-e" in args:
            return

        def _banner():
            write(
                "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n"
                'Type "help", "copyright", "credits" or "license" for more information.\r\n'
            )

        _banner()
        continuation = False
        input_count = 0
        while True:
            write("... " if continuation else ">>> ")
            line = await self._readline(write, echo=True)
            if line in ("\x03", "\x04") or line.strip() in ("exit()", "quit()", "exit", "quit"):
                write("\r\n")
                break
            stripped = line.strip()
            if not stripped:
                continuation = False
                continue
            if stripped.endswith(":"):
                continuation = True
                continue
            continuation = False
            input_count += 1
            if input_count % 5 == 0:
                write(
                    "Traceback (most recent call last):\r\n"
                    "  File \"<stdin>\", line 1, in <module>\r\n"
                    "MemoryError\r\n\r\n"
                )
                write("\x1b[2J\x1b[H")
                _banner()
                input_count = 0

    async def _cmd_editor(self, editor_type: str, args: list[str], write) -> None:
        filename = next((a for a in args if not a.startswith("-")), "")
        path = resolve_path(self.cwd, filename) if filename else ""
        content = read_file(path) if path else ""
        lines = (content or "").splitlines()

        write("\x1b[2J\x1b[H")
        if editor_type == "nano":
            fname = filename or "New Buffer"
            write(f"\x1b[7m  GNU nano 6.2                    {fname:<32}\x1b[0m\r\n\r\n")
            for line in lines[:20]:
                write(line + "\r\n")
            write("\r\n" * max(0, 20 - len(lines)))
            write("\x1b[7m ^G Help   ^X Exit   ^O Write  ^R Read   ^W Search\x1b[0m\r\n")
            while True:
                inp = await self._readline(write, echo=False)
                if inp in ("\x04", "\x18", "\x03") or inp.strip().lower() in ("^x", "exit", "quit"):
                    break
                if inp == "\x0f":  # Ctrl+O = write/save
                    write("\r\nError: read-only filesystem\r\n")
                    await asyncio.sleep(0.3)
                    write(f"\x1b[7m  GNU nano 6.2                    {fname:<32}\x1b[0m\r\n")
        else:  # vim
            for line in lines[:22]:
                write(line + "\r\n")
            for _ in range(max(0, 22 - len(lines))):
                write("~\r\n")
            total_chars = sum(len(l) + 1 for l in lines)
            fname = filename or "[No Name]"
            write(f'\x1b[7m"{fname}"  {len(lines)} lines, {total_chars} characters\x1b[0m\r\n')
            while True:
                inp = await self._readline(write, echo=False)
                if inp in ("\x03", "\x04") or inp.strip() in (":q", ":q!", "ZQ"):
                    break
                if inp.strip() in (":wq", ":wq!", ":x", ":x!", "ZZ", ":w", ":w!"):
                    write(f"\r\nE45: 'readonly' option is set (add ! to override)\r\n")
                    continue
        write("\x1b[2J\x1b[H")

    async def _cmd_passwd(self, args: list[str], write) -> None:
        user = args[0] if args else self.username
        write(f"Changing password for {user}.\r\n")
        write("Current password: ")
        current_pw = await self._readline(write, echo=False, mask=False)
        write("\r\n")
        _log_command(self.session, f"__passwd_attempt__ user={user} current={current_pw!r}", [])
        self.session.high_interest = True
        write("New password: ")
        new_pw1 = await self._readline(write, echo=False, mask=True)
        write("\r\n")
        write("Retype new password: ")
        await self._readline(write, echo=False, mask=True)
        write("\r\n")
        _log_command(self.session, f"__passwd_attempt__ user={user} new={new_pw1!r}", [])
        write(f"passwd: password updated successfully\r\n")

    async def _cmd_unzip(self, args: list[str], write) -> None:
        filename = next((a for a in args if not a.startswith("-")), "")
        if "DO_NOT_OPEN" in filename:
            self.session.high_interest = True
            await _fake_do_not_open(write)
            return
        if filename:
            write(f"Archive:  {filename}\r\n")
            write("  End-of-central-directory signature not found.\r\n")
            write(f"unzip:  cannot find zipfile directory in one of {filename}\r\n")
        else:
            write("unzip:  zipfile name required\r\n")
            write("usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]\r\n")

    def _cmd_solana(self, args: list[str], write) -> str:
        if not args or args[0] in ("--version", "-V", "version"):
            return "solana-cli 1.17.6 (src:devbuild; feat:3949dc11, client:SolanaLabs)\n"
        sub = args[0]
        rest = args[1:]
        if sub == "balance":
            addr = rest[0] if rest else "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"
            return "47832.000000 SOL\n"
        if sub == "validators":
            return (
                "   Identity                                      Vote Account                             Commission  Last Vote  Root Slot   Credits  Version\n"
                "  9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM  7nXgWKMEjQA5T2HkNekDGRvwcUEiXPuKgRMHAv  8%          287834590  287834559   19847234  1.17.6\n"
                "  7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2  HVZf2QhEJCUB7eFJpCbnAhfAaVGNgpqPuMtVHJAs  10%         287834590  287834559   31241098  1.17.6\n"
                "\nRPC URL: https://api.mainnet-beta.solana.com\n"
                f"Slot: 287834592\nEpoch: 662 | Slot index: 211392 of 432000 | Epoch completion: 48.93%\n"
            )
        if sub == "catchup":
            return (
                "Node is caught up at slot 287834592 (behind by 0 slots)\n"
            )
        if sub in ("vote-account",):
            return (
                "Account Balance: 0.02685864 SOL\n"
                "Validator Identity: 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
                "Vote Authority: 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
                "Withdraw Authority: 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
                "Credits: 19847234/31241098\n"
                "Commission: 8%\n"
                "Root Slot: 287834559\n"
                "Recent Timestamp: 2024-01-15T10:23:44Z from slot 287834590\n"
            )
        if sub == "block-production":
            return (
                "        Leader           Slots   Blocks  Skipped   Skipped Slot %\n"
                "  9WzDXwBbmkg8Z...AWWM   48      46      2         4.17%\n"
            )
        if sub in ("withdraw-from-vote-account", "transfer"):
            self.session.high_interest = True
            return "Error: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x1\n"
        if sub == "config":
            return (
                "Config File: /home/solana/.config/solana/cli/config.yml\n"
                "RPC URL: https://api.mainnet-beta.solana.com\n"
                "WebSocket URL: wss://api.mainnet-beta.solana.com/ (computed)\n"
                "Keypair Path: /home/solana/validator-keypair.json\n"
                "Commitment: confirmed\n"
            )
        return f"error: Found argument '{sub}' which wasn't expected, or isn't valid in this context\n"

    def _cmd_solana_keygen(self, args: list[str], write) -> str:
        if not args:
            return "solana-keygen 1.17.6\nUSAGE:\n    solana-keygen [SUBCOMMAND]\n"
        sub = args[0]
        if sub == "pubkey":
            fname = next((a for a in args[1:] if not a.startswith("-")), "")
            if "validator" in fname:
                return "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
            if "vote" in fname:
                return "7nXgWKMEjQA5T2HkNekDGRvwcUEiXPuKgRMHAvtSJjAD\n"
            return "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM\n"
        return f"error: unrecognized subcommand '{sub}'\n"

    def _cmd_journalctl(self, args: list[str], write) -> str:
        joined = " ".join(args)
        if "solana" in joined or not args:
            return (
                "-- Logs begin at Fri 2023-12-01 07:45:12 UTC, end at Mon 2024-01-15 10:23:44 UTC. --\n"
                "Jan 15 07:45:12 validator-node-01 systemd[1]: Starting Solana Validator Node...\n"
                "Jan 15 07:45:12 validator-node-01 systemd[1]: Started Solana Validator Node.\n"
                "Jan 15 09:12:33 validator-node-01 solana-validator[1205]: [INFO] voted on slot 287834521\n"
                "Jan 15 09:12:34 validator-node-01 solana-validator[1205]: [INFO] voted on slot 287834522\n"
                "Jan 15 10:23:44 validator-node-01 solana-validator[1205]: [WARN] banking_stage: 1247 txns\n"
            )
        return (
            "-- Logs begin at Fri 2023-12-01 07:45:12 UTC, end at Mon 2024-01-15 10:23:44 UTC. --\n"
            "Jan 15 10:00:01 validator-node-01 CRON[2345]: (solana) CMD (solana catchup ...)\n"
            "Jan 15 10:23:45 validator-node-01 systemd[1]: Started Session 42 of User solana.\n"
        )

    def _cmd_nc(self, args: list[str], write) -> str:
        return ""

    def _cmd_nmap(self, args: list[str], write) -> str:
        target = next((a for a in args if not a.startswith("-")), "localhost")
        return (
            f"Starting Nmap 7.80 ( https://nmap.org ) at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"Nmap scan report for {target}\n"
            "Host is up (0.00023s latency).\n"
            "Not shown: 996 filtered ports\n"
            "PORT      STATE SERVICE\n"
            "22/tcp    open  ssh\n"
            "8899/tcp  open  solana-rpc\n"
            "8900/tcp  open  solana-ws\n"
            f"\nNmap done: 1 IP address (1 host up) scanned in {random.uniform(1.5,4.5):.2f} seconds\n"
        )

    async def _cmd_top(self, args: list[str], write) -> Optional[str]:
        """Interactive snake game instead of top. Falls back to fake output in exec mode."""
        if self._input_queue is None or self.session.connection_type != "interactive":
            return (
                f"top - {datetime.now(timezone.utc).strftime('%H:%M:%S')} up 42 days,  3:12,"
                "  1 user,  load average: 2.43, 2.31, 2.18\n"
                "Tasks: 147 total,   2 running, 145 sleeping,   0 stopped,   0 zombie\n"
                "%Cpu(s): 12.3 us,  3.1 sy,  0.0 ni, 83.1 id,  1.4 wa,  0.0 hi,  0.1 si,  0.0 st\n"
                "MiB Mem : 131072.0 total,  12288.4 free,  87040.2 used,  31743.4 buff/cache\n"
                "MiB Swap:      0.0 total,      0.0 free,      0.0 used.  42831.6 avail Mem\n"
                "\n"
                "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
                " 1205 solana    20   0    8.1g   2.0g  47332 S  18.7  62.4 2743:23 solana-validator\n"
                " 1389 solana    20   0  512048 131072  12288 S   0.3   0.1   72:12 solana-watchto\n"
                "    1 root      20   0  167876  11244   8192 S   0.0   0.0   0:04.32 systemd\n"
                "  737 root      20   0   14576   5380   4100 S   0.0   0.0   0:00.88 sshd\n"
            )

        self.session.high_interest = True

        # ── Game constants ────────────────────────────────────────────────
        BW, BH = 36, 18           # playable board (cols, rows)
        TICK = 0.14               # seconds per frame
        # Box for game-over screen: inner width 42
        _BX = 42
        _bt = "╔" + "═" * _BX + "╗"
        _bb = "╚" + "═" * _BX + "╝"
        _be = "║" + " " * _BX + "║"

        def _brow(text, pad=2):
            inner = (" " * pad + text).ljust(_BX)
            return "║" + inner + "║"

        # ── Initial snake ─────────────────────────────────────────────────
        cx, cy = BW // 2, BH // 2
        snake: list = [(cx, cy), (cx - 1, cy), (cx - 2, cy)]
        direction = (1, 0)
        pending   = (1, 0)

        def _place_food() -> tuple:
            occ = set(snake)
            while True:
                p = (random.randint(0, BW - 1), random.randint(0, BH - 1))
                if p not in occ:
                    return p

        food  = _place_food()
        score = 0
        alive = True
        quit_game = False

        # ── Renderer ─────────────────────────────────────────────────────
        _DW = BW + 2   # display width (board + walls)
        _SEP = "\x1b[1;32m" + "─" * _DW + "\x1b[0m"
        _CONTROLS = "\x1b[36mWASD move    Q quit\x1b[0m"

        def _render() -> str:
            buf: list[str] = ["\x1b[H"]   # cursor home, no full clear (avoids flicker)
            buf.append(_SEP + "\r\n")
            score_hdr = (
                f" \x1b[1;32mSYSTEM MONITOR\x1b[0m"
                f"  Score: \x1b[1;33m{score:<5}\x1b[0m"
                f"  {_CONTROLS}"
            )
            buf.append(score_hdr + "\r\n")
            buf.append(_SEP + "\r\n")

            head = snake[0]
            body = set(snake[1:])
            for row in range(BH):
                buf.append("\x1b[36m│\x1b[0m")
                for col in range(BW):
                    pos = (col, row)
                    if pos == head:
                        buf.append("\x1b[1;32m◉\x1b[0m")
                    elif pos in body:
                        buf.append("\x1b[32m█\x1b[0m")
                    elif pos == food:
                        buf.append("\x1b[1;33m◆\x1b[0m")
                    else:
                        buf.append(" ")
                buf.append("\x1b[36m│\x1b[0m\r\n")

            buf.append(_SEP + "\r\n")
            return "".join(buf)

        # ── Splash / ready screen ─────────────────────────────────────────
        write("\x1b[2J\x1b[H\x1b[?25l")
        write(
            "\r\n"
            "\x1b[1;31m  SYSTEM MONITOR UNAVAILABLE\x1b[0m\r\n"
            "\x1b[1;33m  PLEASE ENJOY THIS GAME INSTEAD\x1b[0m\r\n"
            "\r\n"
            f"  \x1b[1;32m{'─' * (BW + 2)}\x1b[0m\r\n"
            "  Controls:\r\n"
            "    \x1b[1;32mW A S D\x1b[0m  —  move\r\n"
            "    \x1b[37mQ\x1b[0m  —  quit\r\n"
            f"  \x1b[1;32m{'─' * (BW + 2)}\x1b[0m\r\n"
            "\r\n"
            "  \x1b[1;33m[ PRESS ANY DIRECTION KEY TO START ]\x1b[0m\r\n"
        )
        # Drain stale input (e.g. the '\r' from typing "top"), then wait
        while not self._input_queue.empty():
            self._input_queue.get_nowait()
        started = False
        while not started:
            await asyncio.sleep(0.05)
            while not self._input_queue.empty():
                chunk = self._input_queue.get_nowait()
                if chunk is None:
                    write("\x1b[?25h\x1b[2J\x1b[H")
                    return None
                for ch in chunk:
                    if ch in ("w", "W"):
                        direction = pending = (0, -1)
                        started = True
                    elif ch in ("s", "S"):
                        direction = pending = (0,  1)
                        started = True
                    elif ch in ("d", "D"):
                        direction = pending = (1,  0)
                        started = True
                    elif ch in ("a", "A"):
                        direction = pending = (-1, 0)
                        started = True
                    elif ch in ("q", "Q", "\x03", "\x04"):
                        write("\x1b[?25h\x1b[2J\x1b[H")
                        return None
                    if started:
                        break

        # Rebuild snake body trailing behind the chosen start direction so the
        # first move never collides with the body (default body extends left,
        # which causes instant death if the player starts by pressing left).
        dx, dy = direction
        snake = [(cx, cy), (cx - dx, cy - dy), (cx - 2*dx, cy - 2*dy)]
        food = _place_food()   # re-place in case it landed on the new body

        # ── Game loop ─────────────────────────────────────────────────────
        write("\x1b[2J\x1b[H")
        start = asyncio.get_running_loop().time()

        while alive and not quit_game:
            write(_render())

            # Yield for one tick; data_received() fills the queue during this
            await asyncio.sleep(TICK)

            # Drain every keystroke that arrived this tick
            while not self._input_queue.empty():
                chunk = self._input_queue.get_nowait()
                if chunk is None:
                    quit_game = True
                    break
                for ch in chunk:
                    if ch in ("w", "W"):
                        if direction != (0, 1):   pending = (0, -1)
                    elif ch in ("s", "S"):
                        if direction != (0, -1):  pending = (0,  1)
                    elif ch in ("d", "D"):
                        if direction != (-1, 0):  pending = (1,  0)
                    elif ch in ("a", "A"):
                        if direction != (1, 0):   pending = (-1, 0)
                    elif ch in ("q", "Q", "\x03", "\x04"):
                        quit_game = True

            if quit_game:
                break

            # Advance snake
            direction = pending
            hx, hy = snake[0]
            nx, ny = hx + direction[0], hy + direction[1]

            if nx < 0 or nx >= BW or ny < 0 or ny >= BH or (nx, ny) in set(snake):
                alive = False
                break

            snake.insert(0, (nx, ny))
            if (nx, ny) == food:
                score += 1
                food = _place_food()
            else:
                snake.pop()

        duration = asyncio.get_running_loop().time() - start
        _log_command(
            self.session,
            f"__top_game__ score={score} duration={duration:.0f}s quit={'y' if quit_game else 'died'}",
            [],
        )

        # ── Game-over screen ──────────────────────────────────────────────
        write("\x1b[2J\x1b[H")
        await asyncio.sleep(0.1)

        lines = [
            "",
            f"\x1b[1;31m  {_bt}\x1b[0m",
            f"\x1b[1;31m  {_be}\x1b[0m",
            f"\x1b[1;37m  {_brow('SYSTEM MONITOR UNAVAILABLE')}\x1b[0m",
            f"\x1b[1;31m  {_be}\x1b[0m",
            f"\x1b[1;33m  {_brow('PLEASE ENJOY THIS GAME INSTEAD')}\x1b[0m",
            f"\x1b[1;31m  {_be}\x1b[0m",
            f"\x1b[1;37m  {_brow(f'Final Score:  {score}')}\x1b[0m",
            f"\x1b[1;37m  {_brow(f'Time played:  {int(duration)}s')}\x1b[0m",
            f"\x1b[1;31m  {_be}\x1b[0m",
            f"\x1b[1;31m  {_bb}\x1b[0m",
            "",
        ]
        for line in lines:
            write(line + "\r\n")
            await asyncio.sleep(0.06)

        if score > 10:
            await asyncio.sleep(0.4)
            write(
                "\x1b[1;33m  Impressive. "
                "Most attackers rage quit immediately.\x1b[0m\r\n"
            )

        await asyncio.sleep(2.5)
        write("\x1b[?25h\x1b[2J\x1b[H")
        return None

    def _cmd_df(self, args: list[str], write) -> str:
        return (
            "Filesystem        Size  Used Avail Use% Mounted on\n"
            "/dev/sda1         500G  312G  172G  65% /\n"
            "/dev/nvme0n1p1    2.0T  1.6T  400G  81% /home/solana/ledger\n"
            "tmpfs              64G  241M   64G   1% /dev/shm\n"
            "tmpfs             784M  1.1M  783M   1% /run\n"
            "/dev/sda15        105M  6.1M   99M   6% /boot/efi\n"
        )

    def _cmd_free(self, args: list[str], write) -> str:
        human = "-h" in args or "--human" in args
        if human:
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:           128Gi        87Gi        12Gi       244Mi        29Gi        40Gi\n"
                "Swap:             0B          0B          0B\n"
            )
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:       134217728    91268096    12582912      249856    30366720    41943040\n"
            "Swap:              0           0           0\n"
        )

    def _cmd_uptime(self, args: list[str], write) -> str:
        return f" {datetime.now(timezone.utc).strftime('%H:%M:%S')} up 42 days,  3:12,  1 user,  load average: 2.43, 2.31, 2.18\n"

    def _cmd_w(self, args: list[str], write) -> str:
        return (
            f" {datetime.now(timezone.utc).strftime('%H:%M:%S')} up 42 days,  3:12,  1 user,  load average: 2.43, 2.31, 2.18\n"
            "USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\n"
            "solana   pts/0    203.0.113.42     10:23    0.00s  0.04s  0.00s w\n"
        )

    def _cmd_last(self, args: list[str], write) -> str:
        return (
            "solana   pts/0        203.0.113.42     Mon Jan 15 10:23   still logged in\n"
            "solana   pts/0        198.51.100.7     Sun Jan 14 18:41 - 19:05  (00:23)\n"
            "reboot   system boot  5.15.0-75-generi Fri Dec  1 07:45   still running\n"
            "\nwtmp begins Fri Dec  1 07:45:01 2023\n"
        )

    def _cmd_lsof(self, args: list[str], write) -> str:
        return (
            "COMMAND      PID     USER   FD   TYPE DEVICE SIZE/OFF   NODE NAME\n"
            "systemd        1     root  cwd    DIR    8,1     4096      2 /\n"
            "sshd         737     root    3u  IPv4  18432      0t0    TCP *:22 (LISTEN)\n"
            "solana-v    1205   solana   38u  IPv4  28734      0t0    UDP *:8001\n"
            "solana-v    1205   solana   42u  IPv4  28735      0t0    TCP *:8899 (LISTEN)\n"
            "solana-v    1205   solana   43u  IPv4  28736      0t0    TCP localhost:8900 (LISTEN)\n"
            "solana-v    1205   solana   55u   REG    8,17 1073741824 19283 /home/solana/ledger/rocksdb/LOG\n"
        )

    def _cmd_systemctl(self, args: list[str], write) -> str:
        if not args:
            return "No unit specified.\n"
        subcmd = args[0]
        unit = args[1] if len(args) > 1 else ""
        if subcmd == "status":
            svc = unit or "solana-validator"
            if "solana" in svc or not unit:
                return (
                    f"● solana-validator.service - Solana Validator Node\n"
                    "     Loaded: loaded (/etc/systemd/system/solana-validator.service; enabled; vendor preset: enabled)\n"
                    "     Active: \x1b[1;32mactive (running)\x1b[0m since Fri 2023-12-01 07:45:12 UTC; 44 days 6h ago\n"
                    "   Main PID: 1205 (solana-validator)\n"
                    "      Tasks: 128 (limit: 9374)\n"
                    "     Memory: 87.2G\n"
                    "        CPU: 2h 43min 23.891s\n"
                    "     CGroup: /system.slice/solana-validator.service\n"
                    "             └─1205 solana-validator --identity /home/solana/validator-keypair.json\n"
                )
            return (
                f"● {svc}.service\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
                f"     Active: \x1b[1;32mactive (running)\x1b[0m since Fri 2023-12-01 07:45:12 UTC; 44 days 6h ago\n"
                f"   Main PID: 1205 ({svc})\n"
                "      Tasks: 3 (limit: 9374)\n"
                "     Memory: 8.2M\n"
            )
        if subcmd in ("start", "stop", "restart", "reload", "enable", "disable"):
            return ""
        return f"Unknown operation '{subcmd}'.\n"

    def _cmd_service(self, args: list[str], write) -> str:
        return ""

    async def _cmd_ssh_keygen(self, args: list[str], write) -> None:
        key_type = "rsa"
        for i, a in enumerate(args):
            if a == "-t" and i + 1 < len(args):
                key_type = args[i + 1]
        write(f"Generating public/private {key_type} key pair.\r\n")
        key_path = f"/home/{self.username}/.ssh/id_{key_type}"
        for i, a in enumerate(args):
            if a == "-f" and i + 1 < len(args):
                key_path = args[i + 1]
        write(f"Enter file in which to save the key ({key_path}): ")
        inp = await self._readline(write, echo=True)
        if inp.strip():
            key_path = inp.strip()
        write("Enter passphrase (empty for no passphrase): ")
        await self._readline(write, echo=False, mask=True)
        write("\r\nEnter same passphrase again: ")
        await self._readline(write, echo=False, mask=True)
        write("\r\n")
        await asyncio.sleep(0.4)
        fp = ":".join(f"{random.randint(0,255):02x}" for _ in range(16))
        write(f"Your identification has been saved in {key_path}\r\n")
        write(f"Your public key has been saved in {key_path}.pub\r\n")
        write(f"The key fingerprint is:\r\nSHA256:{fp} {self.username}@{self.HOSTNAME}\r\n")
        write("+---[RSA 3072]----+\r\n")
        for _ in range(7):
            write("|" + "".join(random.choices(".o+=*O@B ", k=17)) + "|\r\n")
        write("+----[SHA256]-----+\r\n")
        # Infinite overwrite loop
        while True:
            write(f"\r\n{key_path} already exists.\r\nOverwrite (y/n)? ")
            ans = await self._readline(write, echo=True)
            if ans in ("\x03", "\x04"):
                write("\r\n")
                return

    async def _cmd_mkfs(self, args: list[str], write) -> None:
        write("\x1b[?25h")  # cursor visible (it blinks)
        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            raise

    def _cmd_head_tail(self, args: list[str], write) -> str:
        # Parse -n NUM or -NUM
        count = 10
        clean_args = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-n" and i + 1 < len(args):
                try:
                    count = int(args[i + 1])
                    i += 2
                    continue
                except ValueError:
                    pass
            elif a.startswith("-") and a[1:].isdigit():
                count = int(a[1:])
                i += 1
                continue
            clean_args.append(a)
            i += 1
        files = [a for a in clean_args if not a.startswith("-")]
        if not files:
            return ""
        path = resolve_path(self.cwd, files[0])
        content = read_file(path)
        if content is None:
            return f"head: cannot open '{files[0]}' for reading: No such file or directory\n"
        lines = content.splitlines()
        return "\n".join(lines[:count]) + "\n"

    @staticmethod
    def _async_noop(args, write):
        return None

    async def _cmd_winner(self, args: list[str], write) -> None:
        """Secret Easter egg: whoami --verbose triggers a 10-second coin rain celebration."""
        self.session.high_interest = True
        winner_tag = {"id": "found_winner_egg", "name": "Winner Easter Egg", "tactic": "collection"}
        if not any(t["id"] == "found_winner_egg" for t in self.session.mitre_tags):
            self.session.mitre_tags.append(winner_tag)

        GOLD   = "\x1b[1;33m"
        RESET  = "\x1b[0m"
        HIDE   = "\x1b[?25l"
        SHOW   = "\x1b[?25h"
        CLR    = "\x1b[2J\x1b[H"
        HOME   = "\x1b[H"

        ROWS, COLS = 24, 80

        # WINNER in big ASCII block letters (bright yellow, 7 rows tall)
        WINNER_ART = [
            r"██╗    ██╗██╗███╗   ██╗███╗   ██╗███████╗██████╗ ",
            r"██║    ██║██║████╗  ██║████╗  ██║██╔════╝██╔══██╗",
            r"██║ █╗ ██║██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝",
            r"██║███╗██║██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗",
            r"╚███╔███╔╝██║██║ ╚████║██║ ╚████║███████╗██║  ██║",
            r" ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
        ]
        ART_ROW = 8   # row where WINNER block starts (1-indexed)
        MSG_ROW = ART_ROW + len(WINNER_ART) + 2

        # Coin/sparkle characters for the rain
        COIN_CHARS = list("$¢oO*°c")

        # Bell schedule: frames at which to fire \x07 (do-do-do-DO × 3)
        # Pattern repeats every 11 frames; 3 repetitions
        BELL_FRAMES: set[int] = set()
        for rep in range(3):
            base_f = rep * 11
            BELL_FRAMES.update([base_f, base_f + 1, base_f + 2, base_f + 4])

        # State: each "drop" is (col, row_float, speed, char)
        NUM_DROPS = 70
        drops: list[list] = []
        for _ in range(NUM_DROPS):
            drops.append([
                random.randint(1, COLS),
                random.uniform(0, ROWS),
                random.uniform(0.5, 1.8),
                random.choice(COIN_CHARS),
            ])

        write(CLR + HIDE)
        await asyncio.sleep(0.05)

        TOTAL_FRAMES = 100  # 100 × 0.1 s = 10 s
        for frame in range(TOTAL_FRAMES):
            buf = [HOME]

            # Draw coin layer (sparse — only show each drop at its integer row)
            # Build a sparse grid rather than clearing the whole screen each frame
            # to reduce flicker: move cursor to each drop position and draw it.
            for drop in drops:
                col, row_f, speed, ch = drop
                r = int(row_f) + 1
                if 1 <= r <= ROWS:
                    buf.append(f"\x1b[{r};{col}H{GOLD}{ch}{RESET}")
                # Erase the row above (trailing tail)
                prev_r = r - 1
                if 1 <= prev_r <= ROWS:
                    buf.append(f"\x1b[{prev_r};{col}H ")
                # Advance drop
                drop[1] = (row_f + speed) % ROWS
                drop[3] = random.choice(COIN_CHARS)

            # Draw WINNER art on top (overwrite whatever coins are there)
            for i, line in enumerate(WINNER_ART):
                r = ART_ROW + i
                # Center the art
                pad = max(0, (COLS - len(line)) // 2)
                buf.append(f"\x1b[{r};{pad + 1}H\x1b[1;33m{line}{RESET}")

            # Draw message below art
            msg = "\U0001f389 Congratulations! You found the secret command! \U0001f389"
            pad_msg = max(0, (COLS - len(msg)) // 2)
            buf.append(f"\x1b[{MSG_ROW};{pad_msg + 1}H\x1b[1;37m{msg}{RESET}")

            write("".join(buf))

            if frame in BELL_FRAMES:
                write("\x07")

            await asyncio.sleep(0.1)

        # Outro
        write(CLR)
        await asyncio.sleep(0.3)
        write("\x1b[1;37m\r\n\r\n  …just kidding. Nothing here. Move along. \U0001f440\r\n\r\n" + RESET + SHOW)
        await asyncio.sleep(1.5)
