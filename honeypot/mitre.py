"""MITRE ATT&CK technique auto-tagging from shell commands."""

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


# Ordered from most specific to least specific
RULES: list[tuple[re.Pattern, Technique]] = [
    (re.compile(r"\bcat\s+/etc/(passwd|shadow|group|sudoers)\b"),
     Technique("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access")),

    (re.compile(r"\bcat\s+.*\.aws/(credentials|config)\b"),
     Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access")),

    (re.compile(r"\b(wget|curl)\b.*https?://"),
     Technique("T1105", "Ingress Tool Transfer", "Command and Control")),

    (re.compile(r"\bcrontab\s+-[el]\b"),
     Technique("T1053.003", "Scheduled Task/Job: Cron", "Persistence")),

    (re.compile(r"\bexport\s+HISTFILE=/dev/null\b"),
     Technique("T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion")),

    (re.compile(r"\b(unset\s+HISTFILE|history\s+-[cw])\b"),
     Technique("T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion")),

    (re.compile(r"\bchmod\s+(\+x|[0-7]{3,4})\s"),
     Technique("T1222.002", "File and Directory Permissions Modification: Linux and Mac", "Defense Evasion")),

    (re.compile(r"/dev/tcp/"),
     Technique("T1071.001", "Application Layer Protocol: Web Protocols (Bash /dev/tcp)", "Command and Control")),

    (re.compile(r"\b(nc|netcat|ncat)\s+(-[lp]+\s+\d+|-e\s+/bin)\b"),
     Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution")),

    (re.compile(r"\b(python3?|perl|ruby|php)\s+-[ec]\b"),
     Technique("T1059.006", "Command and Scripting Interpreter: Python", "Execution")),

    (re.compile(r"\b(bash|sh)\s+-[ic]\b"),
     Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution")),

    (re.compile(r"\bfind\s+/\s+.*-perm\s+-[04]{1,4}\b"),
     Technique("T1548.001", "Abuse Elevation Control Mechanism: Setuid/Setgid", "Privilege Escalation")),

    (re.compile(r"\bsudo\s+(su|-s|-i)\b"),
     Technique("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation")),

    (re.compile(r"\bsudo\s+"),
     Technique("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation")),

    (re.compile(r"\b(useradd|adduser|usermod)\s+"),
     Technique("T1136.001", "Create Account: Local Account", "Persistence")),

    (re.compile(r"\bssh-keygen\b"),
     Technique("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence")),

    (re.compile(r"\becho\s+.*>>\s*.*authorized_keys\b"),
     Technique("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence")),

    (re.compile(r"\b(iptables|ufw|firewall-cmd)\s+"),
     Technique("T1562.004", "Impair Defenses: Disable or Modify System Firewall", "Defense Evasion")),

    (re.compile(r"\b(ps|pstree)\s+"),
     Technique("T1057", "Process Discovery", "Discovery")),

    (re.compile(r"\b(netstat|ss)\s+"),
     Technique("T1049", "System Network Connections Discovery", "Discovery")),

    (re.compile(r"\bwhoami\b"),
     Technique("T1033", "System Owner/User Discovery", "Discovery")),

    (re.compile(r"\b(id|groups)\b"),
     Technique("T1033", "System Owner/User Discovery", "Discovery")),

    (re.compile(r"\b(ifconfig|ip\s+addr|ip\s+link)\b"),
     Technique("T1016", "System Network Configuration Discovery", "Discovery")),

    (re.compile(r"\buname\b"),
     Technique("T1082", "System Information Discovery", "Discovery")),

    (re.compile(r"\b(cat|less|more)\s+/proc/(version|cpuinfo|meminfo)\b"),
     Technique("T1082", "System Information Discovery", "Discovery")),

    (re.compile(r"\b(ls|find|locate)\s+"),
     Technique("T1083", "File and Directory Discovery", "Discovery")),

    (re.compile(r"\b(cat|less|more|head|tail)\s+/var/log/\b"),
     Technique("T1654", "Log Enumeration", "Discovery")),

    (re.compile(r"\benv\b"),
     Technique("T1552.007", "Unsecured Credentials: Container API", "Credential Access")),

    (re.compile(r"\bcat\s+/proc/[0-9]+/environ\b"),
     Technique("T1552.007", "Unsecured Credentials: Container API", "Credential Access")),
]


def tag_command(command: str) -> list[dict]:
    """Return a list of MITRE technique dicts matching the command."""
    seen: set[str] = set()
    results: list[dict] = []
    for pattern, technique in RULES:
        if pattern.search(command) and technique.id not in seen:
            seen.add(technique.id)
            results.append({
                "id": technique.id,
                "name": technique.name,
                "tactic": technique.tactic,
            })
    return results


# Commands that silently set high_interest = True
HIGH_INTEREST_COMMANDS = re.compile(
    r"\b(whoami|history|wget|curl)\b"
    r"|\bcat\s+/etc/(passwd|shadow)\b"
    r"|\bcat\s+.*credentials\b"
    r"|\bfind\s+/.*-perm\b"
)


def is_high_interest(command: str) -> bool:
    return bool(HIGH_INTEREST_COMMANDS.search(command))


# Commands that trigger the visual Easter egg
TRIPWIRE_COMMANDS = re.compile(
    r"^\s*(sudo\s+(su|bash|sh|-s|-i)|su\s*(root|-|$)|chmod\s+777|chattr)\b"
)


def is_tripwire(command: str) -> bool:
    return bool(TRIPWIRE_COMMANDS.match(command))
