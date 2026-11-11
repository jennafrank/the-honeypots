---
title: Command-count correction (November 2026)
---

# Command-count correction (November 2026)

The first edition of the [147-day SSH honeypot report](report.html) gave the total as 414,070 commands. That figure counts some commands twice. The corrected total is **370,429 commands**. This note explains what went wrong, how it was checked and what changed.

## What went wrong

When an attacker sends a chained line such as `cd /dev/shm || cd /tmp && cat > astats`, the sensor splits it on `; ` and `&&`, logs each part, and then logs the whole line again (`honeypot/shell.py`). Every logged entry is added to the session's `command_count`. The report's total was the sum of `command_count`, so each chained line was counted once per part plus once more as the whole line.

Session-level figures are not affected, because a session that logged an echo also logged its parts. MITRE ATT&CK counts are also mostly unaffected, because tags are de-duplicated per session (`honeypot/session.py`).

## How it was checked

The script that produced the first edition was not kept. Its population was reproduced from the read-only SQLite snapshot of the sensor database instead.

The window that matches all four published population numbers at once is:

- the same five excluded addresses (operator, loopback and one friendly tester), and
- sessions started on or before `2026-09-21T17:46:29Z`.

| Published figure | Value | Recomputed (raw) |
|---|---|---|
| Sessions | 136,128 | 136,128 |
| Unique source IPs | 6,145 | 6,145 |
| Sessions with commands | 69,436 | 69,436 |
| Total commands | 414,070 | 414,070 |

Two other cutoffs matched the first, second and fourth numbers but gave 69,443 sessions with commands, so they were ruled out.

The echo entries were then removed. For each session, a logged entry is dropped if it is the whole-line form of parts logged alongside it. Each part is counted once.

## What changed

| Figure | First edition | Corrected | Where |
|---|---|---|---|
| Total commands | 414,070 | 370,429 (304,067 lines as sent) | Report sections 1, 3 and Closing; README; snack report |
| Miner script length | 93 commands | 81 commands | Report sections 5b, 8, 9 and 12; README |
| Top commands, rank 7 | `cd /dev/shm \|\| ... && cat > astats` = 10,218 | `cd /dev/shm \|\| ... \|\| cd /` = 10,218, then `cat > astats` = 10,218 at rank 8 | Report section 5a |
| Tier 3 (2 to 20 commands) | 1,073 sessions (0.8%) | 1,113 sessions (0.8%) | Report section 5b; README |
| Tier 4 (more than 20 commands) | 4,024 sessions (3.0%) | 3,984 sessions (2.9%) | Report section 5b; README |
| T1548.003 (Sudo) | 29 sessions | 28 sessions | Report section 7 |

The rank 7 row in the first edition was the whole-line echo itself, so it had no independent count. Its two parts each occur 10,218 times.

Forty sessions move from Tier 4 to Tier 3, because echoes had pushed their logged counts above 20. Tiers 1 and 2 do not change.

In the T1548.003 row, one session received the sudo tag only from a whole-line echo.

## Checked and unchanged

These figures recompute to the published value: sessions, unique IPs, sessions with commands, every other top-command count, the `chmod +x w.sh` count (3,637), the systemd session count (3,590) and the other 23 MITRE rows.

## Not reproduced (left as published)

These figures could not be reproduced exactly from the snapshot. They have been left as published rather than replaced with a guess.

- **"3,210 sessions" ran the miner script.** Exactly 3,208 sessions in the window logged 93 entries, and all 3,208 collapse to 81 commands. The first edition's definition of the 3,210 was not recorded.
- **"Crontab manipulation appeared 3,605 times".** No definition tried gives 3,605.
- **`uname -a` = 4,778.** The recompute gives 4,779.

## Scope

- The original PDF edition (`final/hot-pink-huntress-ssh-honeypot-report.pdf`) is unchanged and still shows the first-edition figures.
- The HTML report on this site is the corrected edition.
- The dashboard's "Commands" stat uses the same `SUM(command_count)`, so a fresh dashboard shows the inflated figure until the sensor's logging is changed.

Author: Jenna Frank (Hot Pink Huntress).
