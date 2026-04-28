# SSH Honeypot Threat Intelligence Report
## Sable Saint-Claire & The Honeypots

**Report Period:** `[START_DATE]` — `[END_DATE]` (`[HOURS]` hours)
**Generated:** `[TIMESTAMP]`
**Honeypot Identity:** Solana Validator Node (`sol-validator-01`)
**Deployment:** `[CLOUD_PROVIDER]` / `[REGION]`

---

## Executive Summary

During this `[N]`-day observation window, the honeypot recorded:

| Metric | Value |
|---|---|
| Total sessions | `[SESSION_COUNT]` |
| Total commands executed | `[COMMAND_COUNT]` |
| Unique source IPs | `[UNIQUE_IPS]` |
| Countries of origin | `[COUNTRY_COUNT]` |
| High-interest sessions | `[HIGH_INTEREST_COUNT]` |
| AbuseIPDB-flagged IPs | `[ABUSED_IP_COUNT]` |
| Cloud-origin sessions | `[CLOUD_PCT]`% |
| Most active attack hour | `[PEAK_HOUR]` UTC |

**Key findings this period:**

> *[Summarize 3–5 notable observations: dominant attack ASN, most common credential, any novel TTPs, unusual command sequences, geographic patterns.]*

---

## 1. Attack Volume & Timing

### Hourly Distribution

```
[HOURLY_BAR_CHART]
```

*Interpretation:* `[Notes on peak hours — are attacks randomized, or do they cluster in business hours for a specific timezone? Describe any burst patterns.]*`

### Session Duration

- Median session length: `[MEDIAN_DURATION]` seconds
- Longest session: `[MAX_DURATION]` seconds (`[MAX_SESSION_IP]`)
- Sessions under 30 seconds: `[SHORT_SESSION_PCT]`%

*Short sessions typically indicate automated scanners. Sessions over 60 seconds usually indicate human operators.*

---

## 2. Credential Analysis

### Top 20 Username/Password Pairs

| Rank | Username | Password | Attempts |
|:---:|---|---|:---:|
| 1 | `[USER]` | `[PASS]` | `[N]` |
| 2 | | | |
| ... | | | |

### Observations

- **Most sprayed username:** `[USERNAME]` (`[PCT]`% of attempts)
- **Most sprayed password:** `[PASSWORD]`
- **Password list sophistication:** `[Low / Medium / High — evaluate based on whether common rockyou passwords appear, or novel credential combinations]`
- **Default credential targeting:** `[Yes/No — were Solana-specific credentials attempted?]`

> *[Analysis: Are these credentials from a known leaked dataset? Are attackers specifically targeting Solana validator defaults? Any domain-specific credential patterns?]*

---

## 3. Geographic Distribution

### Top 10 Source Countries

| Rank | Country | Sessions | % |
|:---:|---|:---:|:---:|
| 1 | `[COUNTRY]` | `[N]` | `[PCT]`% |
| ... | | | |

### Top 10 Source ASNs

| Rank | ASN | Organization | Sessions |
|:---:|---|---|:---:|
| 1 | `AS[N]` | `[ORG]` | `[N]` |
| ... | | | |

### Cloud vs. Residential

- Cloud infrastructure: `[CLOUD_PCT]`%
- Residential/ISP: `[RESIDENTIAL_PCT]`%
- Unknown/VPN: `[UNKNOWN_PCT]`%

*High cloud percentage suggests VPS-hosted bots or rented scanning infrastructure. High residential percentage may indicate compromised home machines or residential proxies.*

---

## 4. MITRE ATT&CK Breakdown

### Technique Frequency

| Technique ID | Name | Tactic | Occurrences |
|---|---|---|:---:|
| `[T####.###]` | `[Name]` | `[Tactic]` | `[N]` |
| ... | | | |

### Tactic Distribution

```
Discovery          ████████████████████ [N] commands
Credential Access  ████████████         [N] commands
Defense Evasion    █████████            [N] commands
Execution          ████████             [N] commands
Persistence        ██████               [N] commands
Privilege Escalation ████              [N] commands
Command & Control  ███                  [N] commands
```

### Key Observations

> *[Which tactics dominate? Is the pattern consistent with automated scanning (high Discovery, low Execution) or human operators (more varied, including Persistence and Defense Evasion)? Which specific techniques were most common and what does that suggest about attacker objectives?]*

---

## 5. Command Analysis

### Top 20 Commands Observed

| Rank | Command | Sessions | % of Total |
|:---:|---|:---:|:---:|
| 1 | `[CMD]` | `[N]` | `[PCT]`% |
| ... | | | |

### Command Sequence Patterns

*Common attack sequences observed this period:*

**Pattern A — Automated Recon:**
```
whoami → id → uname -a → cat /etc/passwd → ls /home → exit
```

**Pattern B — Credential Harvest:**
```
cat /etc/shadow → cat /home/solana/.aws/credentials → find / -name "*.pem"
```

**Pattern C — Persistence Attempt:**
```
cat ~/.ssh/authorized_keys → echo [pubkey] >> ~/.ssh/authorized_keys → crontab -e
```

> *[Describe the 2–3 most common command sequences actually observed. What attacker objectives do they suggest? Did any sessions reach later-stage TTPs?]*

---

## 6. High-Interest Sessions

### Flagged Sessions This Period

| Session ID | IP | Country | Duration | Commands | Flags |
|---|---|---|:---:|:---:|---|
| `[ID]` | `[IP]` | `[CC]` | `[SEC]`s | `[N]` | `[flags]` |
| ... | | | | | |

### Notable Session Deep-Dives

#### Session `[ID]` — `[IP]` (`[COUNTRY]`)

- **Duration:** `[N]` seconds
- **ASN:** `AS[N]` (`[ORG]`)
- **AbuseIPDB Score:** `[N]`/100
- **Connection type:** Interactive / Non-interactive
- **Commands executed:**

```
[COMMAND_HISTORY]
```

- **Analysis:** `[What was this attacker trying to do? Did they find any canary files? Did they trigger any Easter eggs? What MITRE techniques does this session represent?]`

---

## 7. Canary Token Interactions

Canary files that were accessed this period:

| File | Accesses | Unique IPs |
|---|:---:|:---:|
| `wallet.json` | `[N]` | `[N]` |
| `private_keys_backup.txt` | `[N]` | `[N]` |
| `DO_NOT_OPEN.zip` | `[N]` | `[N]` |
| `.aws/credentials` | `[N]` | `[N]` |
| `validator-keypair.json` | `[N]` | `[N]` |

*Canary file access is a strong indicator of human-operated post-exploitation activity. Automated scanners rarely open plausible-looking wallet files.*

---

## 8. AbuseIPDB Correlation

- IPs with confidence score > 50%: `[N]` (`[PCT]`% of unique IPs)
- IPs with confidence score > 90%: `[N]`
- Previously unreported IPs: `[N]`

> *[Were any high-confidence IPs from known botnet C2 infrastructure? Any IPs that had not previously been reported — potential new actors?]*

---

## 9. Threat Intelligence Conclusions

> *[Write 3–5 paragraphs synthesizing the period's findings. Structure as:*
>
> *1. Overall threat landscape — what's the volume trend vs. prior period?*
> *2. Attacker profile — automated bots vs. human operators vs. mixed?*
> *3. TTP assessment — how sophisticated are the observed techniques? Consistent with commodity scanning tools or targeted activity?*
> *4. Solana-specific observations — are attackers aware they're hitting a validator? Are they targeting validator-specific files and commands?*
> *5. Recommendations — what defensive actions would this data support if this were a real validator?]*

---

## 10. Methodology

### Data Collection

This report covers honeypot data collected over `[N]` hours from `[START]` to `[END]` UTC. The honeypot presents as a Solana mainnet-beta validator node running `solana-cli 1.17.6` with a visible staking balance of 47,832 SOL. All SSH connections are accepted regardless of credential.

### Enrichment Pipeline

Each source IP is enriched with:
- **GeoIP** (ip-api.com) — country, city, ASN, ISP, lat/lon
- **AbuseIPDB** — abuse confidence score, report count
- **Reverse DNS** — hostname resolution

### MITRE Tagging

Commands are automatically tagged against the MITRE ATT&CK Enterprise framework using regex rules in `honeypot/mitre.py`. Tags are assigned per-command at execution time.

### Limitations

- The honeypot accepts all credentials, which inflates session counts relative to a real system with authentication
- IP geolocation is approximate and may be inaccurate for VPN/proxy traffic
- MITRE tagging is pattern-based and may over-tag ambiguous commands
- Automated scanner sessions are not filtered from statistics unless otherwise noted

### Tools

- asyncssh 2.14+ / Python 3.10+
- SQLite (honeypot.db)
- ip-api.com (GeoIP)
- AbuseIPDB v2 API

---

*Report generated by `generate_report.py`. Run `python generate_report.py --hours [N] --pdf` to reproduce.*
