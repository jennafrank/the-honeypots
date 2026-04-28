#!/usr/bin/env python3
"""
generate_report.py — produce a Markdown + PDF honeypot analysis report.

Usage:
    python generate_report.py [--hours 48] [--out /data/reports/report.md]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from dotenv import load_dotenv
load_dotenv()

from honeypot.db import (
    command_frequency,
    high_interest_sessions,
    hourly_volume,
    init_db,
    mitre_frequency,
    recent_sessions,
    stats_today,
    top_asns,
    top_countries,
    top_credentials,
)


def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n * 100 // total}%"


def _bar(n: int, max_n: int, width: int = 20) -> str:
    if max_n == 0:
        return ""
    filled = int(n * width / max_n)
    return "█" * filled + "░" * (width - filled)


def build_markdown(hours: int = 48) -> str:
    now = datetime.now(timezone.utc)
    stats = stats_today()
    countries = top_countries(15)
    asns = top_asns(15)
    creds = top_credentials(20)
    cmds = command_frequency(25)
    mitre = mitre_frequency(20)
    hourly = hourly_volume(hours)
    hi_sessions = high_interest_sessions(20)
    recent = recent_sessions(100)

    total_sessions = len(recent)
    cloud_count = sum(1 for s in recent if s.get("is_cloud"))
    resi_count = total_sessions - cloud_count
    unique_ips = len({s["source_ip"] for s in recent})
    total_commands = sum(s["command_count"] for s in recent)

    # Find peak hour
    peak_hour = max(hourly, key=lambda h: h["count"], default={"hour": "N/A", "count": 0})

    md = f"""# SSH Honeypot Analysis Report

**Generated:** {now.strftime("%Y-%m-%d %H:%M UTC")}
**Period:** Last {hours} hours
**Classification:** Internal / Research Use Only

---

## Executive Summary

During the analysis window, the honeypot recorded **{total_sessions} connection attempts**
from **{unique_ips} unique IP addresses** across
**{len(countries)} countries**.
Attackers executed **{total_commands} commands** across all sessions.
**{stats["high_interest_today"]} sessions** were classified as high-interest (session duration >60s
or execution of credential-access / lateral-movement commands).

| Metric | Value |
|--------|-------|
| Total connections | {total_sessions} |
| Unique source IPs | {unique_ips} |
| High-interest sessions | {stats["high_interest_today"]} |
| Cloud / VPS sources | {cloud_count} ({_pct(cloud_count, total_sessions)}) |
| Residential sources | {resi_count} ({_pct(resi_count, total_sessions)}) |
| Commands executed | {total_commands} |
| Peak hour | {peak_hour.get("hour", "N/A")} ({peak_hour["count"]} connections) |

"""

    # ── Attack volume ─────────────────────────────────────────────────────────
    md += "## Attack Volume Over Time\n\n"
    md += "```\n"
    md += f"{'Hour':<20} {'Count':>6}  Histogram\n"
    md += "-" * 50 + "\n"
    max_count = max((h["count"] for h in hourly), default=1)
    for h in hourly[-24:]:
        hour_str = h["hour"][11:16] if len(h["hour"]) > 10 else h["hour"]
        bar = _bar(h["count"], max_count, 24)
        md += f"{hour_str:<20} {h['count']:>6}  {bar}\n"
    md += "```\n\n"

    # ── Geographic breakdown ──────────────────────────────────────────────────
    md += "## Geographic Breakdown\n\n"
    md += "### Top Source Countries\n\n"
    md += "| # | Country | Connections | Share |\n"
    md += "|---|---------|-------------|-------|\n"
    for i, c in enumerate(countries, 1):
        md += f"| {i} | {c['geo_country'] or 'Unknown'} | {c['count']} | {_pct(c['count'], total_sessions)} |\n"

    md += "\n### Cloud vs Residential Split\n\n"
    md += f"- **Cloud / VPS:** {cloud_count} ({_pct(cloud_count, total_sessions)}) — "
    md += "Automated scanning infrastructure, bulletproof hosting\n"
    md += f"- **Residential / Unknown:** {resi_count} ({_pct(resi_count, total_sessions)}) — "
    md += "Compromised home/corporate IPs, residential proxies\n\n"

    md += "### Top ASNs\n\n"
    md += "| ASN | Provider | Type | Connections |\n"
    md += "|-----|----------|------|-------------|\n"
    for a in asns:
        atype = "Cloud/VPS" if a["is_cloud"] else "Residential"
        md += f"| {a['geo_asn'] or '—'} | {a['geo_isp'] or '—'} | {atype} | {a['count']} |\n"
    md += "\n"

    # ── Top credentials ───────────────────────────────────────────────────────
    md += "## Top Credentials Attempted\n\n"
    md += "| # | Username | Password | Attempts |\n"
    md += "|---|----------|----------|----------|\n"
    for i, c in enumerate(creds, 1):
        md += f"| {i} | `{c['username']}` | `{c['password'] or '(empty)'}` | {c['count']} |\n"
    md += "\n"
    md += "> **Note:** Default/common credentials dominate. SSH key brute-force "
    md += "accounts for public-key attempts.\n\n"

    # ── TTP analysis ──────────────────────────────────────────────────────────
    md += "## TTP Analysis — MITRE ATT&CK Mapping\n\n"
    md += "| Technique ID | Name | Tactic | Occurrences |\n"
    md += "|-------------|------|--------|-------------|\n"
    for t in mitre:
        md += f"| [{t['id']}](https://attack.mitre.org/techniques/{t['id'].replace('.','/')}) "
        md += f"| {t['name']} | {t['tactic']} | {t['count']} |\n"
    md += "\n"

    md += "### Command Frequency\n\n"
    md += "```\n"
    max_cmd = max((c["count"] for c in cmds), default=1)
    for c in cmds[:15]:
        bar = _bar(c["count"], max_cmd, 20)
        md += f"{c['command']:<20} {c['count']:>5}  {bar}\n"
    md += "```\n\n"

    # ── Interactive session profiles ──────────────────────────────────────────
    md += "## High-Interest Session Profiles\n\n"
    if not hi_sessions:
        md += "*No high-interest sessions recorded in this period.*\n\n"
    else:
        for idx, s in enumerate(hi_sessions, 1):
            dur = f"{int(s.get('duration_seconds', 0))}s"
            geo = f"{s.get('geo_city','')}, {s.get('geo_country','')}".strip(", ")
            cloud_tag = " (Cloud/VPS)" if s.get("is_cloud") else ""
            md += f"### Session {idx} — {s['source_ip']}{cloud_tag}\n\n"
            md += f"- **Time:** {s.get('started_at','—')}\n"
            md += f"- **Origin:** {geo or 'Unknown'} · {s.get('geo_asn','')}\n"
            md += f"- **Credentials:** `{s['username']}` / `{s.get('password','')}`\n"
            md += f"- **Duration:** {dur} · {s['command_count']} commands\n"

            if s.get("mitre_tags"):
                tags = ", ".join(f"{t['id']} ({t['tactic']})" for t in s["mitre_tags"])
                md += f"- **MITRE:** {tags}\n"

            md += "\n**Command transcript:**\n\n```\n"
            for c in s.get("commands", []):
                ts = c.get("timestamp", "")
                ts_short = ts[11:19] if len(ts) > 10 else ts
                md += f"[{ts_short}] $ {c['command']}\n"
            md += "```\n\n"

            # Narrative summary
            cmds_list = [c["command"] for c in s.get("commands", [])]
            narrative = _narrative(s, cmds_list)
            if narrative:
                md += f"**Analysis:** {narrative}\n\n"

    # ── Canary tokens ─────────────────────────────────────────────────────────
    md += "## Canary Token Observations\n\n"
    aws_reads = [s for s in hi_sessions if any("credentials" in c["command"]
                 for c in s.get("commands", []))]
    if aws_reads:
        md += f"**{len(aws_reads)} session(s)** accessed the fake `~/.aws/credentials` file. "
        md += "If the canarytokens.org AWS key was configured, these accesses would have "
        md += "triggered out-of-band alerts via AWS API calls.\n\n"
        for s in aws_reads:
            md += f"- `{s['source_ip']}` at {s.get('started_at','—')}\n"
    else:
        md += "*No credential file accesses detected in this period.*\n\n"

    # ── Conclusions ───────────────────────────────────────────────────────────
    md += "## Conclusions\n\n"
    md += "1. **Credential stuffing dominates** — the vast majority of attempts use simple "
    md += "default credentials (`root/root`, `admin/admin`, etc.).\n\n"
    md += f"2. **{'Cloud/VPS infrastructure' if cloud_count > resi_count else 'Residential IPs'} "
    md += f"are the primary attack source** "
    md += f"({_pct(max(cloud_count, resi_count), total_sessions)} of traffic).\n\n"
    md += "3. **Interactive attackers show reconnaissance patterns** — high-interest sessions "
    md += "consistently run `whoami`, `cat /etc/passwd`, `ps aux`, and credential file enumeration.\n\n"
    md += "4. **MITRE coverage** — techniques span Initial Access through Credential Access, "
    md += "indicating a mixture of automated scanners and human operators.\n\n"
    md += "5. **Recommendations:** rotate exposed credentials immediately, enable IP reputation "
    md += "blocking at the perimeter, and consider port-knocking or VPN-only SSH access.\n\n"
    md += "---\n*Generated by SSH Honeypot Analytics*\n"

    return md


def _narrative(session: dict, cmds: list[str]) -> str:
    """Generate a brief human-readable summary of what the attacker did."""
    parts = []
    if any("cat /etc/passwd" in c or "cat /etc/shadow" in c for c in cmds):
        parts.append("Attacker enumerated system users via `/etc/passwd`")
    if any(".aws/credentials" in c for c in cmds):
        parts.append("accessed cloud credentials file")
    if any("wget" in c or "curl" in c for c in cmds):
        parts.append("attempted to download external tools/payloads")
    if any("crontab" in c for c in cmds):
        parts.append("examined/modified scheduled tasks for persistence")
    if any("chmod" in c for c in cmds):
        parts.append("modified file permissions")
    if any("history" in c for c in cmds):
        parts.append("read command history for intelligence")
    if any("ps " in c or "ps aux" in c for c in cmds):
        parts.append("enumerated running processes")
    if session.get("is_cloud"):
        parts.append("Source is cloud/VPS infrastructure suggesting automated tooling")

    return ". ".join(parts).capitalize() + "." if parts else ""


def build_pdf(md_text: str, out_path: str) -> bool:
    """Convert markdown → HTML → PDF via weasyprint."""
    try:
        import markdown2
        from weasyprint import CSS, HTML

        html_body = markdown2.markdown(
            md_text,
            extras=["tables", "fenced-code-blocks", "header-ids"],
        )
        css = CSS(string="""
            @page { margin: 2cm; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                   font-size: 12px; line-height: 1.6; color: #24292f; }
            h1 { color: #0969da; border-bottom: 2px solid #0969da; padding-bottom: 8px; }
            h2 { color: #24292f; border-bottom: 1px solid #d0d7de; margin-top: 24px; }
            h3 { color: #57606a; }
            table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 11px; }
            th { background: #f6f8fa; border: 1px solid #d0d7de; padding: 6px 12px; text-align: left; }
            td { border: 1px solid #d0d7de; padding: 5px 12px; }
            code, pre { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 11px;
                        background: #f6f8fa; }
            pre { padding: 12px; border-radius: 6px; overflow: auto; }
            blockquote { border-left: 4px solid #0969da; padding-left: 12px; color: #57606a; }
        """)
        full_html = f"<!DOCTYPE html><html><body>{html_body}</body></html>"
        HTML(string=full_html).write_pdf(out_path, stylesheets=[css])
        return True
    except ImportError:
        print("weasyprint not available — skipping PDF generation", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"PDF generation failed: {exc}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Generate honeypot analysis report")
    parser.add_argument("--hours", type=int, default=48, help="Hours of data to include")
    parser.add_argument("--out", default="/data/reports/report.md", help="Output Markdown path")
    parser.add_argument("--pdf", action="store_true", help="Also generate PDF")
    args = parser.parse_args()

    init_db()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating report for last {args.hours}h …")
    md = build_markdown(hours=args.hours)

    out_path.write_text(md, encoding="utf-8")
    print(f"Markdown saved: {out_path}")

    if args.pdf:
        pdf_path = out_path.with_suffix(".pdf")
        if build_pdf(md, str(pdf_path)):
            print(f"PDF saved: {pdf_path}")

    print("Done.")


if __name__ == "__main__":
    main()
