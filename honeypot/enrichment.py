"""Async IP enrichment: GeoIP (ip-api.com), AbuseIPDB, and reverse DNS."""

import asyncio
import logging
import os
import socket
from typing import Optional

import aiohttp

from .db import get_ip_cache, set_ip_cache

logger = logging.getLogger(__name__)

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# ASN prefixes commonly associated with cloud/VPS providers
_CLOUD_ASN_PATTERNS = (
    "amazon", "google", "microsoft", "digitalocean", "linode", "vultr",
    "hetzner", "ovh", "contabo", "leaseweb", "choopa", "as-choopa",
    "psychz", "quadranet", "serverius", "servermania", "sharktech",
    "frantech", "buyvm", "cloudinnovation", "alibaba", "tencent",
    "huawei", "oracle", "ibm", "rackspace", "fastly", "cloudflare",
    "as14061", "as14618", "as16509", "as15169", "as8075", "as20940",
)


def _is_cloud_asn(asn: str, isp: str) -> bool:
    combined = (asn + " " + isp).lower()
    return any(p in combined for p in _CLOUD_ASN_PATTERNS)


async def enrich_ip(ip: str) -> dict:
    """Return enrichment dict for ip, using cache if available."""
    cached = get_ip_cache(ip)
    if cached:
        return cached

    enrichment = {
        "geo_country": "",
        "geo_country_code": "",
        "geo_city": "",
        "geo_asn": "",
        "geo_isp": "",
        "geo_lat": 0.0,
        "geo_lon": 0.0,
        "is_cloud": False,
        "abuse_confidence": 0,
        "rdns": "",
    }

    await asyncio.gather(
        _fetch_geoip(ip, enrichment),
        _fetch_rdns(ip, enrichment),
        _fetch_abuseipdb(ip, enrichment),
    )

    enrichment["is_cloud"] = _is_cloud_asn(enrichment["geo_asn"], enrichment["geo_isp"])
    set_ip_cache(ip, enrichment)
    return enrichment


async def _fetch_geoip(ip: str, out: dict) -> None:
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,lat,lon"
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5)
        ) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        out["geo_country"] = data.get("country", "")
                        out["geo_country_code"] = data.get("countryCode", "")
                        out["geo_city"] = data.get("city", "")
                        out["geo_isp"] = data.get("isp", data.get("org", ""))
                        out["geo_asn"] = data.get("as", "")
                        out["geo_lat"] = float(data.get("lat", 0))
                        out["geo_lon"] = float(data.get("lon", 0))
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)


async def _fetch_rdns(ip: str, out: dict) -> None:
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=3.0,
        )
        out["rdns"] = result[0]
    except Exception:
        out["rdns"] = ""


async def _fetch_abuseipdb(ip: str, out: dict) -> None:
    if not ABUSEIPDB_KEY:
        return
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5)
        ) as session:
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    out["abuse_confidence"] = data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception as exc:
        logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
