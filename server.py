"""
ThreatU MCP server — Threat intelligence enrichment for SOC analysts.

Wraps VirusTotal, AbuseIPDB, GreyNoise, MalwareBazaar, URLhaus,
ThreatFox, and IPInfo into a single FastMCP server.

Services requiring API keys (configured in ~/.config/mcp-threatu/config.json):
  virustotal, abuseipdb, greynoise, ipinfo

Services with no API key required:
  malwarebazaar, urlhaus, threatfox
"""

import json
import logging
import os
import re
import sys
from typing import Optional

from fastmcp import FastMCP

# Add project root to path for lib imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.virustotal import VirusTotal
from lib.abuseipdb import AbuseIPDB
from lib.greynoise import GreyNoise
from lib.malwarebazaar import MalwareBazaar
from lib.urlhaus import URLhaus
from lib.threatfox import ThreatFox
from lib.ipinfo import IPInfo

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("threatu")

CONFIG_PATH = os.path.expanduser("~/.config/mcp-threatu/config.json")

# ── Config loading ────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _key(cfg: dict, service: str) -> Optional[str]:
    """Return API key for a service, or None if not configured."""
    k = cfg.get(service, {}).get("api_key", "").strip()
    return k if k else None


# ── Lazy singletons ───────────────────────────────────────────────────────────

_cfg = None
_vt = None
_abuse = None
_gn = None
_mb = None
_uh = None
_tf = None
_ip = None


def cfg():
    global _cfg
    if _cfg is None:
        _cfg = _load_config()
    return _cfg


def vt() -> Optional[VirusTotal]:
    global _vt
    if _vt is None:
        k = _key(cfg(), "virustotal")
        if k:
            _vt = VirusTotal(k)
    return _vt


def abuse() -> Optional[AbuseIPDB]:
    global _abuse
    if _abuse is None:
        k = _key(cfg(), "abuseipdb")
        if k:
            _abuse = AbuseIPDB(k)
    return _abuse


def gn() -> Optional[GreyNoise]:
    global _gn
    if _gn is None:
        k = _key(cfg(), "greynoise")
        if k:
            _gn = GreyNoise(k)
    return _gn


def mb() -> MalwareBazaar:
    global _mb
    if _mb is None:
        _mb = MalwareBazaar()
    return _mb


def uh() -> URLhaus:
    global _uh
    if _uh is None:
        _uh = URLhaus()
    return _uh


def tf() -> ThreatFox:
    global _tf
    if _tf is None:
        _tf = ThreatFox()
    return _tf


def ipinfo() -> Optional[IPInfo]:
    global _ip
    if _ip is None:
        k = _key(cfg(), "ipinfo")
        if k:
            _ip = IPInfo(k)
    return _ip


# ── IOC type detection ────────────────────────────────────────────────────────

_RE_IPV4   = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if _RE_IPV4.match(ioc):
        return "ip"
    if _RE_MD5.match(ioc) or _RE_SHA1.match(ioc) or _RE_SHA256.match(ioc):
        return "hash"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "unknown"


def _run(client, method: str, *args):
    """Call client.method(*args), return result or error dict on failure."""
    if client is None:
        return {"error": "not_configured"}
    try:
        return getattr(client, method)(*args)
    except Exception as e:
        return {"error": str(e)}


# ── MCP server ────────────────────────────────────────────────────────────────

mcp = FastMCP("threatu")


@mcp.tool()
def ti_enrich_ip(ip: str) -> dict:
    """Enrich an IP address across all threat intelligence sources.

    Sources: VirusTotal, AbuseIPDB, GreyNoise, IPInfo.

    Args:
        ip: IPv4 address to investigate.

    Returns:
        {source_name: result_dict} for each source. Sources without an API
        key configured return {"error": "not_configured"}.
    """
    return {
        "virustotal": _run(vt(),     "check_ip",  ip),
        "abuseipdb":  _run(abuse(),  "check_ip",  ip),
        "greynoise":  _run(gn(),     "check_ip",  ip),
        "ipinfo":     _run(ipinfo(), "check_ip",  ip),
    }


@mcp.tool()
def ti_enrich_hash(hash_value: str) -> dict:
    """Enrich a file hash (MD5, SHA1, or SHA256) across threat intelligence sources.

    Sources: VirusTotal, MalwareBazaar, ThreatFox.

    Args:
        hash_value: File hash to look up.

    Returns:
        {source_name: result_dict} for each source.
    """
    return {
        "virustotal":    _run(vt(), "check_hash", hash_value),
        "malwarebazaar": _run(mb(), "check_hash", hash_value),
        "threatfox":     _run(tf(), "search",     hash_value),
    }


@mcp.tool()
def ti_enrich_domain(domain: str) -> dict:
    """Enrich a domain across threat intelligence sources.

    Sources: VirusTotal, URLhaus, ThreatFox.

    Args:
        domain: Domain name to investigate (e.g. "malicious-site.com").

    Returns:
        {source_name: result_dict} for each source.
    """
    return {
        "virustotal": _run(vt(), "check_domain", domain),
        "urlhaus":    _run(uh(), "check_host",   domain),
        "threatfox":  _run(tf(), "search",       domain),
    }


@mcp.tool()
def ti_enrich_url(url: str) -> dict:
    """Enrich a URL across threat intelligence sources.

    Sources: VirusTotal, URLhaus.

    Args:
        url: Full URL to investigate (must include http:// or https://).

    Returns:
        {source_name: result_dict} for each source.
    """
    return {
        "virustotal": _run(vt(), "check_url", url),
        "urlhaus":    _run(uh(), "check_url", url),
    }


@mcp.tool()
def ti_enrich(ioc: str) -> dict:
    """Auto-detect IOC type and enrich across all relevant sources.

    Detects: IPv4, MD5/SHA1/SHA256 hashes, URLs, domains.
    Routes to the correct enrich tool automatically.

    Args:
        ioc: Any indicator — IP, hash, URL, or domain.

    Returns:
        {"ioc_type": str, "results": {source_name: result_dict}}
    """
    ioc_type = detect_ioc_type(ioc.strip())
    dispatch = {
        "ip":     ti_enrich_ip,
        "hash":   ti_enrich_hash,
        "url":    ti_enrich_url,
        "domain": ti_enrich_domain,
    }
    fn = dispatch.get(ioc_type)
    if fn is None:
        return {"ioc_type": "unknown", "results": {}, "error": f"Cannot detect IOC type for: {ioc}"}
    return {"ioc_type": ioc_type, "results": fn(ioc.strip())}


@mcp.tool()
def ti_configured_sources() -> dict:
    """Show which threat intelligence sources are configured and ready.

    Returns:
        {source_name: {"configured": bool, "requires_key": bool}}
    """
    return {
        "virustotal":    {"configured": vt()     is not None, "requires_key": True},
        "abuseipdb":     {"configured": abuse()  is not None, "requires_key": True},
        "greynoise":     {"configured": gn()      is not None, "requires_key": True},
        "ipinfo":        {"configured": ipinfo() is not None, "requires_key": True},
        "malwarebazaar": {"configured": True,                 "requires_key": False},
        "urlhaus":       {"configured": True,                 "requires_key": False},
        "threatfox":     {"configured": True,                 "requires_key": False},
    }


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
