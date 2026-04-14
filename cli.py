#!/usr/bin/env python3
"""
ThreatU CLI — Enrich any IOC across all threat intelligence sources.

Usage:
    threatu <ioc>
    threatu 192.168.1.1
    threatu d41d8cd98f00b204e9800998ecf8427e
    threatu malicious-site.com
    threatu https://malicious-site.com/payload.exe
"""

import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.virustotal import VirusTotal
from lib.abuseipdb import AbuseIPDB
from lib.greynoise import GreyNoise
from lib.malwarebazaar import MalwareBazaar
from lib.urlhaus import URLhaus
from lib.threatfox import ThreatFox
from lib.ipinfo import IPInfo

console = Console()

CONFIG_PATH = os.path.expanduser("~/.config/mcp-threatu/config.json")

_RE_IPV4   = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def get_key(cfg: dict, service: str):
    k = cfg.get(service, {}).get("api_key", "").strip()
    return k if k else None


# ── IOC detection ─────────────────────────────────────────────────────────────

def detect_type(ioc: str) -> str:
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


# ── Query runners ─────────────────────────────────────────────────────────────

def run(name: str, fn, *args):
    try:
        return name, fn(*args)
    except Exception as e:
        return name, {"error": str(e)}


def query_ip(ioc: str, cfg: dict) -> dict:
    tasks = {}
    k = get_key(cfg, "virustotal")
    if k:
        tasks["VirusTotal"] = (VirusTotal(k).check_ip, ioc)
    k = get_key(cfg, "abuseipdb")
    if k:
        tasks["AbuseIPDB"] = (AbuseIPDB(k).check_ip, ioc)
    k = get_key(cfg, "greynoise")
    if k:
        tasks["GreyNoise"] = (GreyNoise(k).check_ip, ioc)
    k = get_key(cfg, "ipinfo")
    if k:
        tasks["IPInfo"] = (IPInfo(k).check_ip, ioc)
    tasks["ThreatFox"] = (ThreatFox().search, ioc)
    return _parallel(tasks)


def query_hash(ioc: str, cfg: dict) -> dict:
    tasks = {}
    k = get_key(cfg, "virustotal")
    if k:
        tasks["VirusTotal"] = (VirusTotal(k).check_hash, ioc)
    tasks["MalwareBazaar"] = (MalwareBazaar().check_hash, ioc)
    tasks["ThreatFox"]     = (ThreatFox().search, ioc)
    return _parallel(tasks)


def query_domain(ioc: str, cfg: dict) -> dict:
    tasks = {}
    k = get_key(cfg, "virustotal")
    if k:
        tasks["VirusTotal"] = (VirusTotal(k).check_domain, ioc)
    tasks["URLhaus"]   = (URLhaus().check_host, ioc)
    tasks["ThreatFox"] = (ThreatFox().search, ioc)
    return _parallel(tasks)


def query_url(ioc: str, cfg: dict) -> dict:
    tasks = {}
    k = get_key(cfg, "virustotal")
    if k:
        tasks["VirusTotal"] = (VirusTotal(k).check_url, ioc)
    tasks["URLhaus"] = (URLhaus().check_url, ioc)
    return _parallel(tasks)


def _parallel(tasks: dict) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
        futures = {pool.submit(run, name, fn, *([arg] if not isinstance(arg, tuple) else arg)):
                   name for name, (fn, *arg) in tasks.items()}
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result
    return results


# ── Verdict logic ─────────────────────────────────────────────────────────────

def compute_verdict(results: dict, ioc_type: str) -> tuple[str, str]:
    """Returns (verdict_label, color)."""
    score = 0

    vt = results.get("VirusTotal", {})
    if not vt.get("error"):
        mal = vt.get("malicious", 0)
        if mal >= 10:
            score += 3
        elif mal >= 3:
            score += 2
        elif mal >= 1:
            score += 1

    abuse = results.get("AbuseIPDB", {})
    if not abuse.get("error"):
        conf = abuse.get("abuse_confidence", 0) or 0
        if conf >= 80:
            score += 3
        elif conf >= 50:
            score += 2
        elif conf >= 20:
            score += 1

    gn = results.get("GreyNoise", {})
    if not gn.get("error") and gn.get("noise") is False and gn.get("riot") is True:
        score -= 2  # known benign service

    mb = results.get("MalwareBazaar", {})
    if mb.get("found"):
        score += 3

    uh = results.get("URLhaus", {})
    if uh.get("found"):
        score += 2

    tf = results.get("ThreatFox", {})
    if tf.get("found"):
        score += 2

    if score >= 4:
        return "MALICIOUS", "bold red"
    elif score >= 2:
        return "SUSPICIOUS", "bold yellow"
    elif score == 0 and not any(r.get("error") for r in results.values()):
        return "CLEAN", "bold green"
    return "UNKNOWN", "bold white"


# ── Rich rendering ────────────────────────────────────────────────────────────

def render_virustotal(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    mal = r.get("malicious", 0)
    sus = r.get("suspicious", 0)
    total = mal + sus + r.get("harmless", 0) + r.get("undetected", 0)
    verdict = Text()
    if mal > 0:
        verdict.append(f"✗ {mal}/{total} engines flagged", style="red")
    else:
        verdict.append(f"✓ Clean ({total} engines)", style="green")
    details = []
    for k in ("country", "asn", "as_owner", "reputation", "name", "type_description",
               "registrar", "md5", "sha256", "final_url"):
        if r.get(k) is not None:
            details.append(f"{k}: {r[k]}")
    if details:
        verdict.append("\n  " + "  |  ".join(details[:4]), style="dim")
    return verdict


def render_abuseipdb(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    conf = r.get("abuse_confidence", 0) or 0
    reports = r.get("total_reports", 0) or 0
    color = "red" if conf >= 50 else ("yellow" if conf >= 20 else "green")
    t = Text()
    t.append(f"Confidence: {conf}%  |  Reports: {reports}", style=color)
    for k in ("isp", "country", "usage_type", "tor"):
        if r.get(k) is not None:
            t.append(f"\n  {k}: {r[k]}", style="dim")
    return t


def render_greynoise(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    t = Text()
    cls = r.get("classification", "unknown")
    riot = r.get("riot", False)
    noise = r.get("noise", False)
    if riot:
        t.append(f"✓ RIOT — known benign service: {r.get('name', '')}", style="green")
    elif noise and cls == "malicious":
        t.append(f"✗ Noise — malicious scanner", style="red")
    elif noise:
        t.append(f"⚠ Noise — {cls} scanner: {r.get('name', '')}", style="yellow")
    else:
        t.append(f"Not in GreyNoise dataset", style="dim")
    if r.get("last_seen"):
        t.append(f"\n  Last seen: {r['last_seen']}", style="dim")
    return t


def render_ipinfo(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    t = Text()
    parts = [r.get("org", ""), r.get("city", ""), r.get("country", "")]
    t.append("  |  ".join(p for p in parts if p))
    flags = [k for k in ("vpn", "proxy", "tor", "hosting") if r.get(k)]
    if flags:
        t.append(f"\n  ⚠ Flags: {', '.join(flags)}", style="yellow")
    return t


def render_malwarebazaar(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    if not r.get("found"):
        return Text("Not found in MalwareBazaar", style="green")
    t = Text()
    t.append(f"✗ Found — {r.get('signature') or r.get('file_name', '')}", style="red")
    t.append(f"\n  Type: {r.get('file_type')}  |  Size: {r.get('file_size')} bytes", style="dim")
    t.append(f"\n  First seen: {r.get('first_seen')}", style="dim")
    if r.get("tags"):
        t.append(f"\n  Tags: {', '.join(r['tags'])}", style="dim")
    return t


def render_urlhaus(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    if not r.get("found"):
        return Text("Not found in URLhaus", style="green")
    status = r.get("url_status", "unknown")
    color = "red" if status == "online" else "yellow"
    t = Text()
    t.append(f"✗ Found — Status: {status}  |  Threat: {r.get('threat', 'unknown')}", style=color)
    urls = r.get("urls", [])
    if urls:
        t.append(f"\n  {len(urls)} URLs listed", style="dim")
    return t


def render_threatfox(r: dict):
    if r.get("error"):
        return Text(f"Error: {r['error']}", style="red")
    if not r.get("found"):
        return Text("Not found in ThreatFox", style="green")
    t = Text()
    first = r["results"][0] if r.get("results") else {}
    t.append(f"✗ Found — {first.get('malware', '')}  ({r['count']} records)", style="red")
    t.append(f"\n  Threat: {first.get('threat_type')}  |  Confidence: {first.get('confidence')}%", style="dim")
    if first.get("tags"):
        t.append(f"\n  Tags: {', '.join(first['tags'])}", style="dim")
    return t


RENDERERS = {
    "VirusTotal":    render_virustotal,
    "AbuseIPDB":     render_abuseipdb,
    "GreyNoise":     render_greynoise,
    "IPInfo":        render_ipinfo,
    "MalwareBazaar": render_malwarebazaar,
    "URLhaus":       render_urlhaus,
    "ThreatFox":     render_threatfox,
}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/] threatu <ioc>")
        console.print("  threatu 192.168.1.1")
        console.print("  threatu d41d8cd98f00b204e9800998ecf8427e")
        console.print("  threatu malicious-site.com")
        console.print("  threatu https://malicious-site.com/payload.exe")
        sys.exit(1)

    ioc = " ".join(sys.argv[1:]).strip()
    ioc_type = detect_type(ioc)

    if ioc_type == "unknown":
        console.print(f"[red]Cannot detect IOC type for:[/] {ioc}")
        sys.exit(1)

    cfg = load_config()

    console.print(Panel(
        f"[bold]IOC:[/]  {ioc}\n[bold]Type:[/] {ioc_type.upper()}",
        title="[bold cyan]ThreatU — Threat Intelligence Report[/]",
        border_style="cyan",
    ))

    with console.status("[cyan]Querying sources in parallel...[/]"):
        dispatch = {"ip": query_ip, "hash": query_hash, "domain": query_domain, "url": query_url}
        results = dispatch[ioc_type](ioc, cfg)

    # Results table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Source", style="bold", min_width=14)
    table.add_column("Finding")

    for source, renderer in RENDERERS.items():
        if source in results:
            table.add_row(source, renderer(results[source]))

    console.print(table)

    # Verdict
    verdict, color = compute_verdict(results, ioc_type)
    console.print(Panel(
        f"[{color}]{verdict}[/]",
        title="Verdict",
        border_style=color.replace("bold ", ""),
        expand=False,
    ))


if __name__ == "__main__":
    main()
