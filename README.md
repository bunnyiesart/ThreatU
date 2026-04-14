# ThreatU

MCP server for threat intelligence enrichment — wraps multiple TI sources into a single FastMCP server for SOC analysts.

Supports automatic IOC type detection: IPv4, file hashes (MD5/SHA1/SHA256), URLs, and domains.

---

## Sources

| Source | IOC Types | API Key Required |
|---|---|---|
| [VirusTotal](https://virustotal.com) | IP, Hash, Domain, URL | Yes |
| [AbuseIPDB](https://abuseipdb.com) | IP | Yes |
| [GreyNoise](https://greynoise.io) | IP | Yes (community free) |
| [IPInfo](https://ipinfo.io) | IP | Yes (free tier) |
| [MalwareBazaar](https://bazaar.abuse.ch) | Hash | No |
| [URLhaus](https://urlhaus.abuse.ch) | URL, Domain | No |
| [ThreatFox](https://threatfox.abuse.ch) | IP, Hash, Domain, URL | No |

---

## Tools

| Tool | Description |
|---|---|
| `ti_enrich` | Auto-detect IOC type and query all relevant sources |
| `ti_enrich_ip` | Enrich an IP — VirusTotal, AbuseIPDB, GreyNoise, IPInfo |
| `ti_enrich_hash` | Enrich a hash — VirusTotal, MalwareBazaar, ThreatFox |
| `ti_enrich_domain` | Enrich a domain — VirusTotal, URLhaus, ThreatFox |
| `ti_enrich_url` | Enrich a URL — VirusTotal, URLhaus |
| `ti_configured_sources` | Show which sources are configured and ready |

---

## Installation

**1. Clone and setup**

```bash
git clone https://github.com/agrnbqowkofqed/ThreatU.git
cd ThreatU
chmod +x setup.sh
./setup.sh
```

**2. Add API keys**

```bash
nano ~/.config/mcp-threatu/config.json
```

```json
{
    "virustotal": { "api_key": "YOUR_VT_KEY" },
    "abuseipdb":  { "api_key": "YOUR_ABUSEIPDB_KEY" },
    "greynoise":  { "api_key": "YOUR_GREYNOISE_KEY" },
    "ipinfo":     { "api_key": "YOUR_IPINFO_TOKEN" }
}
```

> Sources without a key configured are skipped gracefully — the server still works with any subset of keys.

**3. Register in Claude Code**

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "threatu": {
      "command": "/path/to/ThreatU/.venv/bin/python3",
      "args": ["/path/to/ThreatU/server.py"]
    }
  }
}
```

**4. Install slash command**

```bash
mkdir -p ~/.claude/commands
cp commands/enrich.md ~/.claude/commands/
```

---

## Usage

### Command line

After running `setup.sh`, use the `threatu` command from anywhere:

```bash
threatu 192.168.1.1
threatu d41d8cd98f00b204e9800998ecf8427e
threatu malicious-site.com
threatu https://malicious-site.com/payload.exe
```

All sources are queried **in parallel** and results are printed as a formatted report with a final verdict: `MALICIOUS` / `SUSPICIOUS` / `CLEAN` / `UNKNOWN`.

### Claude Code slash command

```
/enrich 192.168.1.100
/enrich d41d8cd98f00b204e9800998ecf8427e
/enrich malicious-site.com
```

### MCP tools directly

```
ti_enrich("1.2.3.4")
ti_enrich_ip("1.2.3.4")
ti_enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
ti_configured_sources()
```

---

## Getting API Keys

- **VirusTotal**: [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
- **AbuseIPDB**: [abuseipdb.com/register](https://www.abuseipdb.com/register)
- **GreyNoise**: [viz.greynoise.io/signup](https://viz.greynoise.io/signup)
- **IPInfo**: [ipinfo.io/signup](https://ipinfo.io/signup)

---

## Dependencies

- [fastmcp](https://github.com/jlowin/fastmcp) >= 2.0
- requests >= 2.28
