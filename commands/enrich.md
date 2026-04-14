Enrich an IOC (IP, hash, domain, or URL) across all threat intelligence sources. Arguments: $ARGUMENTS

Expected format: `<ioc>`
Examples:
  `/enrich 192.168.1.100`
  `/enrich d41d8cd98f00b204e9800998ecf8427e`
  `/enrich malicious-site.com`
  `/enrich https://malicious-site.com/payload.exe`

Steps:
1. Call ti_enrich with the IOC — it auto-detects the type and queries all relevant sources.
2. Apply analyst mindset silently to the combined results:
   - VT malicious > 5 → high confidence malicious
   - VT malicious 1-5 → suspicious, check other sources
   - AbuseIPDB confidence > 50% → likely malicious IP
   - AbuseIPDB confidence > 80% → confirmed abusive IP
   - GreyNoise noise=true → known internet scanner, likely not targeted
   - GreyNoise riot=true → known benign service (Google, Cloudflare, etc.)
   - MalwareBazaar found=true → confirmed malware sample
   - URLhaus found=true + url_status=online → active malicious URL
   - ThreatFox found=true → known IOC in threat intel database
   - IPInfo hosting=true or vpn=true or tor=true → infrastructure concern
3. Report:

   **IOC:** `<ioc>` | **Type:** <ip|hash|url|domain>

   **Verdict:** Malicious / Suspicious / Clean / Unknown
   *(one line summary of overall assessment)*

   **Source results:**
   For each source that returned data, show a concise summary row:
   | Source | Finding | Key detail |

   **Details:**
   Expand any source that returned a positive/suspicious result with full details.

   **Recommended action:**
   - Tier 1: known noise/benign → no action
   - Tier 2: suspicious → monitor, cross-check in IRIS with iris_global_search_ioc
   - Tier 3: confirmed malicious → open/update IRIS case, block at firewall
