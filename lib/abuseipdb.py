import requests

BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDB:
    def __init__(self, api_key: str):
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        r = requests.get(
            f"{BASE}/check",
            headers=self.headers,
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
            timeout=30,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "source":            "abuseipdb",
            "abuse_confidence":  d.get("abuseConfidenceScore"),
            "total_reports":     d.get("totalReports"),
            "distinct_users":    d.get("numDistinctUsers"),
            "last_reported":     d.get("lastReportedAt"),
            "country":           d.get("countryCode"),
            "isp":               d.get("isp"),
            "domain":            d.get("domain"),
            "is_whitelisted":    d.get("isWhitelisted"),
            "usage_type":        d.get("usageType"),
            "tor":               d.get("isTor"),
        }
