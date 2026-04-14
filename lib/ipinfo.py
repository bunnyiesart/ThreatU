import requests

BASE = "https://ipinfo.io"


class IPInfo:
    def __init__(self, api_key: str):
        self.params = {"token": api_key}

    def check_ip(self, ip: str) -> dict:
        r = requests.get(f"{BASE}/{ip}/json", params=self.params, timeout=30)
        r.raise_for_status()
        d = r.json()
        return {
            "source":     "ipinfo",
            "ip":         d.get("ip"),
            "hostname":   d.get("hostname"),
            "city":       d.get("city"),
            "region":     d.get("region"),
            "country":    d.get("country"),
            "org":        d.get("org"),
            "timezone":   d.get("timezone"),
            "loc":        d.get("loc"),
            "vpn":        d.get("privacy", {}).get("vpn"),
            "proxy":      d.get("privacy", {}).get("proxy"),
            "tor":        d.get("privacy", {}).get("tor"),
            "hosting":    d.get("privacy", {}).get("hosting"),
        }
