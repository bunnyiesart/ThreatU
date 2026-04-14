import requests

BASE = "https://api.greynoise.io"


class GreyNoise:
    def __init__(self, api_key: str):
        self.headers = {"key": api_key, "Accept": "application/json"}

    def check_ip(self, ip: str) -> dict:
        r = requests.get(
            f"{BASE}/v3/community/{ip}",
            headers=self.headers,
            timeout=30,
        )
        r.raise_for_status()
        d = r.json()
        return {
            "source":       "greynoise",
            "noise":        d.get("noise"),
            "riot":         d.get("riot"),
            "classification": d.get("classification"),
            "name":         d.get("name"),
            "link":         d.get("link"),
            "last_seen":    d.get("last_seen"),
            "message":      d.get("message"),
        }
