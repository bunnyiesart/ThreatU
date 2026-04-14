import requests

BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhaus:
    """No API key required."""

    def check_url(self, url: str) -> dict:
        r = requests.post(f"{BASE}/url/", data={"url": url}, timeout=30)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") == "no_results":
            return {"source": "urlhaus", "found": False}
        return {
            "source":      "urlhaus",
            "found":       True,
            "url_status":  d.get("url_status"),
            "threat":      d.get("threat"),
            "date_added":  d.get("date_added"),
            "blacklists":  d.get("blacklists", {}),
            "tags":        d.get("tags", []),
            "host":        d.get("host"),
        }

    def check_host(self, host: str) -> dict:
        r = requests.post(f"{BASE}/host/", data={"host": host}, timeout=30)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") == "no_results":
            return {"source": "urlhaus", "found": False}
        urls = d.get("urls", [])
        return {
            "source":      "urlhaus",
            "found":       True,
            "url_count":   d.get("urlhaus_reference", len(urls)),
            "blacklists":  d.get("blacklists", {}),
            "urls": [
                {
                    "url":        u.get("url"),
                    "status":     u.get("url_status"),
                    "threat":     u.get("threat"),
                    "date_added": u.get("date_added"),
                    "tags":       u.get("tags", []),
                }
                for u in urls[:10]
            ],
        }
