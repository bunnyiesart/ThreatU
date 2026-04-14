import requests

BASE = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox:
    """No API key required."""

    def search(self, ioc: str) -> dict:
        r = requests.post(
            BASE,
            json={"query": "search_ioc", "search_term": ioc},
            timeout=30,
        )
        r.raise_for_status()
        body = r.json()
        if body.get("query_status") != "ok":
            return {"source": "threatfox", "found": False, "status": body.get("query_status")}
        data = body.get("data", [])
        return {
            "source":  "threatfox",
            "found":   True,
            "count":   len(data),
            "results": [
                {
                    "ioc":          d.get("ioc"),
                    "ioc_type":     d.get("ioc_type"),
                    "threat_type":  d.get("threat_type"),
                    "malware":      d.get("malware"),
                    "malware_alias": d.get("malware_alias"),
                    "confidence":   d.get("confidence_level"),
                    "first_seen":   d.get("first_seen"),
                    "last_seen":    d.get("last_seen"),
                    "tags":         d.get("tags", []),
                    "reporter":     d.get("reporter"),
                }
                for d in data[:10]
            ],
        }
