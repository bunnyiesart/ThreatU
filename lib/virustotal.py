import base64
import requests

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal:
    def __init__(self, api_key: str):
        self.headers = {"x-apikey": api_key}

    def _get(self, path: str) -> dict:
        r = requests.get(f"{BASE}{path}", headers=self.headers, timeout=30)
        r.raise_for_status()
        return r.json().get("data", {}).get("attributes", {})

    def _stats(self, attrs: dict) -> dict:
        s = attrs.get("last_analysis_stats", {})
        return {
            "malicious":  s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless":   s.get("harmless", 0),
            "undetected": s.get("undetected", 0),
        }

    def check_ip(self, ip: str) -> dict:
        a = self._get(f"/ip_addresses/{ip}")
        return {
            "source": "virustotal",
            **self._stats(a),
            "country":   a.get("country"),
            "asn":       a.get("asn"),
            "as_owner":  a.get("as_owner"),
            "reputation": a.get("reputation"),
        }

    def check_hash(self, h: str) -> dict:
        a = self._get(f"/files/{h}")
        return {
            "source": "virustotal",
            **self._stats(a),
            "name":             a.get("meaningful_name"),
            "type_description": a.get("type_description"),
            "size":             a.get("size"),
            "md5":              a.get("md5"),
            "sha256":           a.get("sha256"),
            "first_seen":       a.get("first_submission_date"),
            "last_seen":        a.get("last_submission_date"),
            "tags":             a.get("tags", []),
        }

    def check_domain(self, domain: str) -> dict:
        a = self._get(f"/domains/{domain}")
        return {
            "source": "virustotal",
            **self._stats(a),
            "reputation":    a.get("reputation"),
            "registrar":     a.get("registrar"),
            "creation_date": a.get("creation_date"),
            "categories":    a.get("categories", {}),
            "tags":          a.get("tags", []),
        }

    def check_url(self, url: str) -> dict:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        a = self._get(f"/urls/{url_id}")
        return {
            "source": "virustotal",
            **self._stats(a),
            "final_url":  a.get("last_final_url"),
            "title":      a.get("title"),
            "categories": a.get("categories", {}),
        }
