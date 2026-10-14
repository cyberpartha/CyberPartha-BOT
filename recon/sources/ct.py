"""Certificate Transparency connector via crt.sh public log archive."""
from __future__ import annotations
import json, re, urllib.request
from urllib.parse import urlencode
from .base import BaseReconSource

class CertificateTransparencySource(BaseReconSource):
    def __init__(self, timeout: int = 10, max_results: int = 100):
        super().__init__("ct", timeout, max_results)

    def fetch_subdomains(self, domain: str) -> list[str]:
        url = "https://crt.sh/?" + urlencode({"q": "%." + domain, "output": "json"})
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberParthaBOT/3.0 research passive-recon"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return []
                raw = resp.read(2_000_000)
                records = json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception:
            return []

        hosts = set()
        for item in records:
            name_val = item.get("name_value", "")
            for name in name_val.split("\n"):
                clean = name.strip().lower()
                clean = re.sub(r"^\*\.", "", clean)
                if clean.endswith(domain) and len(clean) <= 253:
                    hosts.add(clean)
                if len(hosts) >= self.max_results:
                    break
            if len(hosts) >= self.max_results:
                break
        return sorted(list(hosts))
