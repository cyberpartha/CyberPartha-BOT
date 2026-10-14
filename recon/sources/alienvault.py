"""AlienVault OTX passive DNS archive connector."""
from __future__ import annotations
import json, urllib.request
from .base import BaseReconSource

class AlienVaultSource(BaseReconSource):
    def __init__(self, timeout: int = 10, max_results: int = 100):
        super().__init__("alienvault", timeout, max_results)

    def fetch_subdomains(self, domain: str) -> list[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberParthaBOT/3.0 research passive-recon"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return []
                data = json.loads(resp.read(1_000_000).decode("utf-8", errors="ignore"))
        except Exception:
            return []

        records = data.get("passive_dns", [])
        hosts = set()
        for entry in records:
            h = entry.get("hostname", "").strip().lower()
            if h.endswith(domain) and len(h) <= 253:
                hosts.add(h)
            if len(hosts) >= self.max_results:
                break
        return sorted(list(hosts))
