"""Wayback Machine CDX API passive archive connector."""
from __future__ import annotations
import json, urllib.request
from urllib.parse import urlencode, urlsplit
from .base import BaseReconSource

class WaybackSource(BaseReconSource):
    def __init__(self, timeout: int = 10, max_results: int = 100):
        super().__init__("wayback", timeout, max_results)

    def fetch_subdomains(self, domain: str) -> list[str]:
        url = "https://web.archive.org/cdx/search/cdx?" + urlencode({
            "url": domain + "/*",
            "output": "json",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "fl": "original",
            "limit": str(self.max_results)
        })

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None

        opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(url, headers={"User-Agent": "CyberParthaBOT/3.0 research passive-recon"})
        try:
            with opener.open(req, timeout=self.timeout) as r:
                if r.status != 200:
                    return []
                content = r.read(1_000_001)
                records = json.loads(content)
        except Exception:
            return []

        if not isinstance(records, list) or len(records) < 2:
            return []

        hosts = set()
        for row in records[1:]:
            if not isinstance(row, list) or not row or not isinstance(row[0], str):
                continue
            try:
                parsed = urlsplit(row[0])
                host = parsed.hostname
                if parsed.scheme in ("http", "https") and host and host.endswith(domain):
                    hosts.add(host.lower().strip())
            except Exception:
                continue
            if len(hosts) >= self.max_results:
                break
        return sorted(list(hosts))
