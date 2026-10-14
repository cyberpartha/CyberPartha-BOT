"""Base class for all passive reconnaissance source connectors."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseReconSource(ABC):
    def __init__(self, name: str, timeout: int = 10, max_results: int = 100):
        self.name = name
        self.timeout = min(max(timeout, 2), 30)
        self.max_results = min(max(max_results, 10), 500)

    @abstractmethod
    def fetch_subdomains(self, domain: str) -> List[str]:
        """Fetch subdomains for a domain from third-party passive sources only.
        MUST NEVER send traffic directly to the target domain."""
        pass
