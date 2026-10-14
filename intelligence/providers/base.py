"""Abstract base class for pluggable AI reasoning providers."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseAIProvider(ABC):
    def __init__(self, name: str, model: str = ""):
        self.name = name
        self.model = model

    @abstractmethod
    def analyze_endpoint(self, endpoint_info: Dict[str, Any], policy_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform offline reasoning on endpoint metadata.
        MUST NEVER send active traffic to target or execute unauthorized tests."""
        pass
