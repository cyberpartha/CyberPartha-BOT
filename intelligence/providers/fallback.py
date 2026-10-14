"""Deterministic offline rule-based reasoning provider (Zero external API dependencies)."""
from __future__ import annotations
from typing import Dict, Any, List
from .base import BaseAIProvider
from ..reasoning.engine import VulnerabilityReasoningEngine

class FallbackRuleProvider(BaseAIProvider):
    def __init__(self):
        super().__init__("rule-based-fallback", model="none")

    def analyze_endpoint(self, endpoint_info: Dict[str, Any], policy_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        hypotheses = VulnerabilityReasoningEngine.generate_hypotheses(endpoint_info, policy_info)
        return [h.to_dict() for h in hypotheses]
