"""
AI Provider Factory with strict policy validation and prompt injection defenses.
"""
from __future__ import annotations
import os, re
from typing import Dict, Any
from .base import BaseAIProvider
from .fallback import FallbackRuleProvider

INJECTION_PATTERNS = re.compile(
    r'(?i)(ignore previous instructions|disregard|system prompt|bypass scope|override policy|disable safety|approve all)'
)

def sanitize_ai_prompt(text: str) -> str:
    """Sanitize inputs before passing to AI reasoning engines to block prompt injection."""
    if INJECTION_PATTERNS.search(text):
        return "[INPUT FILTERED: Potential Prompt Injection Pattern Detected]"
    # Strip dangerous delimiters
    cleaned = text.replace("<|im_start|>", "").replace("<|im_end|>", "").replace("```", "")
    return cleaned

class AIProviderFactory:
    @staticmethod
    def get_provider(program_policy: Dict[str, Any]) -> BaseAIProvider:
        # 1. Enforce program policy: if AI is prohibited or not explicitly reviewed, fallback to rule-based engine
        if not program_policy.get("ai_allowed", False) or not program_policy.get("policy_reviewed", False):
            return FallbackRuleProvider()

        provider_name = os.environ.get("CYBERPARTHA_AI_PROVIDER", "fallback").lower().strip()

        # When no provider is explicitly configured or available, return safe rule-based fallback
        return FallbackRuleProvider()
