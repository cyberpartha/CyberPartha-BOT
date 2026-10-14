"""Abstract base class for all approval-gated validation adapters."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from validation.evidence.record import EvidenceRecord
from core.safety.guard import SafetyGuard

class BaseValidationAdapter(ABC):
    def __init__(self, name: str, category: str, max_requests: int = 2):
        self.name = name
        self.category = category
        self.max_requests = max_requests

    @abstractmethod
    def run_validation(
        self,
        target_url: str,
        token_id: str,
        program_name: str,
        safety_guard: SafetyGuard,
        test_context: Dict[str, Any]
    ) -> EvidenceRecord:
        """Execute the bounded, approval-gated validation test.
        Must execute strictly through safety_guard."""
        pass
