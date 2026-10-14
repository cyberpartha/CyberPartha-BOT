"""
Structured Evidence Record for validation observations.
Prevents false-positive labeling: distinguishes confirmed findings from unverified anomalies.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

@dataclass
class EvidenceRecord:
    target_url: str
    http_method: str
    category: str
    test_account: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body_snippet: str
    expected_secure_behavior: str
    actual_observed_behavior: str
    conclusion: str  # VALIDATED, INCONCLUSIVE, NOT REPRODUCIBLE
    confidence: str  # HIGH, MEDIUM, LOW
    limitations: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
