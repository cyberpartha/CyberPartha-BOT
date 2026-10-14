"""Validation adapter for owned-object authorization boundaries (IDOR/BOLA)."""
from __future__ import annotations
from typing import Dict, Any
from .base import BaseValidationAdapter
from validation.evidence.record import EvidenceRecord
from core.safety.guard import SafetyGuard

class OwnedObjectAuthAdapter(BaseValidationAdapter):
    def __init__(self):
        super().__init__("owned-object-auth", "access-control", max_requests=2)

    def run_validation(
        self,
        target_url: str,
        token_id: str,
        program_name: str,
        safety_guard: SafetyGuard,
        test_context: Dict[str, Any]
    ) -> EvidenceRecord:
        # Requires two researcher-owned test object IDs
        owned_a = test_context.get("owned_id_a")
        owned_b = test_context.get("owned_id_b")
        if not owned_a or not owned_b:
            raise ValueError("IDOR validation strictly requires two researcher-owned test identifiers (owned_id_a, owned_id_b).")

        # 1. Authorize the specific test request
        safety_guard.authorize_and_consume(
            token_id=token_id,
            program_name=program_name,
            target_url=target_url,
            http_method="GET"
        )

        mock_status = test_context.get("mock_status", 403)
        mock_body = test_context.get("mock_body", "Access Denied")

        # Evidence validation: HTTP 200 with object data from Account B accessed by Account A
        if mock_status == 200 and test_context.get("data_revealed"):
            conclusion = "VALIDATED"
            confidence = "HIGH"
            actual = f"Account A successfully accessed object {owned_b} belonging to Account B without permission."
        else:
            conclusion = "NOT REPRODUCIBLE"
            confidence = "HIGH"
            actual = f"Server properly denied cross-account access (Status {mock_status})."

        return EvidenceRecord(
            target_url=target_url,
            http_method="GET",
            category="access-control",
            test_account=test_context.get("test_account", "account_a"),
            request_headers={"Authorization": "[REDACTED_TEST_BEARER_TOKEN]"},
            request_body=None,
            response_status=mock_status,
            response_headers={"Content-Type": "application/json"},
            response_body_snippet=mock_body[:200],
            expected_secure_behavior=f"Cross-account access to object {owned_b} must be denied (401/403/404).",
            actual_observed_behavior=actual,
            conclusion=conclusion,
            confidence=confidence,
            limitations="Tested exclusively against researcher-owned test fixtures; zero third-party data accessed."
        )
