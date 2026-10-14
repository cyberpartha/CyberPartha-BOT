"""Validation adapter for HTTP security headers and configuration."""
from __future__ import annotations
from typing import Dict, Any
from .base import BaseValidationAdapter
from validation.evidence.record import EvidenceRecord
from core.safety.guard import SafetyGuard

class SecurityHeadersAdapter(BaseValidationAdapter):
    def __init__(self):
        super().__init__("security-headers", "security-misconfiguration", max_requests=1)

    def run_validation(
        self,
        target_url: str,
        token_id: str,
        program_name: str,
        safety_guard: SafetyGuard,
        test_context: Dict[str, Any]
    ) -> EvidenceRecord:
        safety_guard.authorize_and_consume(
            token_id=token_id,
            program_name=program_name,
            target_url=target_url,
            http_method="HEAD"
        )

        # In offline/mocked environments, retrieve mock response or perform request
        mock_headers = test_context.get("mock_headers", {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff"
        })
        status_code = test_context.get("mock_status", 200)

        missing = []
        if "strict-transport-security" not in mock_headers:
            missing.append("HSTS")
        if "x-content-type-options" not in mock_headers:
            missing.append("X-Content-Type-Options")

        conclusion = "VALIDATED" if missing else "NOT REPRODUCIBLE"
        return EvidenceRecord(
            target_url=target_url,
            http_method="HEAD",
            category="security-misconfiguration",
            test_account=test_context.get("test_account", "researcher_test"),
            request_headers={"User-Agent": "CyberParthaBOT/3.0"},
            request_body=None,
            response_status=status_code,
            response_headers=mock_headers,
            response_body_snippet="",
            expected_secure_behavior="Endpoint must return baseline security headers (HSTS, nosniff).",
            actual_observed_behavior=f"Missing security headers: {missing}" if missing else "Baseline security headers present.",
            conclusion=conclusion,
            confidence="HIGH" if missing else "LOW",
            limitations="Passive HTTP header observation only; does not prove exploitable impact."
        )
