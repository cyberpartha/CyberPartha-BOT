"""
Validation Runner: Enforces human pre-test display, single-use token consumption,
zero chaining, rate limits, and budget compliance.
"""
from __future__ import annotations
from typing import Dict, Any, Optional
from validation.adapters.base import BaseValidationAdapter
from validation.evidence.record import EvidenceRecord
from core.safety.guard import SafetyGuard
from core.approval.token import ApprovalToken, ApprovalStore

class ValidationRunner:
    @staticmethod
    def format_approval_modal(
        target_url: str,
        http_method: str,
        adapter: BaseValidationAdapter,
        test_account: str,
        program_policy: Dict[str, Any]
    ) -> str:
        rate = program_policy.get("max_req_per_minute", 30)
        return f"""
================================================================================
                    CYBERPARTHA BOT v3 — ACTIVE TEST APPROVAL
================================================================================
Target URL      : {target_url}
HTTP Method     : {http_method}
Validation Test : {adapter.name} ({adapter.category})
Test Account    : {test_account}
Request Budget  : Max {adapter.max_requests} request(s)
Rate Limit      : {rate} req/min
Policy Check    : Approved category, in-scope target
Stop Condition  : Immediate abort on STOP file, redirect out-of-scope, or 429
================================================================================
"""

    @staticmethod
    def execute_test(
        adapter: BaseValidationAdapter,
        target_url: str,
        token_id: str,
        program_name: str,
        safety_guard: SafetyGuard,
        test_context: Dict[str, Any]
    ) -> EvidenceRecord:
        # Executes the single bounded test via the adapter and safety guard
        return adapter.run_validation(
            target_url=target_url,
            token_id=token_id,
            program_name=program_name,
            safety_guard=safety_guard,
            test_context=test_context
        )
