"""Tests for Phase 4 validation adapters and runner."""
import unittest, tempfile, pathlib, os
from unittest.mock import MagicMock
from validation.adapters.security_headers import SecurityHeadersAdapter
from validation.adapters.auth_object import OwnedObjectAuthAdapter
from validation.execution.runner import ValidationRunner
from core.safety.guard import SafetyGuard, RateLimiter
from core.scope.guard import ScopeGuard
from core.approval.token import ApprovalStore, ApprovalToken
from core.budget import RequestBudget
from core.audit.logger import AuditLogger

class TestPhase4Validation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False)
        self.tmp.close()
        self.log_path = pathlib.Path(self.tmp.name)

        self.scope = ScopeGuard(allowed_domains=['example.com'], excluded_domains=['evil.example.com'])
        self.approvals = ApprovalStore()
        self.budget = RequestBudget(5)
        self.audit = AuditLogger(self.log_path, 'TestProg')
        self.guard = SafetyGuard(self.scope, self.approvals, self.budget, self.audit)

    def tearDown(self):
        try: os.unlink(self.tmp.name)
        except OSError: pass

    def test_security_headers_adapter_missing_headers_validated(self):
        url = "https://example.com/api"
        token = ApprovalToken.create("TestProg", url, "HEAD")
        self.approvals.register(token)

        adapter = SecurityHeadersAdapter()
        context = {"mock_headers": {"content-type": "text/html"}, "mock_status": 200}

        record = ValidationRunner.execute_test(
            adapter=adapter,
            target_url=url,
            token_id=token.token_id,
            program_name="TestProg",
            safety_guard=self.guard,
            test_context=context
        )
        self.assertEqual(record.conclusion, "VALIDATED")
        self.assertIn("HSTS", record.actual_observed_behavior)

    def test_owned_object_auth_adapter_enforces_two_ids(self):
        adapter = OwnedObjectAuthAdapter()
        with self.assertRaises(ValueError):
            adapter.run_validation("https://example.com/item/1", "token123", "TestProg", self.guard, {})

    def test_owned_object_auth_adapter_idor_confirmed_only_with_evidence(self):
        url = "https://example.com/documents/2"
        token = ApprovalToken.create("TestProg", url, "GET")
        self.approvals.register(token)

        adapter = OwnedObjectAuthAdapter()
        context = {
            "owned_id_a": "doc_1",
            "owned_id_b": "doc_2",
            "mock_status": 200,
            "data_revealed": True,
            "mock_body": '{"doc_id": "doc_2", "owner": "user_b"}'
        }

        record = adapter.run_validation(
            target_url=url,
            token_id=token.token_id,
            program_name="TestProg",
            safety_guard=self.guard,
            test_context=context
        )
        self.assertEqual(record.conclusion, "VALIDATED")
        self.assertEqual(record.confidence, "HIGH")

    def test_unapproved_target_fails_closed(self):
        url = "https://example.com/secret"
        adapter = SecurityHeadersAdapter()
        with self.assertRaises(Exception):
            ValidationRunner.execute_test(
                adapter=adapter,
                target_url=url,
                token_id="unregistered_token",
                program_name="TestProg",
                safety_guard=self.guard,
                test_context={}
            )

if __name__ == '__main__':
    unittest.main()
