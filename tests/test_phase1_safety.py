"""Phase 1 — SafetyGuard integration tests (offline, mocked)."""
import unittest
from unittest.mock import patch, MagicMock
from core.scope.guard import ScopeGuard, ScopeViolation
from core.approval.token import ApprovalToken, ApprovalStore, ApprovalError
from core.audit.logger import AuditLogger
from core.budget import RequestBudget, BudgetExceeded
from core.stop_switch import EmergencyStop
from core.safety.guard import SafetyGuard, RateLimiter
import tempfile, pathlib


def _make_guard(budget_limit=2, dry_run=False, stopped=False):
    scope = ScopeGuard(
        allowed_domains=['example.com'],
        excluded_domains=['private.example.com'],
    )
    approvals = ApprovalStore()
    budget = RequestBudget(budget_limit)
    with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False) as f:
        log_path = pathlib.Path(f.name)
    audit = AuditLogger(log_path, 'TestProg')
    guard = SafetyGuard(scope, approvals, budget, audit, dry_run=dry_run)
    return guard, approvals, budget


URL = 'https://example.com/api/data'
PROG = 'TestProg'


class TestSafetyGuard(unittest.TestCase):

    def test_full_pipeline_success(self):
        guard, approvals, _ = _make_guard()
        token = ApprovalToken.create(PROG, URL, 'GET')
        approvals.register(token)
        with patch('core.safety.guard.check_stop'):
            guard.authorize_and_consume(token.token_id, PROG, URL, 'GET')

    def test_stop_file_blocks_all(self):
        guard, approvals, _ = _make_guard()
        token = ApprovalToken.create(PROG, URL, 'GET')
        approvals.register(token)
        with patch('core.safety.guard.check_stop', side_effect=EmergencyStop('STOP')):
            with self.assertRaises(EmergencyStop):
                guard.authorize_and_consume(token.token_id, PROG, URL, 'GET')
        self.assertTrue(guard.is_stopped)

    def test_out_of_scope_blocked(self):
        guard, approvals, _ = _make_guard()
        evil_url = 'https://evil.com/api'
        token = ApprovalToken.create(PROG, evil_url, 'GET')
        approvals.register(token)
        with patch('core.safety.guard.check_stop'):
            with self.assertRaises(ScopeViolation):
                guard.authorize_and_consume(token.token_id, PROG, evil_url, 'GET')

    def test_no_token_blocked(self):
        guard, approvals, _ = _make_guard()
        with patch('core.safety.guard.check_stop'):
            with self.assertRaises(ApprovalError):
                guard.authorize_and_consume('invalid-id', PROG, URL, 'GET')

    def test_budget_exhausted(self):
        guard, approvals, _ = _make_guard(budget_limit=1)
        t1 = ApprovalToken.create(PROG, URL, 'GET')
        t2 = ApprovalToken.create(PROG, URL, 'GET')
        approvals.register(t1)
        approvals.register(t2)
        with patch('core.safety.guard.check_stop'):
            guard.authorize_and_consume(t1.token_id, PROG, URL, 'GET')
            with self.assertRaises(BudgetExceeded):
                guard.authorize_and_consume(t2.token_id, PROG, URL, 'GET')

    def test_token_single_use_via_guard(self):
        guard, approvals, _ = _make_guard(budget_limit=5)
        token = ApprovalToken.create(PROG, URL, 'GET')
        approvals.register(token)
        with patch('core.safety.guard.check_stop'):
            guard.authorize_and_consume(token.token_id, PROG, URL, 'GET')
            with self.assertRaises(ApprovalError):
                guard.authorize_and_consume(token.token_id, PROG, URL, 'GET')

    def test_dry_run_raises_not_sends(self):
        guard, approvals, _ = _make_guard(dry_run=True)
        token = ApprovalToken.create(PROG, URL, 'GET')
        approvals.register(token)
        with patch('core.safety.guard.check_stop'):
            with self.assertRaises(RuntimeError) as ctx:
                guard.authorize_and_consume(token.token_id, PROG, URL, 'GET')
        self.assertIn('DRY-RUN', str(ctx.exception))


class TestRateLimiter(unittest.TestCase):

    def test_within_limit(self):
        rl = RateLimiter(max_requests=5, window_seconds=60)
        self.assertTrue(rl.within_limit())

    def test_acquire_does_not_crash(self):
        rl = RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            rl.acquire()


if __name__ == '__main__':
    unittest.main()
