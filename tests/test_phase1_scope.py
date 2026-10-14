"""Phase 1 — ScopeGuard unit tests (offline, no network)."""
import unittest
from core.scope.guard import ScopeGuard, ScopeViolation


class TestScopeGuard(unittest.TestCase):

    def setUp(self):
        self.sg = ScopeGuard(
            allowed_domains=['example.com', 'api.example.com'],
            excluded_domains=['private.example.com'],
        )

    # ── allowed ───────────────────────────────────────────────────────────────
    def test_allowed_exact(self):
        self.sg.check_url('https://example.com/path')

    def test_allowed_subdomain(self):
        self.sg.check_url('https://api.example.com/v1/test')

    def test_allowed_deep_subdomain(self):
        self.sg.check_url('https://sub.api.example.com/data')

    # ── blocked ───────────────────────────────────────────────────────────────
    def test_blocked_http(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('http://example.com/path')

    def test_blocked_out_of_scope(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('https://evil.com/path')

    def test_blocked_subdomain_spoof(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('https://example.com.evil.org/path')

    def test_blocked_excluded_domain(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('https://private.example.com/admin')

    def test_blocked_excluded_subdomain(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('https://deep.private.example.com/data')

    def test_blocked_credentials_in_url(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('https://user:pass@example.com/path')

    def test_blocked_fragment(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_url('https://example.com/path#section')

    def test_blocked_no_allowed_domains(self):
        with self.assertRaises(ValueError):
            ScopeGuard(allowed_domains=[])

    # ── redirect check ────────────────────────────────────────────────────────
    def test_redirect_same_host_allowed(self):
        self.sg.check_redirect(
            'https://api.example.com/v1',
            'https://api.example.com/v2',
        )

    def test_redirect_cross_host_blocked(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_redirect(
                'https://api.example.com/v1',
                'https://example.com/elsewhere',
            )

    def test_redirect_out_of_scope_blocked(self):
        with self.assertRaises(ScopeViolation):
            self.sg.check_redirect(
                'https://api.example.com/v1',
                'https://attacker.com/steal',
            )

    # ── is_allowed_host ───────────────────────────────────────────────────────
    def test_is_allowed_host_true(self):
        self.assertTrue(self.sg.is_allowed_host('api.example.com'))

    def test_is_allowed_host_false(self):
        self.assertFalse(self.sg.is_allowed_host('evil.com'))

    def test_is_allowed_host_excluded_false(self):
        self.assertFalse(self.sg.is_allowed_host('private.example.com'))


if __name__ == '__main__':
    unittest.main()
