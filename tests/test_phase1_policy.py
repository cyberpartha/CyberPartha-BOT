"""Phase 1 — ProfileManager unit tests."""
import json, tempfile, pathlib, unittest
from unittest.mock import patch
from core.policy.profile import ProfileManager, PolicyError, PROGRAMS, STATE


def _tmp_programs_dir():
    return tempfile.mkdtemp()


class TestProfileManager(unittest.TestCase):

    def setUp(self):
        # Redirect to temp dirs for isolation
        self.tmp_prog = pathlib.Path(tempfile.mkdtemp())
        self.tmp_state = pathlib.Path(tempfile.mkdtemp())
        self.pm = ProfileManager()
        # Patch global paths used inside ProfileManager
        import core.policy.profile as mod
        self._orig_programs = mod.PROGRAMS
        self._orig_state = mod.STATE
        mod.PROGRAMS = self.tmp_prog
        mod.STATE = self.tmp_state

    def tearDown(self):
        import core.policy.profile as mod
        mod.PROGRAMS = self._orig_programs
        mod.STATE = self._orig_state

    def test_init_creates_profile(self):
        p = self.pm.init('TestProg', 'example.com')
        self.assertTrue(p.exists())

    def test_init_default_deny(self):
        p = self.pm.init('TestProg', 'example.com')
        data = json.loads(p.read_text())
        self.assertFalse(data['policy_reviewed'])
        self.assertFalse(data['ai_allowed'])
        self.assertFalse(data['passive_allowed'])

    def test_init_duplicate_rejected(self):
        self.pm.init('TestProg', 'example.com')
        with self.assertRaises(PolicyError):
            self.pm.init('TestProg', 'example.com')

    def test_valid_name_rejects_path_traversal(self):
        with self.assertRaises(PolicyError):
            from core.policy.profile import valid_name
            valid_name('../evil')

    def test_valid_domain_rejects_scheme(self):
        with self.assertRaises(PolicyError):
            from core.policy.profile import valid_domain
            valid_domain('https://example.com')

    def test_policy_ok_all_false(self):
        data = {'policy_reviewed': False, 'ai_allowed': False, 'passive_allowed': False}
        self.assertFalse(self.pm.policy_ok(data))

    def test_policy_ok_all_true(self):
        data = {'policy_reviewed': True, 'ai_allowed': True, 'passive_allowed': True}
        self.assertTrue(self.pm.policy_ok(data))

    def test_in_scope_true(self):
        data = {'allowed_domains': ['example.com'], 'excluded_domains': []}
        self.assertTrue(self.pm.in_scope('api.example.com', data))

    def test_in_scope_excluded(self):
        data = {'allowed_domains': ['example.com'], 'excluded_domains': ['private.example.com']}
        self.assertFalse(self.pm.in_scope('private.example.com', data))

    def test_in_scope_subdomain_spoof(self):
        data = {'allowed_domains': ['example.com'], 'excluded_domains': []}
        self.assertFalse(self.pm.in_scope('example.com.evil.org', data))

    def test_require_policy_reviewed_raises(self):
        data = {'policy_reviewed': False}
        with self.assertRaises(PolicyError):
            self.pm.require_policy_reviewed(data)

    def test_require_passive_allowed_raises_without_review(self):
        data = {'policy_reviewed': False, 'passive_allowed': True}
        with self.assertRaises(PolicyError):
            self.pm.require_passive_allowed(data)


if __name__ == '__main__':
    unittest.main()
