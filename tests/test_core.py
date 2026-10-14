import unittest
from unittest.mock import patch
from engine import core
class CoreTests(unittest.TestCase):
    def setUp(self):
        self.policy={"allowed_domains":["example.com"],"excluded_domains":["private.example.com"],
                     "policy_reviewed":False,"ai_allowed":False,"passive_allowed":False}
    def test_scope(self):
        self.assertTrue(core.in_scope("www.example.com",self.policy))
        self.assertFalse(core.in_scope("example.com.evil.org",self.policy))
        self.assertFalse(core.in_scope("private.example.com",self.policy))
        self.assertFalse(core.in_scope("x.private.example.com",self.policy))
    def test_default_deny(self):
        self.assertFalse(core.policy_ok(self.policy))
        self.policy.update(policy_reviewed=True,ai_allowed=True,passive_allowed=True)
        self.assertTrue(core.policy_ok(self.policy))
    def test_name_validation(self):
        with self.assertRaises(ValueError): core.valid_name("../bad")
    def test_domain_validation(self):
        with self.assertRaises(ValueError): core.valid_domain("https://example.com")
    def test_categories(self):
        self.assertGreaterEqual(len(core.CATEGORIES),8)
if __name__=="__main__": unittest.main()
