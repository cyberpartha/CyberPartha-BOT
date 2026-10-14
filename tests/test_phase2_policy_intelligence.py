"""Tests for policy intelligence parser and fingerprint invalidation."""
import unittest
from core.policy.platforms import PolicyParser

class TestPolicyIntelligence(unittest.TestCase):
    def test_parse_hackerone_policy(self):
        text = """
        Targets in scope:
        *.example.com
        api.target.com

        Out of scope:
        dev.example.com
        test.target.com

        Prohibited:
        Automated vulnerability scanner flooding is prohibited.
        No automated tools without authorization.
        """
        parsed = PolicyParser.parse_text(text, platform="hackerone", policy_url="https://hackerone.com/demo")
        self.assertEqual(parsed["platform"], "hackerone")
        self.assertIn("example.com", parsed["allowed_domains"])
        self.assertIn("api.target.com", parsed["allowed_domains"])
        self.assertNotIn("target.com", parsed["allowed_domains"])  # Do not broaden scope
        self.assertIn("dev.example.com", parsed["excluded_domains"])
        self.assertFalse(parsed["confirmed_by_human"])
        self.assertFalse(parsed["policy_reviewed"])
        self.assertFalse(parsed["passive_allowed"])

    def test_fingerprint_changes_on_scope_update(self):
        p1 = {"platform": "custom", "allowed_domains": ["a.com"], "excluded_domains": []}
        p2 = {"platform": "custom", "allowed_domains": ["a.com", "b.com"], "excluded_domains": []}
        fp1 = PolicyParser.calculate_fingerprint(p1)
        fp2 = PolicyParser.calculate_fingerprint(p2)
        self.assertNotEqual(fp1, fp2)

if __name__ == '__main__':
    unittest.main()
