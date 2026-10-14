import unittest
from engine.intelligence import classify, redact
class IntelligenceTests(unittest.TestCase):
    def test_evidence_match(self):
        found=classify("GET /api/orders?object_id=123")
        self.assertEqual([x["category"] for x in found],["access-control"])
    def test_no_evidence(self):
        self.assertEqual(classify("unrelated home page"),[])
    def test_no_secret_in_redacted(self):
        self.assertNotIn("abc123",redact("Authorization: Bearer abc123"))
        self.assertNotIn("secretvalue",redact("api_key=secretvalue"))
if __name__=="__main__": unittest.main()
