"""Tests for Phase 3 Endpoint Intelligence and Normalization."""
import unittest
from intelligence.endpoints.normalizer import EndpointNormalizer

class TestEndpointIntelligence(unittest.TestCase):
    def test_normalize_numeric_id(self):
        url = "https://api.example.com/v1/users/42/profile"
        norm = EndpointNormalizer.normalize(url, method="GET")
        self.assertEqual(norm["normalized_path"], "/v1/users/{id}/profile")
        self.assertIn("42", norm["path_parameters"])
        self.assertEqual(norm["canonical_url"], "https://api.example.com/v1/users/{id}/profile")

    def test_normalize_uuid(self):
        url = "https://api.example.com/orders/550e8400-e29b-41d4-a716-446655440000"
        norm = EndpointNormalizer.normalize(url, method="GET")
        self.assertEqual(norm["normalized_path"], "/orders/{uuid}")

    def test_sensitive_param_redacted(self):
        url = "https://api.example.com/search?q=test&api_key=secret12345678901234567890"
        norm = EndpointNormalizer.normalize(url)
        self.assertIn("api_key", norm["query_parameters"])
        self.assertIn("q", norm["query_parameters"])

        q_params = [("api_key", "secret12345678901234567890"), ("user", "pilu")]
        sanitized = EndpointNormalizer.redact_parameters(q_params)
        self.assertEqual(sanitized["api_key"], "[REDACTED_SENSITIVE_PARAM]")
        self.assertEqual(sanitized["user"], "pilu")

if __name__ == '__main__':
    unittest.main()
