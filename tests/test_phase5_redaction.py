"""Regression tests for report credential redaction."""
import unittest

from reporting.generator import ReportGenerator
from validation.evidence.record import EvidenceRecord


class TestPhase5Redaction(unittest.TestCase):

    def test_credentials_not_exported(self):
        secrets = [
            "SECRET_BEARER_12345",
            "SECRET_COOKIE_67890",
            "SECRET_API_KEY_ABCDE",
            "SECRET_BODY_PASSWORD",
            "SECRET_RESPONSE_TOKEN",
        ]

        evidence = EvidenceRecord(
            target_url="https://example.com/test",
            http_method="POST",
            category="access-control",
            test_account="owned_test_account",
            request_headers={
                "Authorization": "Bearer SECRET_BEARER_12345",
                "Cookie": "session=SECRET_COOKIE_67890",
                "X-API-Key": "SECRET_API_KEY_ABCDE",
            },
            request_body='{"password":"SECRET_BODY_PASSWORD"}',
            response_status=200,
            response_headers={},
            response_body_snippet='{"token":"SECRET_RESPONSE_TOKEN"}',
            expected_secure_behavior="Access denied.",
            actual_observed_behavior="Test observation.",
            conclusion="INCONCLUSIVE",
            confidence="LOW",
            limitations="Synthetic offline test only.",
        )

        report = ReportGenerator.generate_report(
            title="Synthetic Redaction Test",
            program_name="OfflineTest",
            evidence=evidence,
        )

        outputs = [
            ReportGenerator.to_json(report),
            ReportGenerator.to_markdown(report),
        ]

        for output in outputs:
            for secret in secrets:
                with self.subTest(secret=secret):
                    self.assertNotIn(secret, output)


if __name__ == "__main__":
    unittest.main()
