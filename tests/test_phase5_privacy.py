import unittest

from reporting.generator import ReportGenerator
from validation.evidence.record import EvidenceRecord


class TestPhase5Privacy(unittest.TestCase):

    def test_sensitive_fields_not_exported(self):
        secrets = (
            "SECRET_URL_TOKEN_123",
            "SECRET_ACCOUNT_456",
            "SECRET_OBSERVATION_789",
        )

        evidence = EvidenceRecord(
            target_url="https://example.com/test?token=SECRET_URL_TOKEN_123",
            http_method="GET",
            category="access-control",
            test_account="SECRET_ACCOUNT_456",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body_snippet="synthetic",
            expected_secure_behavior="Access denied",
            actual_observed_behavior="Observed SECRET_OBSERVATION_789",
            conclusion="INCONCLUSIVE",
            confidence="LOW",
            limitations="Synthetic offline test",
        )

        report = ReportGenerator.generate_report(
            "Synthetic Privacy Test", "OfflineTest", evidence
        )

        for output in (
            ReportGenerator.to_json(report),
            ReportGenerator.to_markdown(report),
        ):
            for secret in secrets:
                with self.subTest(secret=secret):
                    self.assertNotIn(secret, output)

        self.assertEqual(
            report["affected_asset"],
            "https://example.com/test"
        )


if __name__ == "__main__":
    unittest.main()
