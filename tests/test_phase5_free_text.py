import unittest

from reporting.generator import ReportGenerator
from validation.evidence.record import EvidenceRecord


class TestFreeTextPrivacy(unittest.TestCase):

    def test_sensitive_free_text_rejected(self):
        evidence = EvidenceRecord(
            target_url="https://example.com/test",
            http_method="GET",
            category="access-control",
            test_account="synthetic",
            request_headers={},
            request_body=None,
            response_status=200,
            response_headers={},
            response_body_snippet="synthetic",
            expected_secure_behavior="Denied",
            actual_observed_behavior="Observed",
            conclusion="INCONCLUSIVE",
            confidence="LOW",
            limitations="Bearer TEST_SECRET_TOKEN_1234567890",
        )

        with self.assertRaises(ValueError):
            ReportGenerator.generate_report(
                title="Synthetic Test",
                program_name="OfflineTest",
                evidence=evidence,
            )


if __name__ == "__main__":
    unittest.main()
