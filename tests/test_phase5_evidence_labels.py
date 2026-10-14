import unittest

from reporting.generator import ReportGenerator
from validation.evidence.record import EvidenceRecord


class TestEvidenceLabels(unittest.TestCase):

    def test_markdown_displays_unverified_evidence(self):
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
            actual_observed_behavior="Unexpected response",
            conclusion="VALIDATED",
            confidence="HIGH",
            limitations="Offline synthetic data"
        )

        report = ReportGenerator.generate_report(
            "Synthetic Test", "OfflineTest", evidence
        )

        self.assertEqual(
            report["evidence_classification"],
            "researcher-assertion-unverified"
        )
        self.assertIs(report["independently_confirmed"], False)

        markdown = ReportGenerator.to_markdown(report)

        self.assertIn(
            "researcher-assertion-unverified",
            markdown
        )
        self.assertIn(
            "Independently Confirmed:** `False`",
            markdown
        )


if __name__ == "__main__":
    unittest.main()
