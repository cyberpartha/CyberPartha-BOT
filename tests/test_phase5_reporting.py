"""Tests for Phase 5 Report Generator."""
import unittest, json
from reporting.generator import ReportGenerator
from validation.evidence.record import EvidenceRecord

class TestReportGenerator(unittest.TestCase):
    def test_markdown_and_json_report_generation(self):
        evidence = EvidenceRecord(
            target_url="https://api.example.com/v1/orders/102",
            http_method="GET",
            category="access-control",
            test_account="user_a",
            request_headers={"Authorization": "[REDACTED]"},
            request_body=None,
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body_snippet='{"order_id": 102, "owner": "user_b"}',
            expected_secure_behavior="Cross-account access denied.",
            actual_observed_behavior="User A read order 102 belonging to User B.",
            conclusion="VALIDATED",
            confidence="HIGH",
            limitations="Tested on owned test accounts."
        )

        report = ReportGenerator.generate_report(
            title="BOLA in Order Retrieval",
            program_name="ExampleCorp",
            evidence=evidence
        )
        self.assertEqual(report["severity"], "INFORMATIONAL")
        self.assertEqual(report["conclusion"], "VALIDATED")

        md = ReportGenerator.to_markdown(report)
        self.assertIn("# Bug Bounty Vulnerability Report: BOLA in Order Retrieval", md)
        self.assertIn("VALIDATED", md)

        js = ReportGenerator.to_json(report)
        parsed = json.loads(js)
        self.assertEqual(parsed["program_name"], "ExampleCorp")


    def test_validated_status_does_not_auto_escalate_severity(self):
        for category in (
            "sqli",
            "remote-code-execution",
            "access-control",
            "ssrf",
            "xss",
        ):
            with self.subTest(category=category):
                severity = ReportGenerator.calculate_severity(
                    category, "HIGH", "VALIDATED"
                )
                self.assertEqual(severity, "INFORMATIONAL")


if __name__ == '__main__':
    unittest.main()
