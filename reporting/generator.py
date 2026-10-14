"""
Reporting Engine: Generates reproducible bug bounty reports in Markdown and JSON.
Strictly evidence-based; no hallucinations, no unverified impact claims.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from validation.evidence.record import EvidenceRecord

SEVERITY_RATINGS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")

def _sanitize_headers(headers):
    """Keep only an allowlisted subset of non-credential headers."""
    allowed = {
        "accept",
        "content-type",
    }
    return {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).lower() in allowed
    }


def _safe_asset(url):
    """Remove credentials, query strings and fragments."""
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return "[REDACTED]"

        host = parts.hostname
        if not host:
            return "[REDACTED]"

        authority = host
        if ":" in host:
            authority = f"[{host}]"

        if parts.port is not None:
            authority += f":{parts.port}"

        return urlunsplit((
            parts.scheme,
            authority,
            parts.path or "/",
            "",
            ""
        ))
    except (ValueError, TypeError):
        return "[REDACTED]"


def _validate_free_text(*values):
    """Reject recognizable credentials in report free-text fields."""
    import re

    patterns = (
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    )

    for value in values:
        value = str(value or "")
        if any(re.search(pattern, value) for pattern in patterns):
            raise ValueError(
                "Potential credential detected in report text; "
                "redact before generating report"
            )


class ReportGenerator:
    @staticmethod
    def calculate_severity(category: str, confidence: str, conclusion: str) -> str:
        """Conservative default. Severity requires independent impact review."""
        return "INFORMATIONAL"

    @staticmethod
    def generate_report(
        title: str,
        program_name: str,
        evidence: EvidenceRecord,
        remediation_advice: Optional[str] = None
    ) -> Dict[str, Any]:
        _validate_free_text(
            title,
            program_name,
            evidence.category,
            evidence.limitations,
            remediation_advice,
        )

        severity = ReportGenerator.calculate_severity(evidence.category, evidence.confidence, evidence.conclusion)
        now_str = datetime.now(timezone.utc).isoformat()

        report_data = {
            "title": title,
            "program_name": program_name,
            "generated_at": now_str,
            "severity": severity,
            "category": evidence.category,
            "affected_asset": _safe_asset(evidence.target_url),
            "http_method": evidence.http_method,
            "conclusion": evidence.conclusion,
            "confidence": evidence.confidence,
            "evidence_classification": "researcher-assertion-unverified",
            "independently_confirmed": False,
            "summary": f"Researcher-provided observation for {evidence.category}. Conclusion is an unverified researcher assertion.",
            "prerequisites": "Authorization and program scope must be independently verified by the researcher before submission.",
            "steps_to_reproduce": [
                f"1. Target endpoint: {evidence.http_method} {_safe_asset(evidence.target_url)}",
                "2. Use an authorized researcher-controlled test account.",
                "3. Expected behavior: [REDACTED - researcher review required]",
                "4. Observed behavior: [REDACTED - researcher review required]"
            ],
            "sanitized_poc": {
                "request_method": evidence.http_method,
                "request_headers": _sanitize_headers(evidence.request_headers),
                "request_body": "[REDACTED]",
                "response_status": evidence.response_status,
                "response_body_snippet": "[REDACTED]"
            },
            "security_impact": "Not independently assessed; requires evidence and business-impact review.",
            "limitations": evidence.limitations,
            "suggested_remediation": remediation_advice or "Implement strict server-side authorization controls and input validation."
        }
        return report_data

    @staticmethod
    def to_markdown(report_data: Dict[str, Any]) -> str:
        steps_md = "\n".join(report_data["steps_to_reproduce"])
        return f"""# Bug Bounty Vulnerability Report: {report_data['title']}

- **Program:** `{report_data['program_name']}`
- **Affected Asset:** `{report_data['affected_asset']}`
- **Category:** `{report_data['category']}`
- **Severity:** `{report_data['severity']}`
- **Conclusion:** `{report_data['conclusion']}` (Confidence: `{report_data['confidence']}`)
- **Evidence Classification:** `{report_data['evidence_classification']}`
- **Independently Confirmed:** `{report_data['independently_confirmed']}`
- **Date:** `{report_data['generated_at']}`

---

## 1. Summary
{report_data['summary']}

## 2. Prerequisites
{report_data['prerequisites']}

## 3. Steps to Reproduce
{steps_md}

## 4. Sanitized Proof of Concept
```http
{report_data['http_method']} {report_data['affected_asset']} HTTP/1.1
{json.dumps(report_data['sanitized_poc']['request_headers'], indent=2)}

HTTP/1.1 {report_data['sanitized_poc']['response_status']}
{report_data['sanitized_poc']['response_body_snippet']}
```

## 5. Security Impact
{report_data['security_impact']}

## 6. Limitations & Scope Notes
{report_data['limitations']}

## 7. Suggested Remediation
{report_data['suggested_remediation']}

---
*Report generated automatically by CyberPartha BOT v3 with human researcher approval.*
"""

    @staticmethod
    def to_json(report_data: Dict[str, Any]) -> str:
        return json.dumps(report_data, indent=2, sort_keys=True)
