"""
Vulnerability Reasoning Engine: Generates explainable hypotheses across OWASP categories.
Distinguishes OBSERVED, HYPOTHESIS, INCONCLUSIVE, VALIDATED, NOT REPRODUCIBLE.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional

HYPOTHESIS_STATES = ("OBSERVED", "HYPOTHESIS", "INCONCLUSIVE", "VALIDATED", "NOT REPRODUCIBLE")

@dataclass
class Hypothesis:
    category: str
    target: str
    state: str
    supporting_evidence: str
    reasoning: str
    missing_evidence: str
    proposed_safe_validation: str
    expected_request_budget: int
    estimated_potential_impact: str
    confidence_level: str
    policy_restrictions: str
    human_approval_required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class VulnerabilityReasoningEngine:
    RULES = (
        ("access-control", {"id", "user_id", "account_id", "owner_id", "document_id", "order_id", "resource_id", "{id}", "{uuid}"},
         "Review object-level authorization (IDOR/BOLA) across two researcher-owned test resources.", 3, "HIGH"),
        ("authentication", {"login", "logout", "refresh", "mfa", "reset", "session", "oauth", "token", "password"},
         "Review authentication lifecycle and session invalidation using researcher-owned accounts.", 2, "HIGH"),
        ("injection", {"search", "query", "filter", "sort", "template", "q", "cmd", "exec"},
         "Review input validation and sanitization using benign boundary test inputs.", 3, "MEDIUM"),
        ("ssrf", {"url", "uri", "dest", "destination", "redirect", "webhook", "callback", "feed", "target"},
         "Review external URL fetching and protocol restrictions using controlled test endpoints.", 2, "HIGH"),
        ("path-traversal", {"file", "filename", "path", "doc", "download", "read", "folder"},
         "Review server-side file retrieval using benign path-traversal markers.", 2, "MEDIUM"),
        ("security-misconfiguration", {"admin", "internal", "config", "debug", "actuator", "swagger", "api-docs", "console"},
         "Review exposed administrative, configuration, or documentation endpoints.", 1, "LOW")
    )

    @classmethod
    def generate_hypotheses(cls, endpoint_data: Dict[str, Any], program_policy: Dict[str, Any]) -> List[Hypothesis]:
        hypotheses = []
        target = endpoint_data.get("canonical_url", "")
        method = endpoint_data.get("method", "GET")
        params = set(endpoint_data.get("query_parameters", []))
        path_parts = set(endpoint_data.get("normalized_path", "").split("/"))
        all_features = params.union(path_parts)

        prohibited = set(program_policy.get("prohibited_categories", []))

        for category, triggers, plan, budget, impact in cls.RULES:
            matched = triggers.intersection(all_features)
            if matched:
                is_prohibited = any(category.lower() in p.lower() for p in prohibited)
                policy_note = f"Explicitly prohibited by program policy ({category})" if is_prohibited else "Permitted under program conditions; single-test human approval required."

                h = Hypothesis(
                    category=category,
                    target=f"{method} {target}",
                    state="HYPOTHESIS",
                    supporting_evidence=f"Endpoint exhibits parameters/path elements matching {category}: {sorted(list(matched))}",
                    reasoning=f"Presence of resource/action indicators ({sorted(list(matched))}) suggests potential {category} surface requiring authorization testing.",
                    missing_evidence="No active differential response testing performed yet. Needs dual-account differential observation.",
                    proposed_safe_validation=plan,
                    expected_request_budget=budget,
                    estimated_potential_impact=impact,
                    confidence_level="MEDIUM" if len(matched) > 1 else "LOW",
                    policy_restrictions=policy_note,
                    human_approval_required=True
                )
                hypotheses.append(h)
        return hypotheses
