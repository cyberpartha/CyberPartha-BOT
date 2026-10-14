"""
Policy intelligence and platform policy parsers (HackerOne, Bugcrowd, Intigriti, Custom).
Extracts policy restrictions, scope, rate limits, AI rules, and enforces human confirmation.
"""
from __future__ import annotations
import hashlib, json, re
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "custom")

DEFAULT_PROHIBITED_CATEGORIES = [
    "Denial of Service (DoS/DDoS)",
    "Spam / Social Engineering / Phishing",
    "Physical Security Attacks",
    "Automated Vulnerability Scanner Flooding",
    "Third-party Dependency Injection",
    "Clickjacking on pages with no sensitive actions"
]

_DOMAIN_TOKEN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$', re.IGNORECASE)

def _clean_domain(token: str) -> Optional[str]:
    t = token.strip().lower()
    t = re.sub(r'^(?:https?://)?(?:\*\.)?', '', t)
    t = t.rstrip("/.,:;!?\"'")
    if _DOMAIN_TOKEN.match(t):
        return t
    return None

class PolicyParser:
    @staticmethod
    def calculate_fingerprint(policy_data: Dict[str, Any]) -> str:
        serialized = json.dumps({
            "platform": policy_data.get("platform", "custom"),
            "policy_url": policy_data.get("policy_url", ""),
            "allowed_domains": sorted(policy_data.get("allowed_domains", [])),
            "excluded_domains": sorted(policy_data.get("excluded_domains", [])),
            "ai_allowed": policy_data.get("ai_allowed", False),
            "passive_allowed": policy_data.get("passive_allowed", False),
            "active_allowed": policy_data.get("active_allowed", False),
            "max_req_per_minute": policy_data.get("max_req_per_minute", 30),
            "prohibited_categories": sorted(policy_data.get("prohibited_categories", []))
        }, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def parse_text(text: str, platform: str = "custom", policy_url: str = "") -> Dict[str, Any]:
        platform = platform.lower()
        if platform not in PLATFORMS:
            raise ValueError(f"Unsupported platform: {platform}. Choose from {PLATFORMS}")

        allowed = []
        excluded = []
        prohibited = list(DEFAULT_PROHIBITED_CATEGORIES)
        ai_allowed = False
        passive_allowed = False
        active_allowed = False
        rate_limit = 30

        # Parse explicit scope sections only; prose and policy URLs are not scope.
        section = None
        for line in text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            lower_line = line_str.lower().rstrip(':')
            if lower_line in ("out of scope", "out-of-scope", "excluded", "excluded assets"):
                section = "excluded"
                continue
            if lower_line in ("in scope", "in-scope", "targets in scope", "eligible targets"):
                section = "allowed"
                continue
            if lower_line in ("prohibited", "rules", "restrictions", "notes"):
                section = None
                continue
            if section is None:
                continue
            # Only standalone hostname or wildcard hostname entries count.
            candidate = line_str.lstrip('-* ').strip()
            if line_str.startswith('*.'):
                candidate = line_str[2:]
            dom = _clean_domain(candidate)
            if dom:
                dest = excluded if section == "excluded" else allowed
                if dom not in dest:
                    dest.append(dom)

        # Remove any items from allowed if in excluded
        allowed = [d for d in allowed if d not in excluded]

        if "no automated tools" in text.lower() or "no automation" in text.lower() or "automated testing is prohibited" in text.lower():
            passive_allowed = False
            active_allowed = False
        if "no ai" in text.lower() or "llm prohibited" in text.lower() or "ai-generated reports not allowed" in text.lower():
            ai_allowed = False

        res = {
            "platform": platform,
            "policy_url": policy_url,
            "retrieval_date": datetime.now(timezone.utc).isoformat(),
            "allowed_domains": allowed,
            "excluded_domains": excluded,
            "prohibited_categories": prohibited,
            "ai_allowed": ai_allowed,
            "passive_allowed": passive_allowed,
            "active_allowed": active_allowed,
            "max_req_per_minute": rate_limit,
            "confirmed_by_human": False,
            "policy_reviewed": False,
            "note": "Extracted via policy parser. Requires human operator review and explicit confirmation before use."
        }
        res["fingerprint"] = PolicyParser.calculate_fingerprint(res)
        return res
