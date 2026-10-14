"""Offline, evidence-based research suggestions. No network activity."""
import re
from urllib.parse import urlsplit

CHECKS = [
 ("access-control", ("object_id","user_id","account_id","owner_id","document_id","resource_id"), "Owned-object authorization boundary review", 2),
 ("authentication", ("session","logout","refresh_token","reset_password","mfa"), "Owned-account session and authentication lifecycle review", 2),
 ("injection", ("search","query","filter","sort","template"), "Non-destructive input handling review", 1),
 ("ssrf", ("webhook","callback_url","image_url","fetch_url","import_url"), "URL-input trust boundary review; no internal network probes", 1),
 ("misconfiguration", ("cors","origin","headers","cdn"), "Response security configuration review", 1),
 ("integrity", ("script_src","sri","dependency","package"), "Client-side integrity and dependency review", 0),
 ("logging", ("audit_log","security_event","alert"), "Owner-provided audit-event verification", 0),
 ("business-logic", ("checkout","coupon","workflow","transfer"), "Owned-workflow state and authorization review", 2),
]
def classify(observation):
    """Only interpret operator-provided, sanitized labels. No requests."""
    value = observation.lower()
    results=[]
    for category,markers,title,budget in CHECKS:
        if any(re.search(r'(?<![a-z0-9])'+re.escape(marker)+r'(?![a-z0-9])',value) for marker in markers):
            results.append({"category":category,"title":title,"max_requests":budget,
                            "status":"hypothesis","evidence": "operator-supplied observation"})
    return results
def redact(text):
    """Defense in depth for report snippets; avoid storing raw input at all."""
    text = re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+',r'\1[REDACTED]',text)
    text = re.sub(r'(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)\s*[:=]\s*[^\s,;]+',r'\1=[REDACTED]',text)
    return text[:500]
