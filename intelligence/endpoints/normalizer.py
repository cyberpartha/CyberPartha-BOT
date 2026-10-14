"""
Endpoint Intelligence: URL normalization, parameter extraction, and sensitive data redaction.
"""
from __future__ import annotations
import re
from urllib.parse import urlsplit, parse_qsl, urlunsplit
from typing import Dict, List, Any, Optional

SENSITIVE_KEY_RE = re.compile(
    r'(?i)(token|secret|password|key|cookie|authorization|auth|session|jwt|credential|signature|apikey|bearer)'
)
NUMERIC_ID_RE = re.compile(r'^\d+$')
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

class EndpointNormalizer:
    @staticmethod
    def redact_parameters(query_params: List[tuple[str, str]]) -> Dict[str, str]:
        sanitized = {}
        for k, v in query_params:
            if SENSITIVE_KEY_RE.search(k):
                sanitized[k] = "[REDACTED_SENSITIVE_PARAM]"
            else:
                # Mask potential secret values in query string
                if len(v) > 20 or SENSITIVE_KEY_RE.search(v):
                    sanitized[k] = "[REDACTED_VALUE]"
                else:
                    sanitized[k] = v
        return sanitized

    @staticmethod
    def normalize(url: str, method: str = "GET", auth_type: Optional[str] = None) -> Dict[str, Any]:
        parsed = urlsplit(url)
        path_parts = [p for p in parsed.path.split('/') if p]

        normalized_path_parts = []
        path_parameters = []
        for part in path_parts:
            if NUMERIC_ID_RE.match(part):
                normalized_path_parts.append('{id}')
                path_parameters.append(part)
            elif UUID_RE.match(part):
                normalized_path_parts.append('{uuid}')
                path_parameters.append(part)
            else:
                normalized_path_parts.append(part)

        normalized_path = '/' + '/'.join(normalized_path_parts) if normalized_path_parts else '/'
        q_params = parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_params = EndpointNormalizer.redact_parameters(q_params)

        clean_url = urlunsplit((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            normalized_path,
            '',  # query stripped in normalized canonical URL
            ''
        ))

        return {
            "canonical_url": clean_url,
            "host": parsed.netloc.lower().split(':')[0],
            "method": method.upper(),
            "normalized_path": normalized_path,
            "raw_path": parsed.path,
            "path_parameters": path_parameters,
            "query_parameters": sorted(list(sanitized_params.keys())),
            "auth_type": auth_type or "unknown"
        }
