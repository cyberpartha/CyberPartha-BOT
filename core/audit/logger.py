"""
AuditLogger: append-only JSONL audit trail.

Design:
  - Every decision (allow, deny, approve, block, error) is logged.
  - Sensitive data (tokens, passwords, cookies) is redacted before writing.
  - Each entry includes: timestamp, event_type, program, details.
  - File is opened in append mode; never truncated.
  - Permissions set to 0o600 (owner read/write only).
"""
from __future__ import annotations
import json, os, re, time
from pathlib import Path
from typing import Any, Optional

_REDACT_PATTERNS = [
    (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|'
                r'client[_-]?secret|password|cookie|session|jwt)'
                r'\s*[:=]\s*[^\s,;"\]}{]+'),
                r'\1=[REDACTED]'),
    (re.compile(r'(?i)authorization:\s*\S+'), 'Authorization:[REDACTED]'),
]


def _redact(text: str) -> str:
    """Redact known credential patterns from a string."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text[:2000]


def _safe_value(v: Any) -> Any:
    """Recursively redact strings in a value for safe JSON serialization."""
    if isinstance(v, str):
        return _redact(v)
    if isinstance(v, dict):
        return {k: _safe_value(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_safe_value(item) for item in v]
    return v


class AuditLogger:
    """
    Append-only audit log for CyberPartha BOT decisions.

    Parameters
    ----------
    log_path : Path to the JSONL log file.
    program  : Program name for this session (included in every entry).
    """

    def __init__(self, log_path: Path, program: str = 'global') -> None:
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._program = program
        # Ensure file exists with restrictive permissions
        if not self._path.exists():
            self._path.touch()
            os.chmod(self._path, 0o600)

    def _write(self, event_type: str, details: dict) -> None:
        entry = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'event_type': event_type,
            'program': self._program,
            'details': _safe_value(details),
        }
        with self._path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')

    def log_scope_check(self, url: str, allowed: bool, reason: str = '') -> None:
        self._write('scope_check', {'url': url[:200], 'allowed': allowed, 'reason': reason})

    def log_approval_request(self, program: str, url: str, method: str, approved: bool) -> None:
        self._write('approval_request', {
            'program': program, 'url': url[:200],
            'method': method, 'approved': approved,
        })

    def log_approval_consumed(self, token_id: str, program: str, url: str) -> None:
        self._write('approval_consumed', {
            'token_id': token_id[:8] + '...', 'program': program, 'url': url[:200],
        })

    def log_request(self, method: str, url: str, status: Optional[int], elapsed_ms: float) -> None:
        self._write('http_request', {
            'method': method, 'url': url[:200],
            'status': status, 'elapsed_ms': round(elapsed_ms, 1),
        })

    def log_block(self, reason: str, url: str = '') -> None:
        self._write('blocked', {'reason': reason, 'url': url[:200]})

    def log_stop(self, source: str = 'STOP_file') -> None:
        self._write('emergency_stop', {'source': source})

    def log_budget_exhausted(self, program: str, url: str) -> None:
        self._write('budget_exhausted', {'program': program, 'url': url[:200]})

    def log_error(self, error_type: str, message: str) -> None:
        self._write('error', {'error_type': error_type, 'message': _redact(message)[:500]})

    def log_passive_recon(self, source: str, domain: str, found: int) -> None:
        self._write('passive_recon', {'source': source, 'domain': domain, 'found': found})

    def log_hypothesis(self, category: str, endpoint: str, score: int) -> None:
        self._write('hypothesis_generated', {
            'category': category, 'endpoint': endpoint[:200], 'priority_score': score,
        })
