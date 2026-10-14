"""
Backward-compatibility shim for core.scope_guard.

v3 uses core.scope.ScopeGuard for per-program enforcement.
This module provides the old is_allowed() / ALLOWED_URL interface
so existing test_bot.py imports continue to pass unchanged.
"""
from urllib.parse import urlsplit

# Legacy single-URL allowlist (Canva, kept for backward compat only)
ALLOWED_URL = 'https://api.canva.com/rest/v1/users/me'


def is_allowed(url: str) -> bool:
    """Legacy single-URL check (v1/v2 compatibility only)."""
    if not isinstance(url, str) or url != ALLOWED_URL:
        return False
    try:
        p = urlsplit(url)
        return (
            p.scheme == 'https'
            and p.hostname == 'api.canva.com'
            and p.path == '/rest/v1/users/me'
            and p.port is None
            and p.username is None
            and p.password is None
            and not p.query
            and not p.fragment
        )
    except (ValueError, TypeError):
        return False
