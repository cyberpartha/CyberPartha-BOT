"""
ProfileManager: load, validate, and manage bug bounty program profiles.

A profile is a JSON file in programs/ that documents:
  - allowed_domains / excluded_domains
  - policy_reviewed, ai_allowed, passive_allowed (all must be True to enable ops)
  - Policy URL and version
  - Per-source configuration (max_results, timeouts)
  - lab_mode flag for isolated test environments
"""
from __future__ import annotations
import json, os, re, tempfile
from pathlib import Path
from typing import Any

ROOT     = Path(__file__).resolve().parent.parent.parent
PROGRAMS = ROOT / 'programs'
REPORTS  = ROOT / 'reports'
STATE    = ROOT / 'state'

_NAME_RE   = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$')
_DOMAIN_RE = re.compile(r'^[a-z0-9*][a-z0-9.*-]{0,251}$')


class PolicyError(ValueError):
    """Raised on invalid or incomplete program profiles."""


def _ensure_dirs() -> None:
    for d in (PROGRAMS, REPORTS, STATE):
        d.mkdir(parents=True, exist_ok=True)


def valid_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise PolicyError(
            f'Invalid program name {name!r}; use letters, digits, underscores, hyphens'
        )
    return name


def valid_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise PolicyError('Domain must be a string')
    d = domain.strip().lower()
    if '://' in d:
        raise PolicyError(f'Domain must not include scheme: {d!r}')
    if not d or not _DOMAIN_RE.match(d):
        raise PolicyError(f'Invalid domain: {d!r}')
    return d


class ProfileManager:
    """Manages program profile CRUD and policy gating."""

    def __init__(self) -> None:
        _ensure_dirs()

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def profile_path(self, name: str) -> Path:
        return PROGRAMS / (valid_name(name) + '.json')

    def exists(self, name: str) -> bool:
        return self.profile_path(name).exists()

    def init(self, name: str, domain: str) -> Path:
        """Create a new disabled program profile."""
        name = valid_name(name)
        domain = valid_domain(domain)
        path = self.profile_path(name)
        if path.exists():
            raise PolicyError(f'Profile {name!r} already exists; will not overwrite')
        data = {
            'program_name':           name,
            'policy_url':             '',
            'policy_version':         '',
            'policy_reviewed':        False,
            'ai_allowed':             False,
            'passive_allowed':        False,
            'lab_mode':               False,
            'allowed_domains':        [domain],
            'excluded_domains':       [],
            'max_ct_results':         100,
            'passive_timeout_seconds': 10,
            'rate_limit_per_minute':  10,
            'notes': (
                'Review the real program policy before enabling any operation. '
                'Set policy_reviewed, ai_allowed, passive_allowed manually after '
                'human review of the actual bug bounty policy document.'
            ),
        }
        self._save(path, data)
        return path

    def load(self, name: str) -> dict:
        """Load and validate a profile. Raises PolicyError on invalid data."""
        path = self.profile_path(name)
        if not path.exists():
            raise PolicyError(f'Program profile {name!r} not found')
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError) as e:
            raise PolicyError(f'Cannot read profile: {e}') from e

        if data.get('program_name') != valid_name(name):
            raise PolicyError('Profile program_name mismatch')
        for flag in ('policy_reviewed', 'ai_allowed', 'passive_allowed'):
            if not isinstance(data.get(flag), bool):
                raise PolicyError(f'Policy flag {flag!r} must be boolean')
        domains = data.get('allowed_domains')
        if not isinstance(domains, list) or not domains:
            raise PolicyError('allowed_domains must be a non-empty list')
        data['allowed_domains']  = [valid_domain(d) for d in domains]
        data['excluded_domains'] = [valid_domain(d) for d in data.get('excluded_domains', [])]
        return data

    def _save(self, path: Path, data: dict) -> None:
        """Atomic write with restrictive permissions."""
        _ensure_dirs()
        fd, tmp = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                f.write('\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    # ── policy gates ─────────────────────────────────────────────────────────

    def policy_ok(self, data: dict) -> bool:
        """All three permission flags must be True for passive/active operations."""
        return all(data.get(f) is True
                   for f in ('policy_reviewed', 'ai_allowed', 'passive_allowed'))

    def require_policy_reviewed(self, data: dict) -> None:
        """Raise PolicyError if policy has not been human-reviewed."""
        if not data.get('policy_reviewed'):
            raise PolicyError(
                'Program policy has not been reviewed. '
                'Review the actual bug bounty policy and set policy_reviewed=true manually.'
            )

    def require_passive_allowed(self, data: dict) -> None:
        self.require_policy_reviewed(data)
        if not data.get('passive_allowed'):
            raise PolicyError(
                'Passive reconnaissance is not enabled for this program. '
                'Verify the policy permits automated reconnaissance then set passive_allowed=true.'
            )

    def require_ai_allowed(self, data: dict) -> None:
        self.require_policy_reviewed(data)
        if not data.get('ai_allowed'):
            raise PolicyError(
                'AI-assisted analysis is not enabled for this program. '
                'Verify the policy permits LLM/AI assistance then set ai_allowed=true.'
            )

    # ── scope helpers ─────────────────────────────────────────────────────────

    def in_scope(self, host: str, data: dict) -> bool:
        """Return True iff host is in the program scope."""
        try:
            h = valid_domain(host)
        except PolicyError:
            return False
        allowed  = any(h == d or h.endswith('.' + d) for d in data['allowed_domains'])
        excluded = any(h == d or h.endswith('.' + d) for d in data['excluded_domains'])
        return allowed and not excluded

    def db_path(self, name: str) -> Path:
        return STATE / (valid_name(name) + '.sqlite')
