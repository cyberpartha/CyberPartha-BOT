"""
ApprovalToken: cryptographically bound, single-use approval for ONE network test.

Bound to: program, url, method, payload_hash, test_account, policy_version,
          issued_at, expires_at, max_requests.
Single-use: consumed tokens are archived and cannot be reused.
"""
from __future__ import annotations
import hashlib, hmac, json, secrets, time
from dataclasses import dataclass, asdict
from typing import Optional


class ApprovalError(PermissionError):
    """Raised when an action is not covered by a valid approval token."""


@dataclass(frozen=True)
class ApprovalToken:
    """Immutable approval record for exactly one test operation."""
    token_id:       str
    program_name:   str
    target_url:     str
    http_method:    str
    payload_hash:   str   # SHA-256[:16] of sorted json(params), or 'none'
    test_account:   str
    max_requests:   int
    policy_version: str
    issued_at:      float
    expires_at:     float

    @classmethod
    def create(
        cls,
        program_name: str,
        target_url: str,
        http_method: str,
        payload: Optional[dict] = None,
        test_account: str = 'researcher-owned',
        max_requests: int = 1,
        policy_version: str = 'unset',
        ttl_seconds: int = 300,
    ) -> 'ApprovalToken':
        now = time.time()
        ph = hashlib.sha256(
            json.dumps(payload or {}, sort_keys=True).encode()
        ).hexdigest()[:16]
        return cls(
            token_id=secrets.token_hex(16),
            program_name=program_name,
            target_url=target_url,
            http_method=http_method.upper(),
            payload_hash=ph,
            test_account=test_account,
            max_requests=max_requests,
            policy_version=policy_version,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )

    def validate(
        self,
        program_name: str,
        target_url: str,
        http_method: str,
        payload: Optional[dict] = None,
    ) -> None:
        """Assert this token covers the proposed operation."""
        if time.time() > self.expires_at:
            raise ApprovalError('Approval token has expired')
        if self.program_name != program_name:
            raise ApprovalError('Token program mismatch')
        if self.target_url != target_url:
            raise ApprovalError('Token URL mismatch')
        if self.http_method != http_method.upper():
            raise ApprovalError('Token HTTP method mismatch')
        ph = hashlib.sha256(
            json.dumps(payload or {}, sort_keys=True).encode()
        ).hexdigest()[:16]
        if not hmac.compare_digest(self.payload_hash, ph):
            raise ApprovalError('Token payload fingerprint mismatch')

    def to_dict(self) -> dict:
        return asdict(self)


class ApprovalStore:
    """
    In-memory registry of issued and consumed approval tokens.
    Tokens are single-use: consumed tokens cannot be reused.
    """

    def __init__(self) -> None:
        self._pending:  dict[str, ApprovalToken] = {}
        self._consumed: set[str] = set()

    def register(self, token: ApprovalToken) -> None:
        self._pending[token.token_id] = token

    def consume(
        self,
        token_id: str,
        program_name: str,
        target_url: str,
        http_method: str,
        payload: Optional[dict] = None,
    ) -> ApprovalToken:
        """Validate and consume. Raises ApprovalError on any failure."""
        if token_id in self._consumed:
            raise ApprovalError('Approval token already consumed (single-use)')
        token = self._pending.get(token_id)
        if token is None:
            raise ApprovalError('Unknown approval token')
        token.validate(program_name, target_url, http_method, payload)
        del self._pending[token_id]
        self._consumed.add(token_id)
        return token

    def has_valid_token(self, program_name: str, target_url: str, http_method: str) -> bool:
        now = time.time()
        return any(
            t.program_name == program_name
            and t.target_url == target_url
            and t.http_method == http_method.upper()
            and t.expires_at > now
            for t in self._pending.values()
        )
