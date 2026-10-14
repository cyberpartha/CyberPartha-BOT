"""
SafetyGuard: centralized enforcement layer for ALL outbound requests.

Every active network request in the system MUST pass through SafetyGuard.
It enforces:
  1. Emergency STOP file check
  2. Scope validation (ScopeGuard)
  3. Token-based approval consumption (ApprovalStore)
  4. Request budget enforcement (RequestBudget)
  5. Rate limiting (RateLimiter)
  6. Audit logging of every decision
"""
from __future__ import annotations
import threading, time
from pathlib import Path
from typing import Optional

from core.stop_switch import check_stop, EmergencyStop
from core.budget import RequestBudget, BudgetExceeded
from core.scope.guard import ScopeGuard, ScopeViolation
from core.approval.token import ApprovalStore, ApprovalError
from core.audit.logger import AuditLogger


class RateLimiter:
    """Token-bucket rate limiter: max_requests per window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block if rate limit would be exceeded."""
        with self._lock:
            now = time.time()
            cutoff = now - self._window
            self._timestamps = [t for t in self._timestamps if t > cutoff]
            if len(self._timestamps) >= self._max:
                wait = self._timestamps[0] + self._window - now + 0.05
                if wait > 0:
                    time.sleep(wait)
                self._timestamps = [t for t in self._timestamps if t > time.time() - self._window]
            self._timestamps.append(time.time())

    def within_limit(self) -> bool:
        """Return True if a request can be made now without blocking."""
        with self._lock:
            now = time.time()
            recent = [t for t in self._timestamps if t > now - self._window]
            return len(recent) < self._max


class SafetyGuard:
    """
    The single mandatory enforcement gateway for all active requests.

    Parameters
    ----------
    scope        : ScopeGuard instance for this program.
    approvals    : ApprovalStore shared across this session.
    budget       : RequestBudget for this test (or session-wide).
    audit        : AuditLogger instance.
    rate_limiter : Optional RateLimiter.
    dry_run      : If True, enforcement checks run but no request is sent.
    """

    def __init__(
        self,
        scope: ScopeGuard,
        approvals: ApprovalStore,
        budget: RequestBudget,
        audit: AuditLogger,
        rate_limiter: Optional[RateLimiter] = None,
        dry_run: bool = False,
    ) -> None:
        self._scope = scope
        self._approvals = approvals
        self._budget = budget
        self._audit = audit
        self._rate = rate_limiter or RateLimiter(max_requests=10, window_seconds=60)
        self._dry_run = dry_run
        self._stopped = False

    def authorize_and_consume(
        self,
        token_id: str,
        program_name: str,
        target_url: str,
        http_method: str,
        payload: Optional[dict] = None,
    ) -> None:
        """
        Full enforcement pipeline. Call this before every active request.

        1. Checks for STOP file.
        2. Validates scope.
        3. Consumes approval token.
        4. Decrements budget.
        5. Applies rate limit.
        Raises the appropriate exception on any failure (never silently passes).
        """
        # 1. Emergency stop
        try:
            check_stop()
        except EmergencyStop:
            self._stopped = True
            self._audit.log_stop()
            raise

        # 2. Scope check
        try:
            self._scope.check_url(target_url)
        except ScopeViolation as e:
            self._audit.log_scope_check(target_url, False, str(e))
            self._audit.log_block(str(e), target_url)
            raise

        self._audit.log_scope_check(target_url, True)

        # 3. Token approval
        try:
            token = self._approvals.consume(
                token_id, program_name, target_url, http_method, payload
            )
        except ApprovalError as e:
            self._audit.log_block(f'Approval: {e}', target_url)
            raise

        self._audit.log_approval_consumed(token.token_id, program_name, target_url)

        # 4. Budget
        try:
            self._budget.consume()
        except BudgetExceeded as e:
            self._audit.log_budget_exhausted(program_name, target_url)
            raise

        # 5. Rate limit
        self._rate.acquire()

        if self._dry_run:
            self._audit.log_request(http_method, target_url, None, 0.0)
            raise RuntimeError('DRY-RUN: request would have been sent but was not')

    @property
    def is_stopped(self) -> bool:
        return self._stopped

    @property
    def dry_run(self) -> bool:
        return self._dry_run
