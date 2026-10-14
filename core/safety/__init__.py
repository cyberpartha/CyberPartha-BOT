"""core.safety — Centralized HTTP safety guard with rate limiting."""
from .guard import SafetyGuard, RateLimiter
from core.budget import RequestBudget
from core.scope_guard import is_allowed
from core.stop_switch import check_stop
import sys

def request_approval(url: str) -> bool:
    try:
        from core.approval import request_approval as _ra
        return _ra(url)
    except Exception:
        return False

class SafetyController:
    def __init__(self):
        self.budget = RequestBudget(1)
        self.approved_url = None

    def authorize(self, url: str) -> bool:
        check_stop()
        if not is_allowed(url):
            return False
        mod = sys.modules.get('core.safety')
        fn = getattr(mod, 'request_approval', request_approval) if mod else request_approval
        if fn(url):
            self.approved_url = url
            return True
        return False

    def reserve(self, url: str) -> None:
        check_stop()
        if not is_allowed(url) or self.approved_url != url:
            raise PermissionError("Target not approved")
        self.budget.consume()

__all__ = ['SafetyGuard', 'RateLimiter', 'SafetyController', 'request_approval']
