"""core.approval — Structured, bound, single-use approval tokens."""
from .token import ApprovalToken, ApprovalStore, ApprovalError

def request_approval(url: str = "") -> bool:
    try:
        from core.scope_guard import is_allowed
        if not is_allowed(url):
            print("BLOCKED: Target outside allowlist.")
            return False
        print(f"\nApprove ONE GET to: {url}")
        print("OAuth login and token exchange will occur before this GET.")
        try:
            return input("Type YES to authorize this single run: ").strip() == "YES"
        except (EOFError, KeyboardInterrupt):
            return False
    except Exception:
        return False

__all__ = ['ApprovalToken', 'ApprovalStore', 'ApprovalError', 'request_approval']
