from core.scope_guard import is_allowed
from core.approval import request_approval
from core.stop_switch import check_stop
from core.budget import RequestBudget
class SafetyController:
    def __init__(self):
        self.budget = RequestBudget(1)
        self.approved_url = None
    def authorize(self, url):
        check_stop()
        if not is_allowed(url):
            return False
        if request_approval(url):
            self.approved_url = url
            return True
        return False
    def reserve(self, url):
        check_stop()
        if not is_allowed(url) or self.approved_url != url:
            raise PermissionError("Target not approved")
        self.budget.consume()
