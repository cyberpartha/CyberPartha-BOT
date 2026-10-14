class BudgetExceeded(RuntimeError):
    pass
class RequestBudget:
    def __init__(self, limit=1):
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be positive integer")
        self.remaining = limit
    def consume(self):
        if self.remaining <= 0:
            raise BudgetExceeded("Request budget exhausted")
        self.remaining -= 1
