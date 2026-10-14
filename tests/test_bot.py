import unittest
from unittest.mock import patch, Mock
from core.scope_guard import is_allowed, ALLOWED_URL
from core.safety import SafetyController
from core.budget import BudgetExceeded
from core.stop_switch import EmergencyStop
from core.http_client import get_profile

class SafetyTests(unittest.TestCase):
    def test_allowlist(self):
        self.assertTrue(is_allowed(ALLOWED_URL))
        for url in ("http://api.canva.com/rest/v1/users/me",
                    "https://api.canva.com.evil.test/rest/v1/users/me",
                    "https://api.canva.com/rest/v1/designs",
                    ALLOWED_URL+"?id=1"):
            self.assertFalse(is_allowed(url))
    def test_no_approval(self):
        s = SafetyController()
        with self.assertRaises(PermissionError):
            s.reserve(ALLOWED_URL)
    def test_one_request(self):
        s = SafetyController()
        with patch("core.safety.request_approval", return_value=True):
            self.assertTrue(s.authorize(ALLOWED_URL))
        s.reserve(ALLOWED_URL)
        with self.assertRaises(BudgetExceeded):
            s.reserve(ALLOWED_URL)
    def test_stop(self):
        s = SafetyController()
        with patch("core.stop_switch.Path.exists", return_value=True):
            with self.assertRaises(EmergencyStop):
                s.authorize(ALLOWED_URL)
    def test_mock_http(self):
        s = SafetyController()
        with patch("core.safety.request_approval", return_value=True):
            s.authorize(ALLOWED_URL)
        response = Mock(status_code=200, content=b'{"team_user":{"id":"secret"}}')
        response.json.return_value = {"team_user": {"id": "secret"}}
        with patch("core.http_client.requests.get", return_value=response) as req:
            result = get_profile("dummy", s, ALLOWED_URL)
        self.assertEqual(result["status"], 200)
        self.assertNotIn("secret", str(result))
        self.assertFalse(req.call_args.kwargs["allow_redirects"])
        self.assertEqual(req.call_count, 1)

if __name__ == "__main__":
    unittest.main()
