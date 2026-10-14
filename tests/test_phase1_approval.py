"""Phase 1 — ApprovalToken + ApprovalStore unit tests (offline)."""
import time, unittest
from unittest.mock import patch
from core.approval.token import ApprovalToken, ApprovalStore, ApprovalError


class TestApprovalToken(unittest.TestCase):

    def _token(self, **kwargs):
        defaults = dict(
            program_name='TestProg',
            target_url='https://api.example.com/v1/data',
            http_method='GET',
        )
        defaults.update(kwargs)
        return ApprovalToken.create(**defaults)

    def test_create_and_validate_ok(self):
        t = self._token()
        t.validate('TestProg', 'https://api.example.com/v1/data', 'GET')

    def test_program_mismatch(self):
        t = self._token()
        with self.assertRaises(ApprovalError):
            t.validate('OtherProg', 'https://api.example.com/v1/data', 'GET')

    def test_url_mismatch(self):
        t = self._token()
        with self.assertRaises(ApprovalError):
            t.validate('TestProg', 'https://api.example.com/v1/other', 'GET')

    def test_method_mismatch(self):
        t = self._token()
        with self.assertRaises(ApprovalError):
            t.validate('TestProg', 'https://api.example.com/v1/data', 'POST')

    def test_payload_mismatch(self):
        t = self._token(payload={'key': 'value'})
        with self.assertRaises(ApprovalError):
            t.validate('TestProg', 'https://api.example.com/v1/data', 'GET',
                       payload={'key': 'other'})

    def test_expired_token(self):
        t = self._token(ttl_seconds=1)
        with patch('core.approval.token.time.time', return_value=t.expires_at + 1):
            with self.assertRaises(ApprovalError):
                t.validate('TestProg', 'https://api.example.com/v1/data', 'GET')

    def test_to_dict_has_expected_keys(self):
        t = self._token()
        d = t.to_dict()
        for key in ('token_id', 'program_name', 'target_url', 'http_method',
                    'payload_hash', 'test_account', 'max_requests',
                    'policy_version', 'issued_at', 'expires_at'):
            self.assertIn(key, d)


class TestApprovalStore(unittest.TestCase):

    URL = 'https://api.example.com/v1/data'
    PROG = 'StoreProg'

    def _store_with_token(self):
        store = ApprovalStore()
        token = ApprovalToken.create(self.PROG, self.URL, 'GET')
        store.register(token)
        return store, token

    def test_consume_success(self):
        store, token = self._store_with_token()
        consumed = store.consume(token.token_id, self.PROG, self.URL, 'GET')
        self.assertEqual(consumed.token_id, token.token_id)

    def test_single_use_enforced(self):
        store, token = self._store_with_token()
        store.consume(token.token_id, self.PROG, self.URL, 'GET')
        with self.assertRaises(ApprovalError):
            store.consume(token.token_id, self.PROG, self.URL, 'GET')

    def test_unknown_token_rejected(self):
        store = ApprovalStore()
        with self.assertRaises(ApprovalError):
            store.consume('deadbeef', self.PROG, self.URL, 'GET')

    def test_has_valid_token_true(self):
        store, token = self._store_with_token()
        self.assertTrue(store.has_valid_token(self.PROG, self.URL, 'GET'))

    def test_has_valid_token_false_after_consume(self):
        store, token = self._store_with_token()
        store.consume(token.token_id, self.PROG, self.URL, 'GET')
        self.assertFalse(store.has_valid_token(self.PROG, self.URL, 'GET'))

    def test_token_url_mismatch_blocked(self):
        store, token = self._store_with_token()
        with self.assertRaises(ApprovalError):
            store.consume(token.token_id, self.PROG, 'https://api.example.com/v1/other', 'GET')
        # Token was NOT consumed on failure
        self.assertTrue(store.has_valid_token(self.PROG, self.URL, 'GET'))


if __name__ == '__main__':
    unittest.main()
