"""Phase 1 — AuditLogger unit tests."""
import json, pathlib, tempfile, unittest
from pathlib import Path
from core.audit.logger import AuditLogger


class TestAuditLogger(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False)
        self.tmp.close()
        self.addCleanup(lambda p=self.tmp.name: Path(p).unlink(missing_ok=True))
        self.path = pathlib.Path(self.tmp.name)
        self.log = AuditLogger(self.path, 'TestProg')

    def _entries(self):
        return [json.loads(line) for line in self.path.read_text().splitlines() if line]

    def test_scope_check_logged(self):
        self.log.log_scope_check('https://example.com', True)
        entries = self._entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['event_type'], 'scope_check')
        self.assertEqual(entries[0]['details']['allowed'], True)

    def test_block_logged(self):
        self.log.log_block('Out of scope', 'https://evil.com')
        entries = self._entries()
        self.assertEqual(entries[0]['event_type'], 'blocked')

    def test_stop_logged(self):
        self.log.log_stop()
        self.assertEqual(self._entries()[0]['event_type'], 'emergency_stop')

    def test_sensitive_data_redacted_in_details(self):
        self.log.log_error('auth_error', 'Bearer abc123secret')
        entries = self._entries()
        text = json.dumps(entries)
        self.assertNotIn('abc123secret', text)

    def test_append_only(self):
        self.log.log_stop()
        self.log.log_block('test')
        self.assertEqual(len(self._entries()), 2)

    def test_program_recorded(self):
        self.log.log_stop()
        self.assertEqual(self._entries()[0]['program'], 'TestProg')


if __name__ == '__main__':
    unittest.main()
