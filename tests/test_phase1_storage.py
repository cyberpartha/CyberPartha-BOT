"""Phase 1 — StateDB unit tests (in-memory SQLite)."""
import tempfile, pathlib, unittest
from pathlib import Path
from core.storage.db import StateDB


class TestStateDB(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False)
        self.tmp.close()
        self.addCleanup(lambda p=self.tmp.name: Path(p).unlink(missing_ok=True))
        self.db_path = pathlib.Path(self.tmp.name)

    def test_meta_roundtrip(self):
        with StateDB(self.db_path) as db:
            db.set_meta('key1', 'value1')
            self.assertEqual(db.get_meta('key1'), 'value1')

    def test_meta_default(self):
        with StateDB(self.db_path) as db:
            self.assertEqual(db.get_meta('missing', 'default'), 'default')

    def test_add_host(self):
        with StateDB(self.db_path) as db:
            db.add_host('api.example.com', 'ct')
            self.assertEqual(db.count_hosts(), 1)

    def test_host_dedup(self):
        with StateDB(self.db_path) as db:
            db.add_host('api.example.com', 'ct')
            db.add_host('api.example.com', 'wayback')
            self.assertEqual(db.count_hosts(), 1)

    def test_add_suggestion(self):
        with StateDB(self.db_path) as db:
            sid = db.add_suggestion('access-control', 'Test IDOR', priority=50)
            self.assertIsNotNone(sid)
            row = db.next_pending()
            self.assertIsNotNone(row)
            self.assertEqual(row[1], 'access-control')

    def test_suggestion_status_update(self):
        with StateDB(self.db_path) as db:
            sid = db.add_suggestion('injection', 'SQL test')
            db.update_suggestion_status(sid, 'skipped')
            self.assertIsNone(db.next_pending())

    def test_suggestion_exists(self):
        with StateDB(self.db_path) as db:
            db.add_suggestion('ssrf', 'SSRF check')
            self.assertTrue(db.suggestion_exists('ssrf'))
            self.assertFalse(db.suggestion_exists('xss'))

    def test_all_hosts_limit(self):
        with StateDB(self.db_path) as db:
            for i in range(10):
                db.add_host(f'host{i}.example.com', 'ct')
            hosts = db.all_hosts(limit=5)
            self.assertEqual(len(hosts), 5)


if __name__ == '__main__':
    unittest.main()
