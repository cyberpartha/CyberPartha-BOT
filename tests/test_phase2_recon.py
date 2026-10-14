"""Tests for Phase 2 passive recon connectors and collector orchestrator."""
import unittest, tempfile, os
from unittest.mock import patch, MagicMock
from recon.sources.ct import CertificateTransparencySource
from recon.sources.wayback import WaybackSource
from recon.sources.alienvault import AlienVaultSource
from recon.collector import ReconCollector
from core.storage.db import StateDB

class TestPhase2Recon(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False)
        self.tmp.close()
        self.db = StateDB(self.tmp.name)
        self.db.__enter__()
        self.addCleanup(self.db.__exit__, None, None, None)
        self.profile = {
            "program_name": "example-corp",
            "policy_url": "https://example.com/bounty",
            "policy_reviewed": True,
            "passive_allowed": True,
            "ai_allowed": True,
            "allowed_domains": ["example.com"],
            "excluded_domains": ["private.example.com"]
        }

    def tearDown(self):
        try: os.unlink(self.tmp.name)
        except OSError: pass

    @patch('urllib.request.urlopen')
    def test_ct_source_filters_and_dedups(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'[{"name_value":"api.example.com\\nsub.example.com"}, {"name_value":"evil.test"}]'
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        src = CertificateTransparencySource(timeout=5, max_results=10)
        res = src.fetch_subdomains("example.com")
        self.assertIn("api.example.com", res)
        self.assertIn("sub.example.com", res)
        self.assertNotIn("evil.test", res)

    @patch('urllib.request.urlopen')
    def test_ct_source_error_does_not_crash(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Connection timed out")
        src = CertificateTransparencySource(timeout=5, max_results=10)
        res = src.fetch_subdomains("example.com")
        self.assertEqual(res, [])

    @patch('urllib.request.build_opener')
    def test_wayback_source_success(self, mock_build_opener):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'[["original"], ["https://admin.example.com/login"], ["https://other.com/"]]'
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        src = WaybackSource(timeout=5, max_results=10)
        res = src.fetch_subdomains("example.com")
        self.assertEqual(res, ["admin.example.com"])

    def test_collector_excludes_out_of_scope(self):
        collector = ReconCollector("example-corp", self.profile, self.db)
        with patch.object(CertificateTransparencySource, 'fetch_subdomains', return_value=["api.example.com", "private.example.com", "rogue.com"]):
            with patch.object(WaybackSource, 'fetch_subdomains', return_value=[]):
                res = collector.run(sources=["ct"])
                self.assertEqual(res["status"], "completed")
                hosts = [h["hostname"] for h in res["hosts"]]
                self.assertIn("api.example.com", hosts)
                self.assertNotIn("private.example.com", hosts)  # Excluded!
                self.assertNotIn("rogue.com", hosts)            # Out of scope!

    def test_collector_unreviewed_policy_raises(self):
        unreviewed = {**self.profile, "policy_reviewed": False}
        collector = ReconCollector("example-corp", unreviewed, self.db)
        with self.assertRaises(PermissionError):
            collector.run()

    def test_collector_resume_skips_checkpoints(self):
        collector = ReconCollector("example-corp", self.profile, self.db)
        self.db.set_meta("phase2_done:ct:example.com", "1")
        with patch.object(CertificateTransparencySource, 'fetch_subdomains') as mock_ct:
            with patch.object(WaybackSource, 'fetch_subdomains', return_value=["api.example.com"]):
                res = collector.run(sources=["ct", "wayback"])
                mock_ct.assert_not_called()  # Skipped because checkpoint exists!
                self.assertEqual(res["tasks_run"], 1)

    def test_collector_paused_sends_no_traffic(self):
        self.db.set_paused(True)
        collector = ReconCollector("example-corp", self.profile, self.db)
        with patch.object(CertificateTransparencySource, 'fetch_subdomains') as mock_ct:
            res = collector.run()
            self.assertEqual(res["status"], "paused")
            mock_ct.assert_not_called()

if __name__ == '__main__':
    unittest.main()
