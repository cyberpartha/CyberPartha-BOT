import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from engine import phase4,core
import json

class Phase4Tests(unittest.TestCase):
    def test_disabled_and_nonexistent_profiles_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(core,'STATE',Path(d)),patch.object(core,'PROGRAMS',Path(d)),patch.object(core,'REPORTS',Path(d)):
                with self.assertRaises(FileNotFoundError):
                    phase4.plan('Missing','http://127.0.0.1:8765/')
                core.init('Demo','example.com')
                with self.assertRaises(PermissionError):
                    phase4.plan('Demo','http://127.0.0.1:8765/')
                with self.assertRaises(PermissionError):
                    phase4.enable('Demo','YES')
                self.assertIn('enabled',phase4.enable('Demo','I OWN THIS LOCAL LAB'))
                self.assertEqual(phase4.plan('Demo','http://127.0.0.1:8765/')['method'],'GET')

    def test_stop_and_pause_block_enable(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(core,'BASE',Path(d)),patch.object(core,'STATE',Path(d)/'state'),patch.object(core,'PROGRAMS',Path(d)/'programs'),patch.object(core,'REPORTS',Path(d)/'reports'):
                core.init('Demo','example.com')
                (Path(d)/'STOP').write_text('stop')
                with self.assertRaises(PermissionError): phase4.enable('Demo','I OWN THIS LOCAL LAB')
                (Path(d)/'STOP').unlink()
                with core.db('Demo') as conn: core.setmeta(conn,'paused','1')
                with self.assertRaises(PermissionError): phase4.enable('Demo','I OWN THIS LOCAL LAB')

    def test_reject_external(self):
        for url in ['https://example.com/','http://localhost:8765/','http://192.168.1.1:8765/',
                    'http://127.0.0.1:8765/a?x=1','http://127.0.0.1:8765/%2e%2e/x',
                    'http://127.0.0.1:8765/a/../b']:
            with self.subTest(url=url),self.assertRaises(PermissionError): phase4._safe_target(url)
    def test_local_allowed(self):
        phase4._safe_target('http://127.0.0.1:8765/health')
    def test_wrong_confirmation(self):
        with patch.object(phase4,'_ready'):
            with self.assertRaises(PermissionError): phase4.approve('Demo','http://127.0.0.1:8765/','no')
    def test_explicit_approval_consumed(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(core,'STATE',Path(d)),patch.object(core,'PROGRAMS',Path(d)),patch.object(core,'REPORTS',Path(d)),patch.object(phase4,'_ready'):
                a=phase4.approve('Demo','http://127.0.0.1:8765/','YES')
                token=a['approval_token']
                with patch.object(phase4.urllib.request,'build_opener') as opener:
                    opener.return_value.open.side_effect=OSError('offline')
                    self.assertEqual(phase4.execute('Demo','http://127.0.0.1:8765/',token)['status'],'transport-error')
                    with self.assertRaises(PermissionError): phase4.execute('Demo','http://127.0.0.1:8765/',token)
                    self.assertEqual(opener.return_value.open.call_count,1)
    def test_mismatched_target(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(core,'STATE',Path(d)),patch.object(core,'PROGRAMS',Path(d)),patch.object(core,'REPORTS',Path(d)),patch.object(phase4,'_ready'):
                token=phase4.approve('Demo','http://127.0.0.1:8765/a','YES')['approval_token']
                with self.assertRaises(PermissionError): phase4.execute('Demo','http://127.0.0.1:8765/b',token)
if __name__=='__main__': unittest.main()
