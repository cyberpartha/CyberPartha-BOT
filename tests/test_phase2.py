import unittest
from unittest.mock import patch
from engine import phase2
class Phase2Tests(unittest.TestCase):
    def setUp(self):
        self.data={'program_name':'demo','policy_url':'https://example.com/policy',
                   'policy_reviewed':True,'ai_allowed':True,'passive_allowed':True,
                   'allowed_domains':['example.com'],'excluded_domains':[]}
    def test_policy_fail_closed(self):
        with patch.object(phase2.core,'load',return_value={**self.data,'ai_allowed':False}):
            self.assertFalse(phase2.policy_review('demo')['passive_ready'])
    def test_policy_ready_is_assertion_not_verification(self):
        with patch.object(phase2.core,'load',return_value=self.data):
            self.assertTrue(phase2.policy_review('demo')['passive_ready'])
    def test_archive_host_parser(self):
        class Resp:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'[["original"],["https://api.example.com/path"],["https://evil.test/"]]'
        class Opener:
            def open(self,*args,**kwargs):return Resp()
        with patch('urllib.request.build_opener',return_value=Opener()):
            self.assertEqual(phase2.fetch_wayback('example.com',2,10),['api.example.com','evil.test'])
    def test_denied_without_network(self):
        with patch.object(phase2.core,'load',return_value={**self.data,'passive_allowed':False}):
            with patch.object(phase2,'fetch_wayback') as request:
                with self.assertRaises(PermissionError):phase2.collect('demo')
                request.assert_not_called()
if __name__=='__main__':unittest.main()
