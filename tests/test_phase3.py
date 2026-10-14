import json, tempfile, unittest
from unittest.mock import patch
from pathlib import Path
from engine import phase3

POLICY={'allowed_domains':['example.com'],'excluded_domains':['private.example.com'],
        'policy_reviewed':True,'ai_allowed':True,'passive_allowed':False}
class Phase3Tests(unittest.TestCase):
    def test_owned_id_reasoning(self):
        ep=phase3.normalize_endpoint({'host':'api.example.com','path':'/v1/orders/123','method':'GET','auth_required':True},POLICY)
        self.assertEqual(ep['path'],'/v1/orders/{id}')
        self.assertEqual(phase3.reason(ep)[0]['category'],'access-control')
    def test_out_of_scope(self):
        with self.assertRaises(PermissionError):phase3.normalize_endpoint({'host':'example.com.attacker.test','path':'/ok'},POLICY)
    def test_excluded(self):
        with self.assertRaises(PermissionError):phase3.normalize_endpoint({'host':'private.example.com','path':'/ok'},POLICY)
    def test_sensitive_field_blocked(self):
        with self.assertRaises(ValueError):phase3.normalize_endpoint({'host':'example.com','path':'/ok','authorization':'Bearer abc'},POLICY)
    def test_url_values_blocked(self):
        with self.assertRaises(ValueError):phase3.normalize_endpoint({'host':'example.com','path':'/ok?token=abc'},POLICY)
    def test_redact_parameter_name(self):
        ep=phase3.normalize_endpoint({'host':'example.com','path':'/ok','parameters':['access_token']},POLICY)
        self.assertEqual(ep['parameters'],['{sensitive_parameter}'])
    def test_unknown_auth(self):
        ep=phase3.normalize_endpoint({'host':'example.com','path':'/home'},POLICY)
        self.assertEqual(phase3.reason(ep),[])
    def test_analysis_policy_denied(self):
        with patch('engine.phase3.core.load',return_value={**POLICY,'ai_allowed':False}):
            with self.assertRaises(PermissionError):phase3.analyze_file('Demo','/nonexistent')
if __name__=='__main__':unittest.main()
