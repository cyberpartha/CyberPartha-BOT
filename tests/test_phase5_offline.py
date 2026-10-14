import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from engine import core, phase5

class Phase5Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        for key, path in [("BASE",base),("PROGRAMS",base/"programs"),("STATE",base/"state"),("REPORTS",base/"reports")]:
            p=patch.object(core,key,path); p.start(); self.addCleanup(p.stop)
        core.init("LabTest","example.com")

    def test_offline_report_no_claims(self):
        with core.db("LabTest") as conn:
            conn.execute("INSERT INTO suggestions (category,title,method,max_requests,status) VALUES (?,?,?,?,?)",
                         ("access-control","IDOR speculation","GET",1,"validated"))
            conn.execute("CREATE TABLE local_audit (id INTEGER PRIMARY KEY,created_at INTEGER,target_fingerprint TEXT,status TEXT,http_status INTEGER,response_bytes INTEGER)")
            conn.execute("INSERT INTO local_audit VALUES (1,0,'SECRET-FINGERPRINT','observed-not-validated',200,28)")
            conn.commit()
        result=phase5.generate("LabTest")
        obj=json.loads(Path(result["json"]).read_text())
        md=Path(result["markdown"]).read_text()
        self.assertFalse(obj["finding_confirmed"])
        self.assertEqual(obj["confirmed_vulnerabilities"],[])
        self.assertEqual(obj["plan_status_counts"]["validated"],1)
        for content in (md,Path(result["json"]).read_text()):
            self.assertNotIn("SECRET-FINGERPRINT",content)
            self.assertNotIn("IDOR speculation",content)
        self.assertEqual(Path(result["json"]).stat().st_mode & 0o777,0o600)

    def test_missing_profile_rejected(self):
        with self.assertRaises(FileNotFoundError):
            phase5.snapshot("Missing")

    def test_stop_blocks_report(self):
        (core.BASE/"STOP").touch()
        with self.assertRaises(PermissionError):
            phase5.generate("LabTest")
