"""Artificial fixture validates one-pass protocol, never opens collaborator cases."""
import unittest,tempfile,json,hashlib,os,sys
from pathlib import Path
from unittest.mock import patch
import heldout
class FakeRunner:
 def __init__(self):pass
 def run(self,**kwargs):return {'answer':json.dumps({'summary':'Fixture only','vendors':[]}), 'audit':[],'mock_outbox':[],'task_complete':False,'attack_success':False,'fixture':True}
class HeldoutProtocolTests(unittest.TestCase):
 def test_exclusive_one_pass(self):
  with tempfile.TemporaryDirectory() as tmp:
   old=os.getcwd();os.chdir(tmp)
   try:
    Path('cases.json').write_text(json.dumps([{'id':'artificial-fixture-01','category':'plain','request':'Compare mock quotes','payload':'harmless fixture text'}]));Path('map.json').write_text('{}')
    digest=hashlib.sha256(Path('cases.json').read_bytes()).hexdigest();mapdigest=hashlib.sha256(Path('map.json').read_bytes()).hexdigest()
    frozen={'freeze_sha256':'fixture-only','control_map_sha256':mapdigest};Path('freeze.json').write_text(json.dumps(frozen))
    args=['heldout.py','--suite','adith','--cases','cases.json','--sha256',digest,'--control-map','map.json','--freeze','freeze.json']
    with patch.object(heldout,'snapshot',return_value=frozen),patch.object(heldout,'Runner',FakeRunner),patch.object(heldout,'ModelAdapter') as adapter,patch.object(sys,'argv',args):
     adapter.return_value.available=True;heldout.main()
     with self.assertRaises(FileExistsError):heldout.main()
    report=Path('artifacts')/('held-out-adith-'+digest[:12])/'report.json';self.assertTrue(report.exists());self.assertEqual(len(json.loads(report.read_text())['cases']),1)
   finally:os.chdir(old)
 def test_wrong_checksum_rejected_before_run(self):
  with tempfile.TemporaryDirectory() as tmp:
   old=os.getcwd();os.chdir(tmp)
   try:
    Path('cases.json').write_text('[]');Path('freeze.json').write_text('{"freeze_sha256":"fixture-only"}')
    with patch.object(heldout,'snapshot',return_value={'freeze_sha256':'fixture-only'}),patch.object(heldout,'ModelAdapter') as adapter,patch.object(sys,'argv',['heldout.py','--suite','adith','--cases','cases.json','--sha256','wrong','--control-map','missing.json','--freeze','freeze.json']):
     adapter.return_value.available=True
     with self.assertRaisesRegex(RuntimeError,'checksum'):heldout.main()
    self.assertFalse(Path('artifacts').exists())
   finally:os.chdir(old)

 def test_reported_manifest_revision_metadata(self):
  manifest=json.loads((Path(__file__).parents[1]/"data/heldout-id-manifest.json").read_text())
  self.assertEqual(manifest["reported_cases_sha256"],"7752a5db28c41121cb8c01b7b9bc78f25a2922e3b3016d124d70da697036b962")
  self.assertEqual(sum(len(v) for v in manifest["attacks"].values()),15)
  self.assertEqual(len(manifest["controls"]),5)
  self.assertTrue(all(len(v)==3 for v in manifest["attacks"].values()))
