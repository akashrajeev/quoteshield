import json,tempfile,unittest,zipfile,os
from pathlib import Path
from local_runner import run_suite,PRESETS
from tests.fixture_model import FixtureModel
class LocalRunnerTests(unittest.TestCase):
 def test_bundle_fixture_only(self):
  with tempfile.TemporaryDirectory() as tmp:
   secret='TEST-NOT-A-REAL-KEY-MUST-NOT-APPEAR';os.environ['SHIELD_MODEL_KEY']=secret
   try:
    report,archive=run_suite('fixture',Path(tmp)/'results',20,1,FixtureModel)
    self.assertFalse(report['stopped_early']);self.assertEqual(len(report['cases']),2)
    with zipfile.ZipFile(archive) as z:
     self.assertTrue(any(n.endswith('summary.json') for n in z.namelist()))
     for n in z.namelist():self.assertNotIn(secret,z.read(n).decode())
    self.assertEqual(report['config']['kind'],'fixture_orchestration_check')
   finally:os.environ.pop('SHIELD_MODEL_KEY',None)
 def test_presets(self):
  self.assertEqual(PRESETS['gemini']['model'],'gemini-2.5-flash');self.assertEqual(PRESETS['groq']['model'],'openai/gpt-oss-120b')
