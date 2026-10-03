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
 def test_provider_configuration(self):
  from unittest.mock import patch
  from provider_config import configure
  for provider in ('gemini','groq','openrouter','nvidia'):
   with self.subTest(provider=provider),patch.dict(os.environ,{},clear=True):
    cfg,key=configure(provider)
    self.assertFalse(key)
    self.assertEqual(os.environ['SHIELD_MODEL_NAME'],cfg['model'])
    self.assertEqual(os.environ['SHIELD_MODEL_URL'],cfg['endpoint'])
    self.assertTrue(cfg['models_endpoint'].endswith('/models'))
 def test_dotenv_precedence_and_keys(self):
  from unittest.mock import patch
  from provider_config import load_local_env,configure
  with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'GROQ_MODEL':'shell-model'},clear=True):
   p=Path(tmp)/'.env';p.write_text('GROQ_API_KEY=fixture-only-value\nGROQ_MODEL=file-model\nNVIDIA_BASE_URL=http://localhost:8000/v1\n')
   load_local_env(p);cfg,key=configure('groq')
   self.assertEqual(key,'fixture-only-value');self.assertEqual(os.environ['SHIELD_MODEL_NAME'],'shell-model')
   configure('groq','cli-model');self.assertEqual(os.environ['SHIELD_MODEL_NAME'],'cli-model')
   configure('nvidia');self.assertNotIn('SHIELD_MODEL_KEY',os.environ);self.assertEqual(os.environ['SHIELD_MODEL_URL'],'http://localhost:8000/v1/chat/completions')
