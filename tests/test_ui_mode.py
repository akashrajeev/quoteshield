import os,unittest
from pathlib import Path
from unittest import mock
from ui_mode import resolve_mode,status_label,NOT_CONFIGURED
APP=str(Path(__file__).resolve().parents[1]/'streamlit_app.py')
CLEAN={k:'' for k in ['SHIELD_PROVIDER','SHIELD_MODEL_URL','SHIELD_MODEL_NAME','SHIELD_MODEL_KEY']}
LIVE={'SHIELD_PROVIDER':'freellmapi','SHIELD_MODEL_URL':'http://127.0.0.1:31415/v1/chat/completions','SHIELD_MODEL_NAME':'proxy-model','SHIELD_MODEL_KEY':''}

class ModePolicy(unittest.TestCase):
 def test_live_is_primary_and_never_silently_offline(self):
  self.assertEqual(resolve_mode(True,False),('llm',None))
  self.assertEqual(resolve_mode(False,False),('llm',NOT_CONFIGURED))
  self.assertEqual(resolve_mode(False,True),('offline',None))
  self.assertEqual(resolve_mode(True,True),('offline',None))
 def test_status_label(self):
  self.assertIn('not configured',status_label(False));self.assertIn('proxy-model',status_label(True,'proxy-model'))

def run_app(env):
 from streamlit.testing.v1 import AppTest
 with mock.patch.dict(os.environ,env),mock.patch('dotenv.load_dotenv',lambda *a,**k:False):
  at=AppTest.from_file(APP,default_timeout=60).run()
  at.env_after={k:os.environ.get(k) for k in LIVE}
  return at

class AppStates(unittest.TestCase):
 def test_unconfigured_shows_red_state_and_disables_runs(self):
  at=run_app(CLEAN);self.assertFalse(at.exception)
  self.assertTrue(any('Live model not configured' in m.value for m in at.markdown))
  self.assertTrue(any('Live model not configured' in e.value for e in at.error))
  runs=[b for b in at.button if b.label in ('Run side-by-side','Run clean legitimate task','Run custom challenge')]
  self.assertEqual(len(runs),3);self.assertTrue(all(b.disabled for b in runs))
 def test_offline_only_via_developer_verification(self):
  at=run_app(CLEAN)
  self.assertIn('Offline guard verification',[t.label for t in at.sidebar.toggle])
  self.assertNotIn('Execution mode',[r.label for r in at.sidebar.radio])
  [x for x in at.sidebar.toggle if x.label=='Offline guard verification'][0].set_value(True).run();self.assertFalse(at.exception)
  self.assertFalse(at.error)
  self.assertTrue(any('Developer verification is on' in w.value for w in at.warning))
  runs=[b for b in at.button if b.label in ('Run side-by-side','Run clean legitimate task','Run custom challenge')]
  self.assertTrue(all(not b.disabled for b in runs))
 def test_live_configured_and_freellmapi_provider_skips_preset(self):
  at=run_app(LIVE);self.assertFalse(at.exception)
  self.assertFalse(at.error)
  self.assertTrue(any('Live model: proxy-model' in m.value for m in at.markdown))
  self.assertEqual(at.env_after,LIVE)  # SHIELD_PROVIDER=freellmapi is not a preset: configure() must not overwrite URL/name/key
  runs=[b for b in at.button if b.label=='Run side-by-side'];self.assertFalse(runs[0].disabled)
 def test_tab_order_judge_challenge_first(self):
  at=run_app(LIVE);self.assertEqual([t.label for t in at.tabs][:2],['Judge Challenge','Attack Arena'])
 def test_offline_path_still_runs_under_developer_verification(self):
  from streamlit.testing.v1 import AppTest
  with mock.patch.dict(os.environ,CLEAN),mock.patch('dotenv.load_dotenv',lambda *a,**k:False):
   at=AppTest.from_file(APP,default_timeout=90).run()
   [x for x in at.sidebar.toggle if x.label=='Offline guard verification'][0].set_value(True).run()
   [b for b in at.button if b.label=='Run side-by-side'][0].click().run()
   self.assertFalse(at.exception)  # the unprotected lane intentionally shows a breach error
   self.assertNotIn('Live model not configured',' '.join(e.value for e in at.error))
   self.assertTrue(any('Offline adversarial tool-proposal verification' in c.value for c in at.caption))
