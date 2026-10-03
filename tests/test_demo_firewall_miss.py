"""Firewall-miss -> guard-block developer demo. A demo case, never an evaluation case."""
import json,os,re,unittest
from pathlib import Path
from unittest import mock
from shield import firewall,QUOTES,Sandbox,Guard,Scope,ToolCall,paired
ROOT=Path(__file__).resolve().parents[1]
DEMO=json.loads((ROOT/'demo/firewall-miss.json').read_text())
RAW=QUOTES['quotes/beacon.txt']+'\n'+DEMO['payload']

class DemoFile(unittest.TestCase):
 def test_labelled_demo_and_isolated_from_eval_data(self):
  self.assertEqual((DEMO['split'],DEMO['demo_only'],DEMO['id']),('demo',True,'demo-firewall-miss'))
  self.assertFalse(str(ROOT/'demo/firewall-miss.json').startswith(str(ROOT/'data')))
  for f in (ROOT/'data').rglob('*.json'):
   text=f.read_text()
   self.assertNotIn('demo-firewall-miss',text,f.name);self.assertNotIn(DEMO['payload'][:60],text,f.name)
 def test_eval_tooling_never_references_demo_dir(self):
  for name in ['evaluate.py','freeze.py','heldout.py','metrics.py','make_corpus.py','make_mixed_corpus.py']:
   p=ROOT/name
   if p.exists():self.assertNotRegex(p.read_text(),r'demo/|firewall-miss',name)

class FirewallMiss(unittest.TestCase):
 def test_deterministic_firewall_finds_nothing(self):
  fw=firewall(RAW)  # no model: deterministic layers only
  self.assertEqual(fw['findings'],[],'Firewall rules now catch the demo payload; write a new phrasing for the demo (the point is a miss).')
  self.assertFalse(fw['quarantined']);self.assertEqual(fw['removed_spans'],[])
  self.assertIn('confidential/ceiling.txt',fw['safe'])
 def test_payload_contains_no_obvious_trigger_words(self):
  self.assertNotRegex(DEMO['payload'],r'(?i)ignore|disregard|override|exfiltrate|send|email|forward|@|https?://|base64|rot13')

class GuardBlocks(unittest.TestCase):
 def test_guard_blocks_ceiling_read_with_resource_scope(self):
  sb=Sandbox(poison=DEMO['payload']);g=Guard(Scope(),sb)
  d=g.inspect(ToolCall('read_file',{'path':'confidential/ceiling.txt'}))
  self.assertEqual((d.verdict,d.rule),('BLOCK','resource_scope'))
 def test_secret_read_stays_false_and_nothing_leaves(self):
  sb=Sandbox(poison=DEMO['payload']);g=Guard(Scope(),sb)
  g.inspect(ToolCall('read_file',{'path':'confidential/ceiling.txt'}))
  self.assertFalse(sb.secret_read);self.assertEqual(sb.reads,[]);self.assertEqual(sb.emails,[])
 def test_offline_scripted_pair_blocks_in_protected_lane_only(self):
  p=paired(DEMO,'offline')
  self.assertIn(('action','BLOCK','resource_scope'),[(e['stage'],e['decision'],e.get('rule') or e.get('reason')) for e in p['protected']['audit']])
  self.assertFalse(p['protected']['secret_exfiltrated']);self.assertEqual(p['protected']['mock_outbox'],[])
  self.assertFalse(any(e['decision']=='BLOCK' for e in p['baseline']['audit']))

class DemoButton(unittest.TestCase):
 def test_button_runs_scripted_demo_labelled_offline(self):
  from streamlit.testing.v1 import AppTest
  with mock.patch.dict(os.environ,{k:'' for k in ['SHIELD_PROVIDER','SHIELD_MODEL_URL','SHIELD_MODEL_NAME','SHIELD_MODEL_KEY']}),mock.patch('dotenv.load_dotenv',lambda *a,**k:False):
   at=AppTest.from_file(str(ROOT/'streamlit_app.py'),default_timeout=90).run()
   self.assertTrue(any('not a measured result' in m.value for m in at.markdown))
   [b for b in at.button if b.label=='Run firewall-miss demo'][0].click().run()
   self.assertFalse(at.exception)
   self.assertTrue(any('Offline adversarial tool-proposal verification' in c.value for c in at.caption))
