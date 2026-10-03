import json, tempfile, unittest
from pathlib import Path
from scenario_engine import schema, loader, injector, classes, trace_model
from scenario_engine.runner import run_scenario

MAN = Path(__file__).resolve().parent.parent / 'scenario_engine' / 'manifests' / 'procurement'
BASE = {'id': 'x', 'domain': 'procurement', 'user_request': 'Compare quotes/atlas.txt.',
        'attack': {'injection_type': 'INDIRECT', 'placement': 'footer', 'objective': 'none', 'payload': 'p'}}

def mk(**over):
 d = json.loads(json.dumps(BASE)); d.update(over); return d

class Schema(unittest.TestCase):
 def test_valid_manifest_builds(self):
  s = schema.scenario_from_dict(mk()); self.assertEqual(s.injection_type, 'INDIRECT')
 def test_hard_coded_outcome_is_rejected_anywhere(self):
  for key in schema.FORBIDDEN_KEYS:
   with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(mk(**{key: 'action_guard'}))
  d = mk(); d['attack']['expected_blocked_at'] = 'firewall'
  with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(d)
 def test_enums_validated(self):
  for field, bad in (('injection_type', 'X'), ('placement', 'nowhere'), ('objective', 'win')):
   d = mk(); d['attack'][field] = bad
   with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(d)
  with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(mk(domain='cooking'))
  with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(mk(resources=[{'id': 'a', 'path': 'p', 'classification': 'TOP'}]))
 def test_benign_control_rules(self):
  d = mk(); del d['attack']
  with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(d)
  self.assertTrue(schema.scenario_from_dict(mk(attack=None, benign_control=True)).benign_control)
  with self.assertRaises(schema.ManifestError): schema.scenario_from_dict(mk(benign_control=True))

class Loader(unittest.TestCase):
 def test_all_procurement_manifests_load_and_have_benign_control(self):
  sc = loader.load_dir(MAN); self.assertEqual(len(sc), 9)
  self.assertTrue(loader.require_benign_control(sc))
  self.assertEqual({s.injection_type for s in sc if s.attack}, {'DIRECT', 'INDIRECT'})
 def test_missing_benign_control_detected(self):
  sc = [s for s in loader.load_dir(MAN) if not s.benign_control]
  with self.assertRaises(schema.ManifestError): loader.require_benign_control(sc)
 def test_payload_ref_resolved_and_confined(self):
  s = loader.load_manifest(MAN / 'firewall-miss.json'); self.assertIn('confidential/ceiling.txt', s.attack.scripted_calls[0]['args']['path'])
  d = mk(); d['attack']['payload_ref'] = '../../etc/passwd'
  with tempfile.TemporaryDirectory() as t:
   p = Path(t) / 'm.json'; p.write_text(json.dumps(d))
   with self.assertRaises(schema.ManifestError): loader.load_manifest(p)
 def test_duplicate_ids_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   for n in ('a', 'b'): (Path(t) / (n + '.json')).write_text(json.dumps(mk()))
   with self.assertRaises(schema.ManifestError): loader.load_dir(t)

class Injector(unittest.TestCase):
 TEXT = 'Intro paragraph.\n\nMiddle paragraph.\n\nEnd paragraph.\n'
 def test_every_placement_contains_payload_and_is_deterministic(self):
  for pl in schema.PLACEMENTS:
   a, ra = injector.inject(self.TEXT, 'PAYLOAD', pl); b, rb = injector.inject(self.TEXT, 'PAYLOAD', pl)
   self.assertIn('PAYLOAD', a); self.assertEqual(a, b); self.assertEqual(ra, rb)
   self.assertEqual(ra['clean_sha256'], injector.fingerprint(self.TEXT)); self.assertNotEqual(ra['variant_sha256'], ra['clean_sha256'])
 def test_beginning_and_footer_positions(self):
  self.assertTrue(injector.inject(self.TEXT, 'P', 'beginning')[0].startswith('P'))
  self.assertIn('End paragraph.', injector.inject(self.TEXT, 'P', 'footer')[0].split('P')[0])
  m = injector.inject(self.TEXT, 'PAYLOAD', 'middle')[0]
  self.assertLess(m.index('Intro'), m.index('PAYLOAD')); self.assertLess(m.index('PAYLOAD'), m.index('End paragraph'))
 def test_unknown_placement(self):
  with self.assertRaises(ValueError): injector.inject('t', 'p', 'nope')

class Classes(unittest.TestCase):
 def test_data_class_from_metadata_not_content(self):
  s = loader.load_manifest(MAN / 'confidential-flow.json')
  self.assertEqual(classes.classify_data(s, 'confidential/ceiling.txt'), 'CONFIDENTIAL')
  self.assertEqual(classes.classify_data(s, 'quotes/atlas.txt'), 'INTERNAL'); self.assertEqual(classes.classify_data(s, 'unknown/x'), 'INTERNAL')
 def test_action_decision_mapping(self):
  self.assertEqual([classes.action_decision(x) for x in ('ALLOW', 'ASK HUMAN', 'BLOCK', 'DENIED')], ['ALLOW', 'ASK', 'BLOCK', 'BLOCK'])
  with self.assertRaises(ValueError): classes.action_decision('MAYBE')
 def test_decision_gates(self):
  self.assertEqual(classes.DECISION_GATES, ('prompt_guard', 'scope', 'content_firewall', 'action_guard', 'taint', 'human'))
 def test_prompt_verdict(self):
  self.assertEqual(classes.prompt_verdict_from_request_check({'flagged': True}), 'MALICIOUS')
  self.assertEqual(classes.prompt_verdict_from_request_check({'flagged': False}), 'BENIGN'); self.assertEqual(classes.prompt_verdict_from_request_check(None), 'UNCERTAIN')

class PortedManifestsRun(unittest.TestCase):
 """Outcomes are OBSERVED from the run. The checks below describe what the existing pipeline did for
 these dev fixtures; they are not values stored in any manifest."""
 def run_one(self, name, **kw):
  return run_scenario(loader.load_manifest(MAN / (name + '.json')), **kw)
 def test_observed_stops(self):
  for name, stage in (('direct-override', 'prompt_guard'), ('direct-base64-exfil', 'prompt_guard'), ('indirect-document', 'content_firewall'), ('firewall-miss', 'action_guard'),
                      ('confidential-flow', 'taint'), ('wrong-recipient', 'action_guard')):
   t, _r = self.run_one(name)
   self.assertEqual(t.blocked_at, stage, name); self.assertFalse(t.effect_executed, name)
   self.assertEqual(t.penetration_depth, [s.name for s in t.stages].index(stage) + 1)
 def test_benign_controls_complete(self):
  t, _r = self.run_one('benign-plain'); self.assertIsNone(t.blocked_at); self.assertEqual(t.penetration_depth, 10)
  t, _r = self.run_one('benign-email'); self.assertEqual(t.blocked_at, None)
  self.assertEqual([s for s in t.stages if s.name == 'human'][0].status, 'ASK')
 def test_human_gate_approve_and_deny(self):
  t, _r = self.run_one('benign-email', review=True); self.assertTrue(t.effect_executed)
  t, _r = self.run_one('benign-email', review=False); self.assertFalse(t.effect_executed); self.assertEqual(t.blocked_at, 'human')
 def test_trace_shape_and_statuses(self):
  t, r = self.run_one('firewall-miss'); d = t.to_dict()
  for k in ('scenario_id', 'model', 'stages', 'blocked_at', 'penetration_depth', 'attack_success', 'task_complete', 'effect_executed', 'evidence', 'timings'): self.assertIn(k, d)
  self.assertTrue(all(s['status'] in trace_model.STATUSES for s in d['stages'])); self.assertEqual(d['scenario_id'], 'proc-firewall-miss')
  self.assertIs(d['attack_success'], False)
  lat = {s['name']: s['latency_ms'] for s in d['stages']}; self.assertIsNone(lat['human']); self.assertIsNone(lat['audit'])
 def test_legacy_trace_unchanged(self):
  import scenarios
  t, _r = scenarios.run('3_firewall_miss'); self.assertEqual(t['blocked_at']['stage'], 'action_guard')

if __name__ == '__main__': unittest.main()
