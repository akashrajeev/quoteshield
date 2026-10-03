import unittest
import scenarios, trace

def stage(t, k): return next(s for s in t['stages'] if s['stage'] == k)

class ScenarioTests(unittest.TestCase):
 def test_each_scenario_stops_at_its_stage(self):
  for name, sc in scenarios.SCENARIOS.items():
   if sc.get('review') == 'wait': continue
   t, r = scenarios.run(name)
   b = t['blocked_at']
   self.assertEqual(b['stage'] if b else None, sc['expected_stage'], name)
   if 'expected_rule' in sc: self.assertEqual(b['rule'], sc['expected_rule'], name)
   self.assertEqual(t['effect_executed'], sc['effect'], name)

 def test_user_prompt_stops_before_any_run(self):
  t, r = scenarios.run('1_user_prompt')
  self.assertIsNone(r)
  self.assertIn('instruction override', [f['rule'] for f in t['findings']])
  self.assertEqual(stage(t, 'prompt_guard')['status'], 'BLOCK')
  self.assertTrue(all(s['status'] == 'NOT_REACHED' for s in t['stages'][1:]))

 def test_firewall_stage_passed_in_scenario_3(self):
  t, r = scenarios.run('3_firewall_miss')
  self.assertEqual(stage(t, 'content_firewall')['status'], 'PASS')
  self.assertEqual(stage(t, 'agent')['status'], 'SCRIPTED')

 def test_confidential_read_was_authorized_in_scenario_4(self):
  t, r = scenarios.run('4_confidential_flow')
  self.assertEqual(stage(t, 'taint')['status'], 'BLOCK')
  reads = [e for e in r['audit'] if e['stage'] == 'action' and e['decision'] == 'ALLOW' and e['call']['args'].get('path') == 'confidential/ceiling.txt']
  self.assertTrue(reads)
  self.assertEqual(r['mock_outbox'], [])

 def test_ask_human_waits_then_approve_once_then_deny(self):
  t, r = scenarios.run('5_ask_human')
  self.assertTrue(t['waiting_for_human']); self.assertFalse(t['effect_executed'])
  self.assertEqual(stage(t, 'human')['status'], 'ASK HUMAN')
  t, r = scenarios.run('5_ask_human', review=True)
  self.assertTrue(t['effect_executed']); self.assertEqual(len(r['mock_outbox']), 1)
  self.assertEqual(stage(t, 'human')['status'], 'APPROVED')
  t, r = scenarios.run('5_ask_human', review=False)
  self.assertFalse(t['effect_executed']); self.assertEqual(t['blocked_at']['stage'], 'human')

 def test_legitimate_run_has_no_block_and_no_effect(self):
  t, r = scenarios.run('7_legitimate')
  self.assertIsNone(t['blocked_at']); self.assertEqual(t['interventions'], [])
  self.assertEqual(stage(t, 'audit')['status'], 'PASS')

 def test_every_stage_explained_in_every_scenario(self):
  for name in scenarios.SCENARIOS:
   t, r = scenarios.run(name, review=True if name == '5_ask_human' else None)
   for s in t['stages']: self.assertTrue(s['explanation'].strip(), (name, s['stage']))

if __name__ == '__main__': unittest.main()
