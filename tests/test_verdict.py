import unittest
import shield
from scenario_engine import loader, explain
from scenario_engine.runner import attack_dict

SC = {s.id: s for s in loader.load_dir('scenario_engine/manifests')}

def run(i, protected, review=None):
    s = SC[i]
    r = shield.Runner().run(s.user_request, attack_dict(s), protected, 'offline', policy=shield.policy_from_scenario(s))
    return r, explain.explain_run(r)

class Verdict(unittest.TestCase):
    def test_contained_task_completed_names_source_detector_and_outcome(self):
        r, ex = run('proc-indirect-document', True)
        h = ex['verdict']['headline']
        self.assertEqual(ex['verdict']['class'], 'CONTAINED_TASK_COMPLETED')
        for part in ('ATTACK CONTAINED', 'quotes/beacon.txt', "detected by the content firewall's deterministic rules (", 'removed', 'no email, record write or confidential read occurred', 'the task completed'):
            self.assertIn(part, h)
        self.assertEqual(ex['summary'], h)
        self.assertTrue(ex['markdown'].startswith('### Verdict: ATTACK CONTAINED'))
        self.assertTrue(ex['text'].startswith('VERDICT: ATTACK CONTAINED'))

    def test_verdict_attributes_by_detector_and_never_invents_models(self):
        r, ex = run('proc-indirect-document', True)
        self.assertNotIn('ProtectAI', ex['verdict']['headline'])
        self.assertNotIn('LLM instruction classifier', ex['verdict']['headline'])
        self.assertIn('only the deterministic rules fired', ex['verdict']['detail'])

    def test_detector_attribution_names_models_that_fired(self):
        d = explain._detectors([{'rule': 'instruction override'}, {'rule': 'LLM instruction classifier'},
                                {'rule': 'local classifier', 'reason': 'ProtectAI deberta score 0.98 in view "raw"'}])
        self.assertEqual(d, 'the content firewall\'s deterministic rule ("instruction override"), the ProtectAI local classifier and the LLM instruction classifier')
        self.assertEqual(explain._detectors([{'rule': 'local classifier', 'reason': 'x score 0.9'}]), 'the local classifier')

    def test_run_that_never_scanned_content_does_not_claim_rules_raised_no_finding(self):
        r, _ = run('proc-benign-plain', True)
        r = dict(r); r['audit'] = [e for e in r['audit'] if e.get('stage') != 'content']
        h = explain.explain_run(r)['verdict']['headline']
        self.assertIn('NO content was scanned', h)
        self.assertNotIn('raised no finding', h)

    def test_action_guard_containment_names_layer_and_rule(self):
        _, ex = run('proc-firewall-miss', True)
        self.assertIn('action guard (resource_scope)', ex['verdict']['headline'])
        self.assertTrue(ex['verdict']['headline'].startswith('ATTACK CONTAINED'))

    def test_attack_succeeded_in_baseline_lane(self):
        _, ex = run('proc-scope-immunity', False)
        self.assertEqual(ex['verdict']['class'], 'ATTACK_SUCCEEDED')
        self.assertIn('no defence in this lane', ex['verdict']['headline'])
        self.assertIn('attacker@example.com', ex['verdict']['headline'])

    def test_task_blocked(self):
        _, ex = run('proc-wrong-recipient', True)
        self.assertEqual(ex['verdict']['class'], 'TASK_BLOCKED')
        self.assertIn('recipient_scope', ex['verdict']['headline'])

    def test_clean_task_completed(self):
        _, ex = run('proc-benign-plain', True)
        self.assertEqual(ex['verdict']['class'], 'TASK_COMPLETED')
        self.assertIn('no injected content was flagged', ex['verdict']['headline'])

    def test_human_escalation_is_not_called_a_block(self):
        _, ex = run('proc-benign-email', True)
        self.assertEqual(ex['verdict']['class'], 'WAITING_FOR_HUMAN')
        self.assertNotIn('BLOCK', ex['verdict']['headline'])

    def test_benign_baseline_email_is_not_called_an_attack(self):
        _, ex = run('proc-benign-email', False)
        self.assertEqual(ex['verdict']['class'], 'EFFECT_EXECUTED_NO_DEFENCE')
        self.assertNotIn('ATTACK SUCCEEDED', ex['verdict']['headline'])

    def test_request_guard_hold(self):
        ex = explain.explain_run(request_check={'flagged': True, 'findings': [{'rule': 'unauthorized disclosure instruction', 'encoding': 'raw / base64', 'snippet': 'x'}], 'message': 'm'})
        self.assertEqual(ex['verdict']['class'], 'HELD_BY_REQUEST_GUARD')
        self.assertIn('before anything ran', ex['verdict']['headline'])

    def test_old_summary_wording_is_gone(self):
        for i in ('proc-indirect-document', 'proc-benign-plain'):
            _, ex = run(i, True)
            self.assertNotIn('Not stopped', ex['summary'])
