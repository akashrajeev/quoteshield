import unittest
from pathlib import Path
import live_progress as lp
from scenario_engine import loader
from scenario_engine.runner import run_scenario

MAN = Path(__file__).resolve().parent.parent / 'scenario_engine' / 'manifests' / 'procurement'

class LiveProgress(unittest.TestCase):
    def result(self, name, **kw):
        _t, r = run_scenario(loader.load_manifest(MAN / (name + '.json')), **kw)
        return r

    def test_stages_light_up_in_event_order_and_end_matches_trace(self):
        r = self.result('confidential-flow')
        p = lp.LaneProgress('protected')
        self.assertIsNone(p.running())                          # lane not started: nothing shows running
        p.started = True
        self.assertEqual(p.running(), 'prompt_guard')           # nothing observed yet: first layer is next
        seen = []
        for e in r['audit']:
            p.on_event(e)
            seen.append(p.running())
        self.assertEqual(p.status['taint'], 'BLOCK')
        final = lp.final_statuses(r)
        for stage, st in p.status.items():                       # every layer that produced a live event agrees with the trace
            if st is not None:
                self.assertEqual(final[stage], st, stage)
        p.finish(r)
        self.assertIsNone(p.running())
        self.assertEqual(p.status, final)

    def test_baseline_marks_inactive_layers(self):
        r = {**self.result('confidential-flow'), 'defence': 'none'}
        f = lp.final_statuses(r)
        for k in ('content_firewall', 'action_guard', 'taint', 'human'):
            self.assertEqual(f[k], 'NOT_ACTIVE')
        p = lp.LaneProgress('baseline', protected=False); p.finish(r)
        self.assertNotIn('pending', lp.render(p, 'Baseline lane'))

    def test_render_has_all_ten_layers_in_order(self):
        p = lp.LaneProgress('protected'); p.started = True
        h = lp.render(p, 'Protected lane')
        pos = [h.index('>L%d<' % i) for i in range(10)]
        self.assertEqual(pos, sorted(pos))
        self.assertIn('running...', h)

    def test_render_escapes(self):
        p = lp.LaneProgress('x'); self.assertNotIn('<script', lp.render(p, '<script>'))

if __name__ == '__main__':
    unittest.main()
