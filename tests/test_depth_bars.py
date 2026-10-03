import unittest
import scenarios, trace_ui

class DepthBars(unittest.TestCase):
 def setUp(self):
  self.items=[(s['title'],scenarios.run(n)[0]) for n,s in scenarios.SCENARIOS.items()]
  self.lines=trace_ui.depth_bars(self.items).split('\n')
 def test_no_title_is_truncated(self):
  for (title,_t),line in zip(self.items,self.lines): self.assertTrue(line.startswith(title))
 def test_waiting_run_is_labelled_and_stops_at_human_stage(self):
  line=[l for l,(n,_t) in zip(self.lines,self.items) if 'a person approves' in n][0]
  self.assertIn('waiting for a person',line); self.assertNotIn('not stopped',line); self.assertIn('########..',line)
 def test_finished_run_is_not_stopped(self):
  self.assertIn('not stopped',[l for l,(n,_t) in zip(self.lines,self.items) if n.startswith('Legitimate task: allowed')][0])
if __name__=='__main__': unittest.main()
