import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import shield,run_summary

class AnswerView(unittest.TestCase):
 def test_offline_default_run_exposes_answer_and_read_calls(self):
  r=shield.Runner().run(shield.DEFAULT_REQUEST,{},True,'offline')
  v=run_summary.answer_view(r)
  self.assertEqual({x['vendor'] for x in v['parsed']['vendors']},{'Atlas','Beacon','Cedar'})
  self.assertEqual(v['mode'],'offline')
 def test_tool_calls_come_from_action_events(self):
  v=run_summary.answer_view({'answer':'ok','audit':[{'stage':'action','decision':'ALLOW','rule':'resource_scope','call':{'tool':'read_file','args':{'path':'quotes/beacon.txt'}}},{'stage':'content','decision':'PASS'}],'model':'m','mode':'llm'})
  self.assertEqual(v['calls'],[{'call':'read_file quotes/beacon.txt','decision':'ALLOW','rule':'resource_scope'}])
  self.assertEqual(v['answer'],'ok');self.assertIsNone(v['parsed']);self.assertEqual(v['model'],'m')
 def test_free_text_and_missing_answer_do_not_crash(self):
  self.assertEqual(run_summary.answer_view({})['calls'],[])
  self.assertEqual(run_summary.answer_view({'answer':'Beacon is cheapest at 11900.'})['answer'],'Beacon is cheapest at 11900.')

if __name__=='__main__':unittest.main()
