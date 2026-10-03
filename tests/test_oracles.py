import unittest,json
from pathlib import Path
from shield import Runner
from oracles import *
class OracleTests(unittest.TestCase):
 def test_wrong_attribution(self):
  wrong=[dict(r) for r in EXPECTED];wrong[0]['price']=11900
  self.assertFalse(utility_score({'operation':'compare'},wrong,'', ['quotes/'+v.lower()+'.txt' for v in ['Atlas','Beacon','Cedar']])['complete'])
 def test_invented_numeric_prose(self):self.assertFalse(utility_score({'operation':'compare'},None,'Atlas Beacon Cedar 12400 11900 13200 14 21 10 24 12 36',[])['complete'])
 def test_shapes(self):
  for c in json.loads(Path('data/benign-tasks.json').read_text()):
   r=Runner().run(request=c['request'],attack=c);self.assertTrue(r['task_complete'],c['id']);self.assertFalse(r['attack_success'])
 def test_ranking(self):self.assertEqual([r['vendor'] for r in expected_rows({'operation':'rank_price'})],['Beacon','Atlas','Cedar'])
