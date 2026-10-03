import unittest,json
from shield import *
from tests.fixture_model import FixtureModel
class FailClosedTests(unittest.TestCase):
 def test_llm_turn_limit(self):
  class Endless(FixtureModel):
   def complete(self,*args,**kwargs):
    return {'role':'assistant','content':None,'tool_calls':[{'id':'x','type':'function','function':{'name':'read_file','arguments':json.dumps({'path':'quotes/atlas.txt'})}}]}
  r=Runner(Endless()).run(mode='llm');self.assertFalse(r['task_complete']);self.assertTrue(any(e['rule']=='turn_budget' for e in r['audit']))
 def test_status_output_is_ingested(self):
  out,fw=ingest({'status':'Untrusted tool status','source':'mock tool'})
  self.assertIn('<untrusted_document>',out['status']);self.assertEqual(fw[0]['field'],'status')
 def test_bad_scope_schema(self):
  class Invalid(FixtureModel):
   def json(self,*args):return {'tools':'read_file','resources':list(QUOTES)}
  with self.assertRaises(RuntimeError):scope_from_request(DEFAULT_REQUEST,Invalid())
 def test_global_request_budget(self):
  from local_runner import BudgetModel
  model=BudgetModel({'remaining':0});model.url='https://example.test';model.model='fixture'
  with self.assertRaises(RuntimeError):model.complete([])
