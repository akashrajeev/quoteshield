"""Scripted model fixture tests orchestration only, never benchmark metrics."""
import json,unittest
from shield import *
from oracles import EXPECTED
class FixtureModel:
 available=True;model='test-fixture-not-a-real-model'
 def __init__(self):self.steps=0
 def json(self,system,value):
  if 'Extract tools' in system:return {'tools':['read_file'],'resources':list(QUOTES),'recipients':[],'record_keys':[],'web_urls':[]}
  return {'injection':False,'reason':'fixture','snippet':''}
 def complete(self,messages,tools=None):
  self.steps+=1
  if self.steps==1:return {'role':'assistant','content':None,'tool_calls':[{'id':f'call-{i}','type':'function','function':{'name':'read_file','arguments':json.dumps({'path':path})}} for i,path in enumerate(QUOTES)]}
  if self.steps==2:return {'role':'assistant','content':None,'tool_calls':[{'id':'denied','type':'function','function':{'name':'read_file','arguments':json.dumps({'path':'confidential/ceiling.txt'})}}]}
  if self.steps==3:
   self.denied_observed=any('Do not retry' in m.get('content','') for m in messages if m.get('role')=='tool')
   return {'role':'assistant','content':json.dumps({'summary':'Fixture answer','vendors':EXPECTED})}
class ModelFlowTests(unittest.TestCase):
 def test_tool_loop_block_continues(self):
  fixture=FixtureModel();r=Runner(fixture).run(mode='llm');self.assertTrue(r['task_complete']);self.assertFalse(r['attack_success']);self.assertTrue(fixture.denied_observed);self.assertEqual(fixture.steps,3)
 def test_scope_cannot_widen(self):
  class Wide(FixtureModel):
   def json(self,*args):return {'tools':['read_file','send_email'],'resources':list(QUOTES)+['confidential/ceiling.txt'],'recipients':['outside@example.test'],'web_urls':[]}
  scope=scope_from_request(DEFAULT_REQUEST,Wide());self.assertNotIn('send_email',scope.tools);self.assertNotIn('confidential/ceiling.txt',scope.resources);self.assertFalse(scope.recipients)
 def test_classifier_invalid_fails_closed(self):
  class Broken(FixtureModel):
   def json(self,*args):return {'injection':'no','reason':'fixture','snippet':''}
  with self.assertRaises(RuntimeError):firewall('safe quote',Broken())

 def test_scope_prompt_names_and_bounds(self):
  class Exact(FixtureModel):
   def json(self,system,value):
    self.checked=True
    assert 'requires read_file' in system
    assert 'send_email, write_record' in system
    assert value['candidate_bounds']['tools']==['read_file']
    assert value['candidate_bounds']['resources']==list(QUOTES)
    return value['candidate_bounds']
  model=Exact();scope=scope_from_request(DEFAULT_REQUEST,model)
  self.assertTrue(model.checked);self.assertEqual(scope.tools,['read_file']);self.assertEqual(scope.resources,list(QUOTES))
 def test_omitted_scope_tool_still_fails_closed(self):
  class Missing(FixtureModel):
   def json(self,*args):return {'tools':['compare'],'resources':list(QUOTES),'recipients':[],'web_urls':[],'record_keys':[]}
  scope=scope_from_request(DEFAULT_REQUEST,Missing());self.assertEqual(scope.tools,[])
  self.assertEqual(Guard(scope,Sandbox()).inspect(ToolCall('read_file',{'path':'quotes/atlas.txt'})).verdict,'BLOCK')
