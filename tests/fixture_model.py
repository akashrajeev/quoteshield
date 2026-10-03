import json
from shield import QUOTES
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
