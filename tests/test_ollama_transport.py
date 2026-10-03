import os,unittest,httpx
from unittest.mock import patch
from api_transport import ModelAdapter
TOOLS=[{'type':'function','function':{'name':'read_file','parameters':{'type':'object'}}}]
class OllamaTests(unittest.TestCase):
 def body(self,url,flag='1',tools=TOOLS):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':url,'SHIELD_MODEL_NAME':'qwen3:4b','SHIELD_MODEL_KEY':'','SHIELD_OLLAMA_NO_THINK':flag}),patch('httpx.post',return_value=httpx.Response(200,json={'choices':[{'message':{'content':'{}'}}]})) as post:
   m=ModelAdapter();m.complete([],tools);b=post.call_args.kwargs['json'];self.assertEqual(b,m.trace[0]['request']);self.assertNotIn('Authorization',post.call_args.kwargs['headers']);return b
 def test_three_loopback_hosts(self):
  for host in ['localhost','127.0.0.1','[::1]']:
   b=self.body('http://'+host+':11434/v1/chat/completions');self.assertNotIn('tool_choice',b);self.assertEqual(b['reasoning_effort'],'none');self.assertEqual(b['tools'],TOOLS);self.assertNotIn('think',b)
 def test_no_tool_json(self):
  b=self.body('http://localhost:11434/v1/chat/completions',tools=None);self.assertNotIn('tools',b);self.assertEqual(b['reasoning_effort'],'none')
 def test_thinking_opt_in(self):self.assertNotIn('reasoning_effort',self.body('http://localhost:11434/v1/chat/completions',flag=''))
 def test_non_ollama_unchanged(self):
  for url in ['https://example.test/v1/chat/completions','http://localhost:8500/v1/chat/completions','http://localhost:11434/other/chat/completions','http://localhost.evil.example:11434/v1/chat/completions']:
   b=self.body(url);self.assertNotIn('reasoning_effort',b);self.assertEqual(b['tool_choice'],'auto')
if __name__=='__main__':unittest.main()

class OllamaJsonShapeTests(unittest.TestCase):
 def test_exact_qwen_scope_array_fails_closed_no_retry(self):
  from shield import Runner
  response={'choices':[{'message':{'role':'assistant','content':'[["read_file","quotes/atlas.txt"],["read_file","quotes/beacon.txt"],["read_file","quotes/cedar.txt"]]'}}]}
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'http://localhost:11434/v1/chat/completions','SHIELD_MODEL_NAME':'qwen2.5:3b','SHIELD_MODEL_KEY':''}),patch('httpx.post',return_value=httpx.Response(200,json=response)) as post:
   model=ModelAdapter()
   with self.assertRaisesRegex(RuntimeError,'expected an object'):Runner(model).run(mode='llm')
   self.assertEqual(post.call_count,1);body=post.call_args.kwargs['json'];self.assertEqual(body['response_format'],{'type':'json_object'});self.assertNotIn('tools',body);self.assertNotIn('tool_choice',body);self.assertEqual(len(model.trace),1)
 def test_scope_object_remains_intersected(self):
  import json
  from shield import scope_from_request,DEFAULT_REQUEST,QUOTES
  response={'choices':[{'message':{'content':json.dumps({'tools':['read_file','send_email'],'resources':list(QUOTES)+['confidential/ceiling.txt'],'recipients':['evil@example.test'],'record_keys':[],'web_urls':[]})}}]}
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'http://localhost:11434/v1/chat/completions','SHIELD_MODEL_NAME':'qwen2.5:3b','SHIELD_MODEL_KEY':''}),patch('httpx.post',return_value=httpx.Response(200,json=response)):
   scope=scope_from_request(DEFAULT_REQUEST,ModelAdapter());self.assertEqual(scope.tools,['read_file']);self.assertEqual(scope.resources,list(QUOTES));self.assertEqual(scope.recipients,[])
 def test_tool_calls_keep_json_string_arguments_and_no_response_format(self):
  response={'choices':[{'message':{'role':'assistant','content':'','tool_calls':[{'id':'call_1','type':'function','function':{'name':'read_file','arguments':'{"path":"quotes/atlas.txt"}'}}]}}]}
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'http://localhost:11434/v1/chat/completions','SHIELD_MODEL_NAME':'qwen2.5:3b','SHIELD_MODEL_KEY':''}),patch('httpx.post',return_value=httpx.Response(200,json=response)) as post:
   result=ModelAdapter().complete([],TOOLS);self.assertEqual(result,response['choices'][0]['message']);self.assertNotIn('response_format',post.call_args.kwargs['json'])
