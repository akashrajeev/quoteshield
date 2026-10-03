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
