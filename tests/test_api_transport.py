import os,json,unittest,httpx
from unittest.mock import patch
from api_transport import ModelAdapter,error_detail
class TransportTests(unittest.TestCase):
 def test_error_is_safe_and_in_trace(self):
  key='fixture-secret-value'
  with patch.dict(os.environ,{'SHIELD_MODEL_KEY':key,'SHIELD_MODEL_URL':'https://api.groq.com/openai/v1/chat/completions','SHIELD_MODEL_NAME':'fixture-model'}),patch('httpx.post',return_value=httpx.Response(400,json={'error':{'message':'Invalid tools '+key,'code':'tool_use_failed','failed_generation':key}})):
   m=ModelAdapter()
   with self.assertRaisesRegex(RuntimeError,'tool_use_failed') as e:m.complete([{'role':'user','content':'mock'}])
   self.assertNotIn(key,str(e.exception));self.assertNotIn(key,json.dumps(m.trace));self.assertEqual(m.trace[0]['error']['http_status'],400)
 def test_message_replay_strips_response_fields(self):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://example.test/v1/chat/completions','SHIELD_MODEL_NAME':'fixture'}),patch('httpx.post',return_value=httpx.Response(200,json={'choices':[{'message':{'role':'assistant','content':'ok'}}]})) as post:
   ModelAdapter().complete([{'role':'assistant','content':None,'reasoning':'private thinking','annotations':[],'extra_content':{'google':'signature'},'tool_calls':[]}])
   msg=post.call_args.kwargs['json']['messages'][0];self.assertNotIn('reasoning',msg);self.assertIn('extra_content',msg)
 def test_non_json_withheld(self):
  self.assertIn('withheld',error_detail(httpx.Response(400,text='secret text')))
 def test_four_provider_400s_preserved_no_retry(self):
  examples=[('https://api.groq.com/openai/v1/chat/completions','tool_use_failed'),('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions','INVALID_ARGUMENT'),('https://openrouter.ai/api/v1/chat/completions','No endpoints found supporting tool use'),('https://integrate.api.nvidia.com/v1/chat/completions','Model not found')]
  for url,error in examples:
   with self.subTest(url=url),patch.dict(os.environ,{'SHIELD_MODEL_URL':url,'SHIELD_MODEL_NAME':'fixture-model'}),patch('httpx.post',return_value=httpx.Response(400,json={'error':{'message':error}})) as post:
    with self.assertRaisesRegex(RuntimeError,error):ModelAdapter().complete([{'role':'user','content':'mock'}])
    self.assertEqual(post.call_count,1)
 def test_bad_known_provider_path_rejected_locally(self):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://api.groq.com/v1/chat/completions','SHIELD_MODEL_NAME':'fixture'}),patch('httpx.post') as post:
   with self.assertRaisesRegex(RuntimeError,'/openai/v1'):ModelAdapter().complete([])
   post.assert_not_called()
