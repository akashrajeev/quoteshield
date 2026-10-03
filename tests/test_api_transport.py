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
    self.assertEqual(post.call_count,3 if error=="tool_use_failed" else 1)
 def test_bad_known_provider_path_rejected_locally(self):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://api.groq.com/v1/chat/completions','SHIELD_MODEL_NAME':'fixture'}),patch('httpx.post') as post:
   with self.assertRaisesRegex(RuntimeError,'/openai/v1'):ModelAdapter().complete([])
   post.assert_not_called()
 def test_tool_retry_recovers_same_model_and_counts_attempts(self):
  from local_runner import BudgetModel
  responses=[httpx.Response(400,json={'error':{'code':'tool_use_failed','message':"attempted tool json not in request.tools"}}),httpx.Response(200,json={'choices':[{'message':{'role':'assistant','content':'ok'}}]})]
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://api.groq.com/openai/v1/chat/completions','SHIELD_MODEL_NAME':'fixture'}),patch('httpx.post',side_effect=responses) as post:
   budget={'remaining':3};m=BudgetModel(budget);m.complete([{'role':'user','content':'test'}],[{'type':'function','function':{'name':'read_file','parameters':{'type':'object'}}}])
   self.assertEqual(budget['remaining'],1);self.assertEqual(len(m.trace),2);self.assertEqual(m.trace[-1]['retry_count'],1);self.assertIn('read_file',post.call_args.kwargs['json']['messages'][-1]['content']);self.assertEqual(post.call_args.kwargs['json']['model'],'fixture')
 def test_retry_cannot_exceed_global_budget(self):
  from local_runner import BudgetModel
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://api.groq.com/openai/v1/chat/completions','SHIELD_MODEL_NAME':'fixture'}),patch('httpx.post',return_value=httpx.Response(400,json={'error':{'code':'tool_use_failed'}})) as post:
   with self.assertRaisesRegex(RuntimeError,'request limit'):BudgetModel({'remaining':1}).complete([])
   self.assertEqual(post.call_count,1)

 def test_groq_json_only_explicit_none_and_json_object(self):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://api.groq.com/openai/v1/chat/completions','SHIELD_MODEL_NAME':'openai/gpt-oss-120b'}),patch('httpx.post',return_value=httpx.Response(200,json={'choices':[{'message':{'role':'assistant','content':'{}'}}]})) as post:
   m=ModelAdapter();self.assertEqual(m.json('JSON only',{}),{})
   body=post.call_args.kwargs['json'];self.assertEqual(body['tool_choice'],'none');self.assertEqual(body['response_format'],{'type':'json_object'});self.assertNotIn('tools',body)
 def test_groq_tools_never_receive_response_format(self):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://api.groq.com/openai/v1/chat/completions','SHIELD_MODEL_NAME':'openai/gpt-oss-120b'}),patch('httpx.post',return_value=httpx.Response(200,json={'choices':[{'message':{'role':'assistant','content':'ok'}}]})) as post:
   ModelAdapter().complete([], [{'type':'function','function':{'name':'read_file','parameters':{'type':'object'}}}],json_output=True)
   body=post.call_args.kwargs['json'];self.assertEqual(body['tool_choice'],'auto');self.assertNotIn('response_format',body);self.assertFalse(body['parallel_tool_calls'])

 def test_trace_endpoint_never_contains_credentials_or_query(self):
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'https://name:password@example.test/v1/chat/completions?key=secret','SHIELD_MODEL_NAME':'fixture','SHIELD_MODEL_KEY':'hidden-key'}),patch('httpx.post',return_value=httpx.Response(404,json={})):
   m=ModelAdapter()
   with self.assertRaises(RuntimeError):m.complete([])
   self.assertEqual(m.trace[0]['transport']['endpoint'],'https://example.test/v1/chat/completions')
   self.assertEqual(m.trace[0]['transport']['auth_scheme'],'Bearer');self.assertTrue(m.trace[0]['transport']['auth_present'])
   self.assertNotIn('hidden-key',json.dumps(m.trace));self.assertNotIn('password',json.dumps(m.trace))

class FailedAttemptDiagnosticsTests(unittest.TestCase):
 def test_transport_type_and_failing_request_recorded_without_secret_url(self):
  secret='fixture-secret'
  with patch.dict(os.environ,{'SHIELD_MODEL_URL':'http://localhost:11434/v1/chat/completions?key='+secret,'SHIELD_MODEL_NAME':'qwen2.5:3b','SHIELD_MODEL_KEY':secret}),patch('httpx.post',side_effect=httpx.ReadTimeout('credential URL '+secret)) as post:
   m=ModelAdapter()
   with self.assertRaisesRegex(RuntimeError,'ReadTimeout') as cm:m.complete([{'role':'user','content':'fixture task'}])
   self.assertEqual(post.call_count,1);self.assertEqual(len(m.trace),1);self.assertEqual(m.trace[0]['error']['category'],'transport');self.assertEqual(m.trace[0]['error']['exception_type'],'ReadTimeout');self.assertEqual(m.trace[0]['request']['messages'][0]['content'],'fixture task');self.assertNotIn(secret,json.dumps(m.trace));self.assertNotIn(secret,str(cm.exception));self.assertEqual(post.call_args.kwargs['timeout'],45)
 def test_invalid_provider_json_and_missing_message_shapes_recorded(self):
  cases=[(httpx.Response(200,text='secret raw non-json'),'JSONDecodeError'),(httpx.Response(200,json={'choices':[]}), 'IndexError'),(httpx.Response(200,json={'choices':[{}]}),'KeyError'),(httpx.Response(200,json={'choices':[{'message':[]}]}),'TypeError')]
  for response,kind in cases:
   with self.subTest(kind=kind),patch.dict(os.environ,{'SHIELD_MODEL_URL':'http://localhost:11434/v1/chat/completions','SHIELD_MODEL_NAME':'fixture','SHIELD_MODEL_KEY':''}),patch('httpx.post',return_value=response) as post:
    m=ModelAdapter()
    with self.assertRaisesRegex(RuntimeError,kind):m.complete([])
    self.assertEqual(post.call_count,1);self.assertEqual(m.trace[0]['error']['category'],'response_schema');self.assertEqual(m.trace[0]['error']['exception_type'],kind);self.assertNotIn('secret raw',json.dumps(m.trace))
