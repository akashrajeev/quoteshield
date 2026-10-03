"""OpenAI-compatible request diagnostics. No credentials in error text or trace."""
import json,os,re,time,copy,math
from urllib.parse import urlsplit

def redact(text,key=''):
 text=str(text)
 for secret in [key,*[v for k,v in os.environ.items() if ('API_KEY' in k or k=='SHIELD_MODEL_KEY') and v]]:
  if secret:text=text.replace(secret,'[REDACTED]')
 text=re.sub(r'(?i)Bearer\s+\S+','Bearer [REDACTED]',text)
 text=re.sub(r'(?:sk-[A-Za-z0-9_-]{12,}|gsk_[A-Za-z0-9_-]{12,}|AIza[A-Za-z0-9_-]{20,}|nvapi-[A-Za-z0-9_-]{12,})','[REDACTED]',text)
 return text[:1800]

def endpoint_label(url):
 p=urlsplit(url);return p.hostname or 'unknown host'

def error_detail(response,key=''):
 try:
  data=response.json();error=data.get('error',data) if isinstance(data,dict) else {}
  if isinstance(error,dict):
   safe={k:error[k] for k in ['message','type','code','param','status'] if k in error}
   metadata=error.get('metadata',{})
   if isinstance(metadata,dict) and 'provider_name' in metadata:safe['provider_name']=metadata['provider_name']
   return redact(json.dumps(safe,ensure_ascii=False),key) or 'No structured provider error'
  return redact(error,key)
 except (ValueError,TypeError):return 'Provider returned a non-JSON error; raw body withheld'

def route_summary(trace):
 models=list(dict.fromkeys(t.get('response_model') for t in trace if t.get('response_model')))
 routes=list(dict.fromkeys(t.get('routed_via') for t in trace if t.get('routed_via')))
 observed=[t for t in trace if t.get('response_model') or t.get('routed_via')]
 return {'model_changed_within_run':len(models)>1 or len(routes)>1,'response_models':models,'routed_via':routes,'route_identity_incomplete':any(not t.get('response_model') and not t.get('routed_via') for t in trace),'observed_identity_attempts':len(observed),'total_attempts':len(trace)}

class ModelAdapter:
 def __init__(self):
  try:self.timeout_s=float(os.environ.get('SHIELD_MODEL_TIMEOUT_S','45'))
  except ValueError:raise ValueError('SHIELD_MODEL_TIMEOUT_S must be a positive finite number of seconds')
  if not math.isfinite(self.timeout_s) or self.timeout_s<=0:raise ValueError('SHIELD_MODEL_TIMEOUT_S must be a positive finite number of seconds')
  self.url=os.environ.get('SHIELD_MODEL_URL','');self.model=os.environ.get('SHIELD_MODEL_NAME','');self.key=os.environ.get('SHIELD_MODEL_KEY','');self.trace=[];self.calls=0;self.max_calls=64
 @property
 def available(self):return bool(self.url and self.model)
 def before_attempt(self):
  """Budget/pacing hook called before EVERY network attempt, including recovery."""
 def complete(self,messages,tools=None,json_output=False):
  import httpx
  if not self.available:raise RuntimeError('Configure SHIELD_MODEL_URL and SHIELD_MODEL_NAME for genuine model execution.')
  allowed={'role','content','name','tool_calls','tool_call_id','function_call','extra_content'}
  cleaned=[{k:v for k,v in m.items() if k in allowed} for m in messages]
  body={'model':self.model,'messages':cleaned,'temperature':0}
  parsed=urlsplit(self.url)
  if not parsed.path.endswith('/chat/completions'):raise RuntimeError('SHIELD_MODEL_URL must end in /chat/completions; BASE_URL should omit that suffix')
  if parsed.hostname=='generativelanguage.googleapis.com' and not parsed.path.startswith('/v1beta/openai/'):raise RuntimeError('Gemini OpenAI-compatible URL must use /v1beta/openai/chat/completions')
  if parsed.hostname=='api.groq.com' and not parsed.path.startswith('/openai/v1/'):raise RuntimeError('Groq OpenAI-compatible URL must use /openai/v1/chat/completions')
  local_ollama=parsed.scheme in ('http','https') and parsed.hostname in ('localhost','127.0.0.1','::1') and parsed.port==11434 and parsed.path=='/v1/chat/completions'
  if local_ollama and os.environ.get('SHIELD_OLLAMA_NO_THINK')=='1':body['reasoning_effort']='none'
  transport_meta={'endpoint':parsed.scheme+'://'+(parsed.hostname or '')+parsed.path,'auth_scheme':'Bearer' if self.key else 'none','auth_present':bool(self.key),'timeout_s':self.timeout_s}
  names=[]
  if tools:
   tools=copy.deepcopy(tools)
   for tool in tools:
    fn=tool.get('function',{})
    if tool.get('type')!='function' or not fn.get('name') or fn.get('parameters',{}).get('type')!='object':raise RuntimeError('Invalid OpenAI function tool schema')
    names.append(fn['name'])
   body['tools']=tools
   if not local_ollama:body['tool_choice']='auto'
   if parsed.hostname=='api.groq.com' and self.model.startswith('openai/gpt-oss-'):
    body['parallel_tool_calls']=False
  if local_ollama and not tools and json_output:body['response_format']={'type':'json_object'}
  if parsed.hostname=='api.groq.com' and not tools and json_output:
   body.update(tool_choice='none',response_format={'type':'json_object'})
  headers={'Content-Type':'application/json'}
  if self.key:headers['Authorization']='Bearer '+self.key
  for retry in range(3):
   if self.calls>=self.max_calls:raise RuntimeError('Model request budget exhausted')
   self.before_attempt();self.calls+=1;started=time.perf_counter()
   response_meta={'response_model':None,'routed_via':None}
   try:
    r=httpx.post(self.url,json=body,headers=headers,timeout=self.timeout_s)
    route=r.headers.get('X-Routed-Via')
    if route:response_meta['routed_via']=redact(route,self.key)[:256]
    if r.status_code>=400:
     detail=error_detail(r,self.key)
     recoverable=r.status_code==400 and ('tool_use_failed' in detail or ('tool' in detail.lower() and any(v in detail.lower() for v in ['not in request.tools','unknown tool','not a valid tool','invalid tool name'])))
     hint='Check provider model access and request schema.'
     if recoverable:hint='Provider rejected generated tool call; same-model correction attempted up to twice.'
     elif 'model' in detail.lower() and any(v in detail.lower() for v in ['not found','invalid','decommission','does not exist']):hint='Select an accessible same-provider model with --model after checking entitlement. Start a separate benchmark.'
     self.trace.append({**response_meta,'transport':transport_meta,'request':copy.deepcopy(body),'error':{'http_status':r.status_code,'detail':detail},'retry_count':retry,'recovery_policy':'same-model tool-error correction, maximum 2 retries','latency_ms':(time.perf_counter()-started)*1000})
     if recoverable and retry<2:
      note=('Valid function tools are: '+', '.join(names)+'. Do not invent or call json/python or any other tool. Return tool calls only using these names, or return the final answer as content.') if names else 'No tools are available in this request. Return the requested JSON as plain assistant content, not a json/python tool call.'
      body['messages']=cleaned+[{'role':'system','content':note}]
      continue
     raise RuntimeError(f"Model HTTP {r.status_code} at {transport_meta['endpoint']} | model={self.model} | {detail} | {hint} | retries={retry}; stopped")
    response=r.json()
    actual_model=response.get('model') if isinstance(response,dict) else None
    if isinstance(actual_model,str) and actual_model:response_meta['response_model']=redact(actual_model,self.key)[:256]
    message=response['choices'][0]['message']
    if not isinstance(message,dict):raise TypeError('Assistant message must be an object')
    self.trace.append({**response_meta,'transport':transport_meta,'request':copy.deepcopy(body),'response':response,'retry_count':retry,'recovery_policy':'same-model tool-error correction, maximum 2 retries','latency_ms':(time.perf_counter()-started)*1000});return message
   except (httpx.HTTPError,ValueError,KeyError,IndexError,TypeError) as exc:
    kind=type(exc).__name__;category='transport' if isinstance(exc,httpx.HTTPError) else 'response_schema'
    # Do not retain exception strings: they may contain credential-bearing URLs or raw bodies.
    self.trace.append({**response_meta,'transport':transport_meta,'request':copy.deepcopy(body),'error':{'category':category,'exception_type':kind,'cause_type':type(exc.__cause__).__name__ if exc.__cause__ else None,'detail':'Provider request failed before a validated assistant message was obtained.'},'retry_count':retry,'recovery_policy':'no retry for transport or response schema failure','latency_ms':(time.perf_counter()-started)*1000})
    raise RuntimeError('Model '+category+' failure ('+kind+'); no retry for this error. Inspect failed request trace.') from exc
 def json(self,system,value):
  content=self.complete([{'role':'system','content':system},{'role':'user','content':json.dumps(value)}],json_output=True)['content']
  try:
   try:parsed=json.loads(re.sub(r'^```(?:json)?\s*|\s*```$','',content.strip()))
   except ValueError:
    from jsonextract import extract_json_object
    parsed=extract_json_object(content)
    if parsed is None:raise
   if not isinstance(parsed,dict):raise RuntimeError('Model returned invalid structured JSON: expected an object; run stopped')
   return parsed
  except RuntimeError:raise
  except Exception as e:raise RuntimeError('Model returned invalid structured JSON') from e
