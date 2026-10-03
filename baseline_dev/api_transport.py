"""OpenAI-compatible request diagnostics. No credentials in error text or trace."""
import json,os,re,time,copy
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

class ModelAdapter:
 def __init__(self):
  self.url=os.environ.get('SHIELD_MODEL_URL','');self.model=os.environ.get('SHIELD_MODEL_NAME','');self.key=os.environ.get('SHIELD_MODEL_KEY','');self.trace=[];self.calls=0;self.max_calls=64
 @property
 def available(self):return bool(self.url and self.model)
 def complete(self,messages,tools=None):
  import httpx
  if not self.available:raise RuntimeError('Configure SHIELD_MODEL_URL and SHIELD_MODEL_NAME for genuine model execution.')
  if self.calls>=self.max_calls:raise RuntimeError('Model request budget exhausted')
  self.calls+=1
  # Keep provider extension data (Gemini thought signatures) but remove response-only
  # reasoning/refusal/annotations fields from replayed assistant messages.
  allowed={'role','content','name','tool_calls','tool_call_id','function_call','extra_content'}
  cleaned=[{k:v for k,v in m.items() if k in allowed} for m in messages]
  body={'model':self.model,'messages':cleaned,'temperature':0}
  parsed=urlsplit(self.url)
  if not parsed.path.endswith('/chat/completions'):raise RuntimeError('SHIELD_MODEL_URL must end in /chat/completions; BASE_URL should omit that suffix')
  if parsed.hostname=='generativelanguage.googleapis.com' and not parsed.path.startswith('/v1beta/openai/'):raise RuntimeError('Gemini OpenAI-compatible URL must use /v1beta/openai/chat/completions')
  if parsed.hostname=='api.groq.com' and not parsed.path.startswith('/openai/v1/'):raise RuntimeError('Groq OpenAI-compatible URL must use /openai/v1/chat/completions')
  if tools:
   tools=copy.deepcopy(tools)
   for tool in tools:
    fn=tool.get('function',{})
    if tool.get('type')!='function' or not fn.get('name') or fn.get('parameters',{}).get('type')!='object':raise RuntimeError('Invalid OpenAI function tool schema')
   body.update(tools=tools,tool_choice='auto')
  headers={'Content-Type':'application/json'}
  if self.key:headers['Authorization']='Bearer '+self.key
  started=time.perf_counter()
  try:
   r=httpx.post(self.url,json=body,headers=headers,timeout=45)
   if r.status_code>=400:
    detail=error_detail(r,self.key)
    hint='Check provider model access and request schema. No model substitution or retry.'
    if 'tool_use_failed' in detail:hint='Provider rejected the generated tool call. Inspect tool trace; this is a model output error, not evidence that the guard failed.'
    elif 'model' in detail.lower() and any(v in detail.lower() for v in ['not found','invalid','decommission','does not exist']):hint='Model ID rejected. Select an accessible model from this provider with --model; confirm free-tier or credit entitlement first. Do not mix models in one benchmark.'
    elif 'reasoning' in detail.lower():hint='Response-only reasoning fields are removed on replay; check custom model requirements.'
    self.trace.append({'request':body,'error':{'http_status':r.status_code,'detail':detail},'latency_ms':(time.perf_counter()-started)*1000})
    raise RuntimeError(f'Model HTTP {r.status_code} at {endpoint_label(self.url)} | model={self.model} | {detail} | {hint} | no automatic retry')
   response=r.json();message=response['choices'][0]['message']
   self.trace.append({'request':body,'response':response,'latency_ms':(time.perf_counter()-started)*1000});return message
  except (httpx.HTTPError,ValueError,KeyError,IndexError) as exc:raise RuntimeError('Model transport or response schema failed; no automatic retry') from exc
 def json(self,system,value):
  content=self.complete([{'role':'system','content':system},{'role':'user','content':json.dumps(value)}])['content']
  try:return json.loads(re.sub(r'^```(?:json)?\s*|\s*```$','',content.strip()))
  except Exception as e:raise RuntimeError('Model returned invalid structured JSON') from e
