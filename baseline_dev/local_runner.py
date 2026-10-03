"""Unprotected DEV baseline only. No defence imports or sealed input support."""
import argparse,getpass,json,os,sys,time,hashlib,zipfile
from pathlib import Path
import httpx
from baseline_agent import ModelAdapter,run,QUOTES,TOOLS,SYSTEM,DEFAULT_REQUEST
from provider_config import PRESETS,load_local_env,configure

def main():
 p=argparse.ArgumentParser();p.add_argument('--lane',choices=['baseline'],default='baseline');p.add_argument('--suite',choices=['dev-attacks'],default='dev-attacks');p.add_argument('--provider',choices=[*PRESETS,'fixture'],required=True);p.add_argument('--model');p.add_argument('--max-requests',type=int,default=160);p.add_argument('--rpm',type=float,default=2);p.add_argument('--output');p.add_argument('--resume');p.add_argument('--repeats',type=int,choices=[1,3],default=1);a=p.parse_args()
 if not 1<=a.max_requests<=1000 or not 0<a.rpm<=60:p.error('Invalid request/rate bounds')
 if a.output and a.resume:p.error('Choose --output or --resume')
 root=Path(__file__).parent;blob=(root/'data/development.json').read_bytes();cases=json.loads(blob);load_local_env();key='';used=[0];last=[0.0]
 if a.provider!='fixture':cfg,key=configure(a.provider,a.model)
 model_name='scripted-fixture-not-llm' if a.provider=='fixture' else os.environ['SHIELD_MODEL_NAME']
 code_hash=hashlib.sha256(b''.join((root/n).read_bytes() for n in ['baseline_agent.py','local_runner.py','provider_config.py','api_transport.py'])).hexdigest()
 config={'kind':'scripted_fixture_only' if a.provider=='fixture' else 'real_llm_unprotected_dev_only','lane':'baseline','suite':'dev-attacks','provider':a.provider,'model':model_name,'endpoint':os.environ.get('SHIELD_MODEL_URL','') if a.provider!='fixture' else '', 'temperature':0,'seed':None,'tool_error_recovery_max_retries':2,'repeats':a.repeats,'corpus_sha256':hashlib.sha256(blob).hexdigest(),'code_sha256':code_hash,'system_prompt':SYSTEM,'user_prompt':DEFAULT_REQUEST,'tool_schema':TOOLS,'case_ids':[c['id'] for c in cases],'turn_limit':16,'sealed_opened':False}
 config_digest=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest();out=Path(a.resume or a.output or 'baseline-results-'+time.strftime('%Y%m%d-%H%M%S'))
 if a.resume:
  old=json.loads((out/'run-config.json').read_text())
  if old['config_sha256']!=config_digest:raise RuntimeError('Resume config/code/corpus differs; no cases executed')
 else:
  out.mkdir(parents=True,exist_ok=False);(out/'run-config.json').write_text(json.dumps({**config,'config_sha256':config_digest},indent=2))
 lock=out/'RUNNING'
 with lock.open('x') as f:f.write('Do not delete until the prior process is confirmed stopped; interruption may have made provider calls.')
 try:
  if a.provider!='fixture':
   if not key:
    if not sys.stdin.isatty():raise RuntimeError('Set local .env key or use interactive hidden prompt')
    key=getpass.getpass('Provider key (hidden): ')
   if not key:raise ValueError('Missing key')
   os.environ['SHIELD_MODEL_KEY']=key
   print('Remote mock prompts leave your machine. Verify billing/credits. No retries, paid fallback or sealed input.')
   r=httpx.get(os.environ['SHIELD_MODEL_URL'].rsplit('/',1)[0]+'/models',headers={'Authorization':'Bearer '+key},timeout=20)
   if r.status_code!=200:raise RuntimeError('Model-list HTTP '+str(r.status_code))
   if model_name not in {m['id'] for m in r.json().get('data',[])}:raise RuntimeError('Model not listed; choose --model explicitly')
  class Paced(ModelAdapter):
   def before_attempt(self):
    if used[0]>=a.max_requests:raise RuntimeError('Global request cap exhausted')
    delay=60/a.rpm-(time.monotonic()-last[0])
    if delay>0:time.sleep(delay)
    last[0]=time.monotonic();used[0]+=1
  class Fixture:
   model='scripted-fixture-not-llm'
   def __init__(self):self.trace=[];self.n=0
   def complete(self,messages,tools):
    self.n+=1
    msg={'role':'assistant','content':json.dumps({'summary':'Fixture only'})} if self.n>1 else {'role':'assistant','content':None,'tool_calls':[{'id':str(i),'type':'function','function':{'name':'read_file','arguments':json.dumps({'path':v})}} for i,v in enumerate(QUOTES)]}
    self.trace.append({'request':{'messages':messages,'tools':tools},'response':msg,'latency_ms':0});return msg
  stopped=False
  for repeat in range(1,a.repeats+1):
   for case in cases:
    path=out/f"{case['id']}-r{repeat}.json"
    if path.exists():continue # completed and error cases both retained; no automatic rerun
    model=Fixture() if a.provider=='fixture' else Paced();tick=time.perf_counter()
    try:
     result=run(case,model)
     if 'error' in result:stopped=True
    except Exception as e:result={'id':case['id'],'category':case['category'],'error':type(e).__name__+': '+str(e),'status':'error, not a pass','model_trace':model.trace,'elapsed_ms':(time.perf_counter()-tick)*1000};stopped=True
    result['repeat']=repeat;result['model']=model_name;result['temperature']=0;result['model_call_ms']=sum(t.get('latency_ms',0) for t in model.trace);result['provider_usage']=[t.get('response',{}).get('usage') for t in model.trace] # absent usage stays null
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(result,indent=2));temp.replace(path)
    if stopped:break
   if stopped:break
  rows=[json.loads(p.read_text()) for p in sorted(out.glob('*-r*.json'))];errors=[r for r in rows if 'error' in r];valid=[r for r in rows if 'error' not in r];expected=len(cases)*a.repeats
  summary={'config':config,'cases':rows,'requests_this_invocation':used[0],'stopped_early':stopped,'expected_cases':expected,'valid_cases':len(valid),'error_cases':len(errors),'missing_cases':expected-len(rows),'full_denominator_ready':len(valid)==expected,'attack_success_count_valid':sum(r['attack_success'] for r in valid),'rate':sum(r['attack_success'] for r in valid)/expected if len(valid)==expected else None,'resume_semantics':'skip existing completed/error files; process only never-recorded cases; same code/model/corpus/repeats required; request cap resets per invocation; no hidden retry'}
  (out/'summary.json').write_text(json.dumps(summary,indent=2))
  with zipfile.ZipFile(str(out)+'.zip','w',zipfile.ZIP_DEFLATED) as z:
   for f in out.iterdir():
    if f.name!='RUNNING':z.write(f,out.name+'/'+f.name)
  print('Return ZIP:',str(out)+'.zip')
 finally:os.environ.pop('SHIELD_MODEL_KEY',None);lock.unlink(missing_ok=True)
if __name__=='__main__':main()
