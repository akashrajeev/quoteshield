"""One-command operator runner. Secrets are process-local, outputs are shareable."""
import argparse,getpass,hashlib,json,os,sys,time,zipfile
from pathlib import Path
from datetime import datetime,timezone
from shield import Runner,ModelAdapter,DEFAULT_REQUEST
from provider_config import PRESETS,load_local_env,configure
class BudgetModel(ModelAdapter):
 def __init__(self,budget):super().__init__();self.budget=budget
 def before_attempt(self):
  if self.budget['remaining']<=0:raise RuntimeError('Operator request limit reached. Partial results retained, no retries.')
  self.budget['remaining']-=1

def run_suite(provider,output,max_requests=20,case_limit=2,model_factory=None):
 root=Path(__file__).parent
 output=Path(output);output.mkdir(parents=True,exist_ok=False)
 budget={'remaining':max_requests};results=[]
 cases=[c for c in json.loads((root/'data/attacks.json').read_text()) if c['split']=='development'][:case_limit]
 cases+=json.loads((root/'data/benign-tasks.json').read_text())[:case_limit]
 manifest={'kind':'fixture_orchestration_check' if provider=='fixture' else 'real_model_development_subset','provider':provider,'model':os.environ.get('SHIELD_MODEL_NAME'),'max_requests':max_requests,'case_limit_per_group':case_limit,'corpus_sha256':hashlib.sha256((root/'data/attacks.json').read_bytes()).hexdigest(),'sealed_heldout_opened':False}
 (output/'run-config.json').write_text(json.dumps(manifest,indent=2))
 stopped=False
 for case in cases:
  lanes={}
  for lane,protected in [('baseline',False),('protected',True)]:
   model=model_factory() if model_factory else BudgetModel(budget)
   try:
    r=Runner(model).run(request=case.get('request',DEFAULT_REQUEST),attack=case,protected=protected,mode='llm')
    lanes[lane]={'task_complete':r['task_complete'],'attack_success':r['attack_success'],'elapsed_ms':r['elapsed_ms']}
    if provider=='fixture':r['mode']='scripted_fixture';r['benchmark_claim']=False
    (output/f"{case['id']}-{lane}.json").write_text(json.dumps(r,indent=2))
   except Exception as exc:
    # Do not include provider bodies/headers/credentials in error artifacts.
    error={'id':case['id'],'lane':lane,'status':'unverified_error','error_type':type(exc).__name__,'model_trace':getattr(model,'trace',[]),'safe_message':str(exc) if isinstance(exc,RuntimeError) else 'Unexpected execution failure; inspect locally.'}
    (output/f"{case['id']}-{lane}-ERROR.json").write_text(json.dumps(error,indent=2));lanes[lane]=error;stopped=True;break
  results.append({'id':case['id'],'category':case['category'],'lanes':lanes})
  if stopped:break
 report={'config':manifest,'cases':results,'stopped_early':stopped,'requests_used':max_requests-budget['remaining'] if provider!='fixture' else None,'scope':'Development subset, not full PS benchmark. Errors are not passes. Fixture mode checks orchestration only. No held-out payloads opened.'}
 (output/'summary.json').write_text(json.dumps(report,indent=2))
 (output/'README.txt').write_text('Send the adjacent ZIP back for analysis. Raw run artifacts contain only synthetic tasks/data and model outputs. No key or Authorization header is saved. Development subset only; no held-out evaluation or freeze. Never include a .env file.\n')
 archive=output.with_suffix('.zip')
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
  for f in output.iterdir():z.write(f,output.name+'/'+f.name)
 return report,archive

def main():
 if "--lane" in sys.argv:
  load_local_env()
  import runpy
  base=Path(__file__).parent/"baseline_dev"
  sys.path.insert(0,str(base))
  runpy.run_path(str(base/"local_runner.py"),run_name="__main__")
  return
 p=argparse.ArgumentParser(description='Local development subset runner. Four OpenAI-compatible providers, .env or hidden key prompt.')
 p.add_argument('--provider',choices=[*PRESETS,'fixture']);p.add_argument('--model');p.add_argument('--max-requests',type=int,default=20);p.add_argument('--case-limit',type=int,default=2);p.add_argument('--output');p.add_argument('--rpm',type=float,default=2,help='Maximum request pace; use a value within your provider limit')
 a=p.parse_args();load_local_env();a.provider=a.provider or os.environ.get("SHIELD_PROVIDER","groq")
 if a.provider not in [*PRESETS,"fixture"]:p.error("Unknown SHIELD_PROVIDER")
 if not 1<=a.max_requests<=1000 or not 1<=a.case_limit<=20 or not 0<a.rpm<=60:p.error('Invalid budget, case count or rate')
 folder=a.output or 'results-'+a.provider+'-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
 if a.provider=='fixture':
  # Scripted fixture is imported only for local test verification.
  from tests.fixture_model import FixtureModel
  report,archive=run_suite('fixture',folder,a.max_requests,a.case_limit,FixtureModel)
 else:
  cfg,key=configure(a.provider,a.model)
  if not key and not sys.stdin.isatty():raise RuntimeError('Set your provider key in local .env or use an interactive hidden prompt; do not pipe a key')
  print('Use a free-tier-only project or an approved paid limit. Mock prompts leave this machine. No retry after quota/error. Preset model must be accessible to your key.')
  key=key or getpass.getpass(a.provider.title()+' API key (hidden, not saved): ')
  if not key:raise ValueError('No key entered')
  os.environ['SHIELD_MODEL_KEY']=key
  try:
   # Validate model access without printing the key or provider error body.
   import httpx
   try:response=httpx.get(os.environ['SHIELD_MODEL_URL'].rsplit('/',1)[0]+'/models',headers={'Authorization':'Bearer '+key},timeout=20)
   except httpx.HTTPError:raise RuntimeError('Model-list transport failed; stopped without printing credentials') from None
   if response.status_code!=200:raise RuntimeError(f'Model-list validation returned HTTP {response.status_code}; stopped')
   ids={m['id'] for m in response.json().get('data',[])}
   if os.environ['SHIELD_MODEL_NAME'] not in ids:raise RuntimeError('Preset model is unavailable to this key; select an available model with --model')
   last=[0.0]
   class Paced(BudgetModel):
    def before_attempt(self):
     delay=60/a.rpm-(time.monotonic()-last[0])
     if delay>0:time.sleep(delay)
     last[0]=time.monotonic();return super().before_attempt()
   shared={'remaining':a.max_requests}
   # Shared counter is global across all baseline/protected runs.
   report,archive=run_suite(a.provider,folder,a.max_requests,a.case_limit,lambda:Paced(shared))
   report['requests_used']=a.max_requests-shared['remaining']
   # Rewrite count and repack, never include credentials.
   (Path(folder)/'summary.json').write_text(json.dumps(report,indent=2))
   with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for f in Path(folder).iterdir():z.write(f,Path(folder).name+'/'+f.name)
  finally:os.environ.pop('SHIELD_MODEL_KEY',None)
 print('Results folder:',folder);print('Return ZIP:',archive);print('Stopped early:',report['stopped_early'])
if __name__=='__main__':main()
