"""Real mock executions across ablation modes; LLM requires explicit config."""
import argparse,json,hashlib,statistics,math
from pathlib import Path
from shield import Runner,ModelAdapter
from metrics import layer_summary

def wilson(success,n):
 if not n:return [None,None]
 z=1.96;p=success/n;d=1+z*z/n;c=(p+z*z/(2*n))/d;r=z*math.sqrt((p*(1-p)+z*z/(4*n))/n)/d
 return [max(0,c-r),min(1,c+r)]

def main():
 p=argparse.ArgumentParser();p.add_argument('--mode',choices=['offline','llm'],default='offline');p.add_argument('--repeats',type=int,default=1);a=p.parse_args()
 if not 1<=a.repeats<=5:raise ValueError('Repeat count must be 1-5')
 if a.mode=='llm' and not ModelAdapter().available:raise RuntimeError('Missing model configuration')
 attacks=[x for x in json.loads(Path('data/attacks.json').read_text()) if x['split']=='development']
 benign=json.loads(Path('data/benign-tasks.json').read_text());rows=[];rawdir=Path('artifacts/raw-ablation');rawdir.mkdir(parents=True,exist_ok=True)
 for defence in ['none','prompt','keyword','firewall','guard','full']:
  for case in attacks+benign:
   for repeat in range(a.repeats):
    try:r=Runner().run(request=case.get('request',__import__('shield').DEFAULT_REQUEST),attack=case,protected=defence!='none',mode=a.mode,defence=defence)
    except Exception as exc:
     error={'id':case['id'],'defence':defence,'repeat':repeat,'error':str(exc),'mode':a.mode}
     (rawdir/f'ERROR-{a.mode}-{defence}-{case["id"]}-{repeat}.json').write_text(json.dumps(error,indent=2))
     raise
    file=rawdir/f'{a.mode}-{defence}-{case["id"]}-{repeat}.json';file.write_text(json.dumps(r,indent=2))
    rows.append({'id':case['id'],'defence':defence,'repeat':repeat,'benign':case['category']=='benign','effect':r['attack_success'],'complete':r['task_complete'],'interventions':sum(x['decision'] in ['BLOCK','ASK HUMAN'] for x in r['audit'] if x['stage']=='action'),'elapsed_ms':r['elapsed_ms'],'timings':r['timings'],'artifact':str(file)})
 summary=[]
 for defence in ['none','prompt','keyword','firewall','guard','full']:
  selected=[r for r in rows if r['defence']==defence];bad=[r for r in selected if not r['benign']];normal=[r for r in selected if r['benign']]
  successful=sum(r['effect'] for r in bad)
  summary.append({'defence':defence,'attack_trials':len(bad),'attack_effects':successful,'attack_trial_wilson95':wilson(successful,len(bad)) if a.mode=='llm' else None,'benign_trials':len(normal),'benign_complete':sum(r['complete'] for r in normal),'benign_intervened_tasks':sum(r['interventions']>0 for r in normal),'utility_under_attack':sum(r['complete'] for r in bad),'latency_median_ms':statistics.median(r['elapsed_ms'] for r in selected),'layer_timings':layer_summary(selected)})
 report={'kind':'offline_ablation_verification' if a.mode=='offline' else 'llm_ablation_evaluation','split':'development','model':ModelAdapter().model if a.mode=='llm' else None,'repeats':a.repeats,'metrics':summary,'cases':rows,'corpus_sha256':hashlib.sha256(Path('data/attacks.json').read_bytes()).hexdigest(),'scope':'Offline attacks submit explicit proposals; firewall-only cannot prevent tool proposals already supplied by the probe. Prompt-only offline mode cannot measure language-model behavior. These are not LLM efficacy rates. 20 benign task-shaped cases use ten selection/comparison shapes and two text variants. Genuine answers require per-vendor structured facts plus blind review. Repeated model trials are correlated; trial-level intervals do not prove independent case-level generalization.'}
 Path(f'artifacts/{a.mode}-ablations-development.json').write_text(json.dumps(report,indent=2));print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
