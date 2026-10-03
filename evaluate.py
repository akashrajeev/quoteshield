"""Offline guard checks and optional genuine LLM benchmark, always kept separate."""
import argparse,hashlib,json,statistics,time
from pathlib import Path
from shield import paired,firewall,ModelAdapter
from metrics import layer_summary

def evaluate(mode='offline',split='development'):
 attacks=json.loads(Path('data/attacks.json').read_text());benign=json.loads(Path('data/benign.json').read_text())
 attacks=[x for x in attacks if split=='all' or x['split']==split]
 if mode=='llm' and not ModelAdapter().available:raise RuntimeError('No model configured; no baseline-hijack numbers will be fabricated.')
 results=[]
 rawdir=Path(f'artifacts/raw-{mode}-{split}');rawdir.mkdir(parents=True,exist_ok=True)
 for attack in attacks+benign:
  try:p=paired(attack,mode)
  except Exception as exc:
   (rawdir/f"ERROR-{attack['id']}.json").write_text(json.dumps({'id':attack['id'],'error':str(exc)},indent=2));raise
  (rawdir/f"{attack['id']}.json").write_text(json.dumps(p,indent=2))
  b=p['baseline'];s=p['protected'];is_benign=attack['id'].startswith('benign')
  actions=[a for a in s['audit'] if a['stage']=='action']
  results.append({'id':attack['id'],'category':attack.get('category','benign'),'split':attack.get('split','benign'),'baseline_effect':b['attack_success'],'protected_effect':s['attack_success'],'completion':s['task_complete'],'content_detection':bool(firewall(attack.get('payload','')+attack.get('tool_payload',''))['findings']),'false_positive_actions':sum(a['decision'] in ['BLOCK','ASK HUMAN'] for a in actions) if is_benign else 0,'benign_actions':len(actions) if is_benign else 0,'timings':s['timings'],'baseline_ms':b['elapsed_ms'],'protected_ms':s['elapsed_ms']})
 attack_rows=[r for r in results if r['category']!='benign'];normal=[r for r in results if r['category']=='benign']
 metrics={'attack_count':len(attack_rows),'benign_count':len(normal),'baseline_effect_count':sum(r['baseline_effect'] for r in attack_rows),'protected_effect_count':sum(r['protected_effect'] for r in attack_rows),'protected_completion_count':sum(r['completion'] for r in results),'content_detection_count':sum(r['content_detection'] for r in attack_rows),'false_positive_actions':sum(r['false_positive_actions'] for r in normal),'benign_actions':sum(r['benign_actions'] for r in normal)}
 timing=layer_summary(results)
 report={'kind':'offline_guard_verification' if mode=='offline' else 'llm_agent_evaluation','model':ModelAdapter().model if mode=='llm' else None,'split':split,'corpus_sha256':hashlib.sha256(Path('data/attacks.json').read_bytes()).hexdigest(),'metrics':metrics,'layer_timings':timing,'cases':results,'latency_definition':'Protection_total_ms sums measured scope/firewall/guard time, not the difference between unrelated generation lengths. p95 uses linear empirical interpolation. Cold/warm endpoint behavior not separated yet.','scope':'Real executions of in-memory mock tools. Offline tool-proposal checks are not baseline LLM hijack rates. Reserved set is author-generated, not independent.'}
 Path('artifacts').mkdir(exist_ok=True);out=Path(f'artifacts/{mode}-{split}.json');out.write_text(json.dumps(report,indent=2));print(json.dumps({'file':str(out),**metrics,'layer_timings':timing},indent=2));return report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--mode',choices=['offline','llm'],default='offline');p.add_argument('--split',choices=['development','reserved','all'],default='development');a=p.parse_args();evaluate(a.mode,a.split)
