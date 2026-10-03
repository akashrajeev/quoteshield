"""Single-pass sealed-corpus evaluator. Invoke only AFTER explicit freeze."""
import argparse,hashlib,json
from pathlib import Path
from shield import Runner,ModelAdapter
from freeze import snapshot
from control_adapters import review_email,score_control
from benign_adapter import exact_effect_review,evaluate_control

def main():
 p=argparse.ArgumentParser();p.add_argument('--suite',choices=['adith','abindas'],required=True);p.add_argument('--cases',required=True);p.add_argument('--sha256',required=True);p.add_argument('--control-map',required=True,help='JSON mapping of control case IDs to adapter kinds, fixed before payload receipt');p.add_argument('--freeze',default='artifacts/freeze-model.json');a=p.parse_args()
 if not ModelAdapter().available:raise RuntimeError('Real model required; no offline substitute for sealed evaluation')
 frozen=json.loads(Path(a.freeze).read_text());current=snapshot(control_map=a.control_map)
 if current['freeze_sha256']!=frozen['freeze_sha256']:raise RuntimeError('Defence/model/config changed after freeze')
 blob=Path(a.cases).read_bytes()
 if hashlib.sha256(blob).hexdigest()!=a.sha256:raise RuntimeError('Sealed corpus checksum mismatch')
 mapping_path=Path(a.control_map)
 if hashlib.sha256(mapping_path.read_bytes()).hexdigest()!=frozen.get('control_map_sha256'):raise RuntimeError('Control map must be included in the pre-payload freeze manifest')
 mapping=json.loads(mapping_path.read_text());cases=json.loads(blob)
 if not isinstance(cases,list):raise ValueError('Cases must be a JSON array')
 if len({c['id'] for c in cases})!=len(cases):raise ValueError('Duplicate case IDs')
 out=Path('artifacts/held-out-'+a.suite+'-'+a.sha256[:12]);out.mkdir(parents=True,exist_ok=True);lock=out/'RUN_STARTED'
 # Exclusive marker prevents a second pass even after interruption.
 with lock.open('x') as f:f.write(frozen['freeze_sha256'])
 rows=[]
 for case in cases:
  facts=case.get('utility_oracle',{}).get('expected_facts',{})
  kind=mapping.get(a.suite+'/'+case['id']);request=case['request']
  # Utility normalization is an evaluator annotation only, not a policy change.
  case={**case,'suite':a.suite}
  if 'task_spec' not in case:
   vendors=list(facts) if facts else ['Atlas','Beacon','Cedar']
   case['task_spec']={'operation':'compare','vendors':vendors}
  lanes={}
  for defence in ['none','full']:
   try:
    reviewer=(lambda call:review_email(call,facts)) if kind=='legitimate_email' and defence=='full' else None
    if a.suite=='abindas' and case.get('expected_review')=='required' and defence=='full':reviewer=lambda call:exact_effect_review(call,case.get('permitted_effects',{}),facts)
    r=Runner().run(request=request,attack=case,protected=defence=='full',mode='llm',defence=defence,reviewer=reviewer)
    if kind:r['control_oracle']=score_control(kind,r,facts)
    if a.suite=='abindas':r['benign_suite_oracle']=evaluate_control(r,case)
    r['expected_test_contract']={k:case.get(k) for k in ['utility_oracle','security_oracle','expected_review','permitted_effects','shape']}
    lanes[defence]=r
    (out/f"{case['id']}-{defence}.json").write_text(json.dumps(r,indent=2))
   except Exception as exc:
    error={'id':case['id'],'defence':defence,'error':str(exc),'status':'unverified, not a pass'}
    lanes[defence]=error;(out/f"{case['id']}-{defence}-ERROR.json").write_text(json.dumps(error,indent=2))
  rows.append({'suite':a.suite,'id':case['id'],'category':case.get('category'),'control_kind':kind,'lanes':lanes})
 report={'suite':a.suite,'kind':'llm_held_out_single_pass','corpus_sha256':a.sha256,'freeze_sha256':frozen['freeze_sha256'],'cases':rows,'scope':'One pass after freeze. Errors preserved, no retries or tuning. Independent authorship requires the collaborator record; checksum alone does not prove it. Control fact attribution and ambiguous prose need blind correctness review.'}
 (out/'report.json').write_text(json.dumps(report,indent=2));(out/'RUN_FINISHED').write_text('complete');print(str(out/'report.json'))
if __name__=='__main__':main()
