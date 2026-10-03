"""Produce an exact local build/config freeze; no git/repo required."""
from pathlib import Path
import hashlib,json,sys,platform
from importlib.metadata import version
from shield import ModelAdapter
FILES=['benign_adapter.py','freeze.py','formats.py','metrics.py','shield.py','security.py','oracles.py','approval.py','control_adapters.py','ablate.py','evaluate.py','heldout.py','requirements.txt','streamlit_app.py','local_runner.py','data/heldout-control-map.json','data/heldout-id-manifest.json','data/attacks.json','data/benign-tasks.json']
def snapshot(require_model=True,control_map=None):
 m=ModelAdapter()
 if require_model and not m.available:raise RuntimeError('Cannot freeze model evaluation without a model configuration')
 values={'files':{str(f):hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in FILES},'model':m.model,'endpoint':m.url,'python':platform.python_version(),'packages':{p:version(p) for p in ['langgraph','httpx','streamlit']},'max_turns':16,'max_model_calls':64,'temperature':0,'timeout_seconds':45,'held_out_run_policy':'one pass, no tuning, raw outputs preserved'}
 if control_map:values['control_map_sha256']=hashlib.sha256(Path(control_map).read_bytes()).hexdigest()
 values['freeze_sha256']=hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 return values
if __name__=='__main__':
 require='--offline-build' not in sys.argv
 control_map=sys.argv[sys.argv.index('--control-map')+1] if '--control-map' in sys.argv else None
 values=snapshot(require,control_map);path=Path('artifacts/freeze-model.json' if require else 'artifacts/snapshot-offline-build.json')
 path.write_text(json.dumps(values,indent=2));print(json.dumps(values,indent=2))
