import json
from pathlib import Path
from .schema import scenario_from_dict, ManifestError

ROOT = Path(__file__).resolve().parent.parent

def _resolve(ref):
 p = (ROOT / ref).resolve()
 if ROOT not in p.parents: raise ManifestError('payload_ref outside the repository: %s' % ref)
 with open(p) as f: return json.load(f)

def load_manifest(path):
 with open(path) as f: d = json.load(f)
 return scenario_from_dict(d, _resolve)

def load_dir(directory):
 out = [load_manifest(p) for p in sorted(Path(directory).rglob('*.json'))]
 ids = [s.id for s in out]
 if len(ids) != len(set(ids)): raise ManifestError('duplicate scenario ids')
 return out

def require_benign_control(scenarios):
 """Every domain in a scenario set must carry a benign control, so a normal task is shown to pass."""
 missing = sorted({s.domain for s in scenarios} - {s.domain for s in scenarios if s.benign_control})
 if missing: raise ManifestError('no benign control for domain(s): %s' % ', '.join(missing))
 return True
