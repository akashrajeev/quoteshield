import json
from pathlib import Path
from .schema import scenario_from_dict, ManifestError

ROOT = Path(__file__).resolve().parent.parent

def _resolve(ref):
 p = (ROOT / ref).resolve()
 if ROOT not in p.parents: raise ManifestError('payload_ref outside the repository: %s' % ref)
 with open(p) as f: return json.load(f)

class _TextResolver:
 def __call__(self, ref):
  p = (ROOT / ref).resolve()
  if ROOT not in p.parents: raise ManifestError('content_ref outside the repository: %s' % ref)
  return p.read_text()
 def provenance(self, ref):
  idx = ROOT / 'corpus/real/PROVENANCE.json'
  if not idx.exists(): return None
  with open(idx) as f: docs = json.load(f)['documents']
  for d in docs:
   if d['path'] == ref: return {k: d.get(k, '') for k in ('source_id', 'origin_url', 'retrieved_at', 'sha256', 'content_type', 'license_note')}
  return None
_resolve_text = _TextResolver()

def load_manifest(path):
 with open(path) as f: d = json.load(f)
 return scenario_from_dict(d, _resolve, _resolve_text)

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
