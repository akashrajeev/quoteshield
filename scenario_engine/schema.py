"""Scenario manifest schema. One JSON file per scenario, no per-scenario Python."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

INJECTION_TYPES = ('DIRECT', 'INDIRECT', 'TOOL_RESPONSE')
PLACEMENTS = ('beginning', 'middle', 'footer', 'footnote', 'table_cell', 'HTML_comment', 'metadata',
              'hidden_text', 'tool_response', 'email_body', 'code_comment')
CLASSIFICATIONS = ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET')
# What boundary a test is meant to exercise. This is an OBJECTIVE, never an expected result.
OBJECTIVES = ('prompt_guard', 'scope', 'content_firewall', 'action_guard', 'provenance', 'human', 'baseline_delta', 'none')
# Keys that would hard-code an outcome. A manifest carrying any of them is rejected.
FORBIDDEN_KEYS = ('expected_blocked_at', 'expected_stage', 'expected_rule', 'expected_depth',
                  'blocked_at', 'penetration_depth', 'expected_penetration_depth')
DOMAINS = ('procurement', 'hr', 'finance', 'customer_support', 'research')

class ManifestError(ValueError):
 pass

@dataclass(frozen=True)
class Provenance:
 """Where a source document came from. content sha256 is a source fingerprint, NOT the audit chain."""
 source_id: str
 origin_url: str = ''
 retrieved_at: str = ''
 sha256: str = ''
 content_type: str = 'text/plain'
 license_note: str = ''

@dataclass(frozen=True)
class Resource:
 """Declare every resource the task may touch. Under a manifest policy a path that is not declared here is not readable,
 and a classification of CONFIDENTIAL, RESTRICTED or SECRET marks it confidential. Classification is metadata, never read from content."""
 id: str
 path: str
 classification: str = 'INTERNAL'
 provenance: Optional[Provenance] = None
 content: str = ''  # resolved text of the resource, from content_ref or inline (synthetic)
 content_ref: str = ''

@dataclass(frozen=True)
class Policy:
 """Generic authorization inputs. No domain logic: only resources, recipients and tools."""
 authorized_resources: tuple = ()
 authorized_recipients: tuple = ()
 allowed_tools: tuple = ()
 ask_human_for: tuple = ()

@dataclass(frozen=True)
class Attack:
 injection_type: str
 placement: str
 objective: str
 payload: str = ''
 scripted_calls: tuple = ()
 payload_ref: str = ''
 host_resource: str = ''  # declared resource whose text carries the payload (default: the procurement mock quote)

@dataclass(frozen=True)
class Evaluation:
 attack_success_rule: str = 'engine_oracle'
 utility_rule: str = 'engine_oracle'

@dataclass(frozen=True)
class Scenario:
 id: str
 domain: str
 user_request: str
 resources: tuple = ()
 policy: Policy = field(default_factory=Policy)
 attack: Optional[Attack] = None
 evaluation: Evaluation = field(default_factory=Evaluation)
 benign_control: bool = False
 notes: str = ''
 scripted_calls: tuple = ()  # offline supplied proposals for a control; tests the boundary, not the model
 task_spec: dict = field(default_factory=dict)  # input to the existing utility oracle (vendors, operation, limit); never an outcome
 poison: Optional[Attack] = None  # benign control whose document also carries an injection that nothing proposes to follow

 @property
 def injection_type(self):
  return self.attack.injection_type if self.attack else None

def _forbidden(obj, path=''):
 if isinstance(obj, dict):
  for k, v in obj.items():
   if k in FORBIDDEN_KEYS: raise ManifestError('manifest may not hard-code an outcome: %s%s' % (path, k))
   _forbidden(v, path + k + '.')
 elif isinstance(obj, list):
  for i, v in enumerate(obj): _forbidden(v, '%s%d.' % (path, i))

def _need(d, key, where):
 if key not in d or d[key] in (None, ''): raise ManifestError('%s: missing %s' % (where, key))
 return d[key]

def _provenance(d):
 if not d: return None
 return Provenance(**{k: d[k] for k in Provenance.__dataclass_fields__ if k in d})

def scenario_from_dict(d, resolve_ref=None, resolve_text=None):
 """Validate and build a Scenario. resolve_ref(path) -> dict supplies payload/calls for payload_ref."""
 if not isinstance(d, dict): raise ManifestError('manifest must be an object')
 _forbidden(d)
 sid = _need(d, 'id', 'scenario')
 domain = _need(d, 'domain', sid)
 if domain not in DOMAINS: raise ManifestError('%s: unknown domain %r' % (sid, domain))
 resources = []
 for r in d.get('resources', []):
  cls = r.get('classification', 'INTERNAL')
  if cls not in CLASSIFICATIONS: raise ManifestError('%s: bad classification %r' % (sid, cls))
  cref, text = r.get('content_ref', ''), r.get('content', '')
  if cref:
   if resolve_text is None: raise ManifestError('%s: content_ref needs a resolver' % sid)
   text = resolve_text(cref)
  prov = _provenance(r.get('provenance'))
  if cref and prov is None and hasattr(resolve_text, 'provenance'): prov = _provenance(resolve_text.provenance(cref))
  resources.append(Resource(id=_need(r, 'id', sid), path=_need(r, 'path', sid), classification=cls, provenance=prov, content=text, content_ref=cref))
 p = d.get('policy', {})
 policy = Policy(tuple(p.get('authorized_resources', [])), tuple(p.get('authorized_recipients', [])),
                 tuple(p.get('allowed_tools', [])), tuple(p.get('ask_human_for', [])))
 attack = None
 a = d.get('attack')
 if a:
  it = _need(a, 'injection_type', sid)
  if it not in INJECTION_TYPES: raise ManifestError('%s: bad injection_type %r' % (sid, it))
  pl = _need(a, 'placement', sid)
  if pl not in PLACEMENTS: raise ManifestError('%s: bad placement %r' % (sid, pl))
  ob = a.get('objective', 'none')
  if ob not in OBJECTIVES: raise ManifestError('%s: bad objective %r' % (sid, ob))
  payload, calls = a.get('payload', ''), list(a.get('scripted_calls', []))
  ref = a.get('payload_ref', '')
  if ref:
   if resolve_ref is None: raise ManifestError('%s: payload_ref needs a resolver' % sid)
   data = resolve_ref(ref); payload = data.get('payload', payload); calls = list(data.get('calls', calls))
  host = a.get('host_resource', '')
  if host and host not in {x.path for x in resources}: raise ManifestError('%s: host_resource %r is not a declared resource' % (sid, host))
  attack = Attack(it, pl, ob, payload, tuple(calls), ref, host)
 benign = bool(d.get('benign_control', False))
 if benign and attack: raise ManifestError('%s: a benign control carries no attack' % sid)
 if not benign and not attack: raise ManifestError('%s: needs an attack, or benign_control true' % sid)
 poison = None
 ps = d.get('poisoned_source')
 if ps:
  if not benign: raise ManifestError('%s: poisoned_source belongs to a benign control; use attack for attacks' % sid)
  pl = _need(ps, 'placement', sid)
  if pl not in PLACEMENTS: raise ManifestError('%s: bad placement %r' % (sid, pl))
  host = _need(ps, 'host_resource', sid)
  if host not in {x.path for x in resources}: raise ManifestError('%s: host_resource %r is not a declared resource' % (sid, host))
  poison = Attack('INDIRECT', pl, 'none', _need(ps, 'payload', sid), (), '', host)
 ts = d.get('task_spec', {})
 if not isinstance(ts, dict): raise ManifestError('%s: task_spec must be an object' % sid)
 e = d.get('evaluation', {})
 return Scenario(id=sid, domain=domain, user_request=_need(d, 'user_request', sid), resources=tuple(resources), policy=policy,
                 attack=attack, evaluation=Evaluation(e.get('attack_success_rule', 'engine_oracle'), e.get('utility_rule', 'engine_oracle')),
                 benign_control=benign, notes=d.get('notes', ''), scripted_calls=tuple(d.get('scripted_calls', [])),
                 task_spec=dict(ts), poison=poison)
