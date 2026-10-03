"""SecurityTrace: a per-run view of how far a request got through the pipeline.

Derived ONLY from a finished run result (its hash-chained audit entries plus the
captured mock effects). It adds no new decisions and changes no run output, so
every stage shown is a record of something that really executed. A stage that did
not run is reported NOT_RUN or NOT_REACHED, never filled in.

Not a score. 'stopped_at' says where the first intervention happened in THIS run.
It is not a detection rate and must not be pooled across runs or versions.
"""
from __future__ import annotations

STAGES = [
 ('prompt_guard', 'User prompt guard'),
 ('scope', 'Scope engine'),
 ('retrieval', 'Retrieval / tool output'),
 ('content_firewall', 'Content firewall'),
 ('agent', 'Agent reasoning'),
 ('action_guard', 'Action guard'),
 ('taint', 'Provenance / taint'),
 ('human', 'Human approval'),
 ('effect', 'Mock tool effect'),
 ('audit', 'Audit chain'),
]
ORDER = [s for s, _ in STAGES]
LABEL = dict(STAGES)
READ_TOOLS = ('read_file', 'search_web')
STOPPING = ('BLOCK', 'QUARANTINE', 'SANITIZE', 'DENIED')

def _call(e):
 c = e.get('call') or {}
 return c.get('tool', 'tool'), c.get('args') or {}

def _describe_call(e):
 tool, args = _call(e)
 key = args.get('path') or args.get('url') or args.get('to') or args.get('key') or ''
 return ('%s %s' % (tool, key)).strip()

def _stage_of(e):
 s, rule = e.get('stage'), e.get('rule')
 if s == 'request': return 'prompt_guard'
 if s == 'scope': return 'scope'
 if s == 'content': return 'content_firewall'
 if s == 'agent': return 'agent'
 if s == 'human': return 'human'
 if s == 'action':
  if rule == 'confidential_flow': return 'taint'
  if e.get('decision') == 'ASK HUMAN': return 'human'
  if _call(e)[0] in READ_TOOLS and e.get('decision') == 'ALLOW': return 'retrieval'
  return 'action_guard'
 return None

def explain(e):
 """One plain sentence from the recorded fields of one audit entry."""
 s, d, rule = e.get('stage'), e.get('decision'), e.get('rule')
 if s == 'request':
  if d == 'PASS': return 'Your task was checked before anything ran. Nothing in it looked like an attempt to override instructions.'
  return 'Your task was flagged (%s) and you confirmed it, so the run went ahead and this is logged.' % ', '.join(sorted({f['rule'] for f in e.get('findings', [])}))
 if s == 'scope':
  return 'Before any file was opened, the system read your task and fixed what this run may touch. Everything later is checked against that scope.'
 if s == 'content':
  src = e.get('source', 'a source')
  rules = sorted({f['rule'] for f in e.get('findings', [])})
  if d == 'PASS': return 'Text from %s was scanned before the agent saw it. Nothing suspicious was found.' % src
  if d == 'SANITIZE': return 'Text from %s was scanned and %d suspicious line(s) were removed (%s). The rest went to the agent.' % (src, len(e.get('removed_spans', [])), ', '.join(rules) or 'rule match')
  if d == 'QUARANTINE': return 'Text from %s was held back entirely (%s). The agent never saw it.' % (src, ', '.join(rules) or e.get('reason', 'rule match'))
  return 'Text from %s was checked: %s.' % (src, d)
 if s == 'agent':
  return 'The agent step ended: %s.' % (e.get('reason') or d)
 if s == 'human':
  return 'A person was asked about this exact call and the answer was %s.' % d.lower()
 if s == 'action':
  what = _describe_call(e)
  if rule == 'confidential_flow': return 'Blocked %s. A confidential file was read earlier in this run, so its data may not go to an outside destination.' % what
  if d == 'ALLOW': return 'Allowed %s: it is inside the scope fixed from your task.' % what
  if d == 'ASK HUMAN': return 'Paused %s. It is allowed in principle, but it sends or changes something, so you must approve this exact call.' % what
  return 'Blocked %s: %s' % (what, e.get('reason', rule))
 return str(e.get('reason', ''))

def build(result):
 """result: a finished Runner.run() dict. Returns the SecurityTrace dict."""
 audit = result.get('audit', [])
 per = {s: [] for s in ORDER}
 for e in audit:
  st = _stage_of(e)
  if st: per[st].append(e)
 stages = []
 stop = None
 for key, label in STAGES:
  ev = per[key]
  entry = {'stage': key, 'label': label, 'status': None, 'rule': None, 'explanation': '', 'events': [e['sequence'] for e in ev]}
  if key == 'audit':
   ok = bool(result.get('audit_chain_verified'))
   entry.update(status='PASS' if ok else 'FAIL', rule='sha256_chain', explanation='The log of this run is a hash chain (%d entries) and it %s. This detects edits; it is not a signature.' % (len(audit), 'verifies' if ok else 'does NOT verify'))
  elif key == 'effect':
   out, rec = result.get('mock_outbox') or [], result.get('mock_records') or []
   ran = bool(out or rec)
   entry.update(status='EXECUTED' if ran else 'NONE', rule='mock_effect', explanation=('Mock effects captured: %d email(s), %d record write(s).' % (len(out), len(rec))) if ran else 'No mock email or record write happened in this run.')
  elif key == 'agent':
   mode = result.get('mode')
   if ev or result.get('model_trace') or audit:
    entry.update(status='LIVE' if mode == 'llm' else 'SCRIPTED', rule='agent_run', explanation=('A real model proposed the tool calls; each was checked below.' if mode == 'llm' else 'Offline mode: the tool calls were supplied by a script, so this tests the boundary, not the model.'))
   else:
    entry.update(status='NOT_REACHED', explanation='The run ended before the agent stage.')
  elif key == 'taint':
   read_conf = any(e.get('decision') == 'ALLOW' and _call(e)[0] == 'read_file' and str(_call(e)[1].get('path', '')).startswith('confidential/') for e in audit if e.get('stage') == 'action')
   blocked = [e for e in ev if e['decision'] == 'BLOCK']
   if blocked: entry.update(status='BLOCK', rule='confidential_flow', explanation=explain(blocked[0]))
   elif read_conf: entry.update(status='TRACKED', rule='confidential_flow', explanation='A confidential file was read, so its data is marked. No call tried to send it out.')
   else: entry.update(status='NOT_TRIGGERED', explanation='No confidential data was read in this run, so there was nothing to track.')
  elif not ev:
   if key == 'prompt_guard': entry.update(status='NOT_RUN', explanation='The request guard is off for this run (SHIELD_REQUEST_GUARD is not set, or this lane has no guard).')
   elif key == 'human': entry.update(status='NOT_NEEDED', explanation='No call needed a person to approve it.')
   else: entry.update(status='NOT_REACHED', explanation='Nothing from this run reached this stage.')
  else:
   worst = next((e for e in ev if e['decision'] in STOPPING), None)
   pick = worst or ev[-1]
   status = {'QUARANTINE': 'QUARANTINED', 'SANITIZE': 'CLEANED'}.get(pick['decision'], pick['decision'])
   if worst is None and len(ev) > 1:
    entry.update(status=status, rule=pick.get('rule'), explanation='%d checks at this stage, all %s. Last: %s' % (len(ev), status, explain(pick)))
   else:
    entry.update(status=status, rule=pick.get('rule'), explanation=explain(pick))
    if len(ev) > 1: entry['explanation'] += ' (%d events at this stage.)' % len(ev)
  stages.append(entry)
  if stop is None and entry['status'] in ('BLOCK', 'QUARANTINED', 'CLEANED', 'DENIED') :
   stop = {'stage': key, 'label': label, 'rule': entry['rule'], 'position': ORDER.index(key) + 1, 'of': len(ORDER)}
 effect = stages[ORDER.index('effect')]['status'] == 'EXECUTED'
 return {'run_id': result.get('run_id'), 'mode': result.get('mode'), 'defence': result.get('defence'), 'stages': stages, 'stopped_at': stop, 'effect_executed': effect, 'attack_success': result.get('attack_success'), 'stages_with_events': sum(1 for s in stages if s['events'])}
