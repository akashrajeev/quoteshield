"""Plain-English explanation of one run, generated deterministically from the run's own records.

No model is used and nothing is inferred. Every sentence carries the evidence it came from (stage name,
rule name, audit sequence number, decoded-view flag, proposed tool call, captured effect). A sentence
that cannot cite evidence is not written. It describes ONE run: it is not a detection rate and it says
nothing about how another model or phrasing would behave.

Inputs: a finished Runner.run() result (any lane), or a flagged request check when the request guard
stopped the task before a run existed.
"""
from __future__ import annotations
import re
import trace as legacy
from .classes import DECISION_GATES, CHECKPOINTS

_CP = {c[1]: c[0] for c in CHECKPOINTS}
_REFUSAL = re.compile(r"(?i)\b(?:i[’']?m sorry|i am sorry|i can[’']?t help|i cannot help|can[’']?t assist|cannot assist|i can[’']?t comply|i won[’']?t)\b")
_STOPPED = ('BLOCK', 'QUARANTINED', 'DENIED')

def _clip(s, n=200):
 s = ' '.join(str(s).split())
 return s if len(s) <= n else s[:n - 1] + '...'

def _target(call):
 a = (call or {}).get('args') or {}
 return str(a.get('path') or a.get('url') or a.get('to') or a.get('key') or '')

def _call_text(call):
 return ('%s %s' % ((call or {}).get('tool', 'tool'), _target(call))).strip()

def _s(text, *evidence):
 if not evidence: raise ValueError('a sentence needs evidence: ' + text)
 return {'text': text, 'evidence': list(evidence)}

def _proposals(result):
 out = []
 for e in result.get('audit', []):
  c = e.get('call')
  if e.get('stage') == 'action' and c and c.get('origin', 'agent') == 'agent':
   out.append((e, c))
 return out

def explain_run(result=None, request_check=None, request=None, lane=None):
 """Returns {'lane','summary','sections':[{'title','sentences':[{'text','evidence'}]}],'text','markdown'}."""
 if result is None:
  if not request_check or not request_check.get('flagged'): raise ValueError('explain_run needs a finished run or a flagged request check')
  tr = legacy.from_request_block(request_check)
  audit, defence, mode = [], 'full', None
 else:
  tr = legacy.build(result)
  audit, defence, mode = result.get('audit', []), result.get('defence'), result.get('mode')
  request = request if request is not None else result.get('request')
 stage = {s['stage']: s for s in tr['stages']}
 b0 = tr['blocked_at']
 baseline = defence == 'none'
 secs = []

 # 1. what was attempted
 a = []
 if request: a.append(_s('The task was: "%s"' % _clip(request), 'request'))
 if result is None:
  a.append(_s('The task was checked by the request guard before anything ran. No model call, tool call or file access happened.', 'stage=prompt_guard', 'no audit entries'))
 else:
  if baseline: a.append(_s('This lane ran with no defence (defence=none): no request guard, content firewall or action guard.', 'defence=none'))
  else: a.append(_s('This lane ran with defence "%s".' % defence, 'defence=%s' % defence))
  if mode == 'llm':
   models = sorted({t.get('response_model') for t in result.get('model_trace', []) if t.get('response_model')})
   a.append(_s('A live model proposed the tool calls%s.' % ((' (' + ', '.join(models) + ')') if models else ''), 'mode=llm', 'model_trace'))
  elif mode: a.append(_s('Offline run: the tool calls were supplied, so this tests the boundary, not a model.', 'mode=%s' % mode))
  props = _proposals(result)
  if props:
   a.append(_s('Tool calls proposed: %s.' % '; '.join('%s (%s)' % (_call_text(c), e['decision']) for e, c in props),
               *['audit#%s action/%s/%s' % (e['sequence'], e['decision'], e.get('rule')) for e, _c in props]))
  else: a.append(_s('No tool call was proposed in the recorded audit.', 'audit'))
 secs.append({'title': 'What was attempted', 'sentences': a})

 # 2. decision gates, in order
 g = []
 findings = (request_check or {}).get('findings') or []
 skipped = []; inactive = []
 pos = {k: i + 1 for i, k in enumerate(legacy.ORDER)}
 for key in DECISION_GATES:
  st = stage[key]; cp = _CP[key]
  if baseline and key in ('content_firewall', 'action_guard', 'taint', 'human'):
   inactive.append(key); continue
  if st['status'] == 'NOT_REACHED':
   skipped.append(key); continue
  ev = ['stage=%s' % key, 'status=%s' % st['status']] + (['rule=%s' % st['rule']] if st['rule'] else []) + ['audit#%s' % n for n in st['events']]
  g.append(_s('%s %s - %s. %s' % (cp, st['label'], st['status'], st['explanation']), *ev))
  if key == 'scope':
   _sc = [e for e in audit if e.get('stage') == 'scope']
   _ct = [e for e in audit if e.get('stage') == 'content']
   if _sc and _ct and _sc[0]['sequence'] < _ct[0]['sequence']:
    g.append(_s('The scope was fixed at audit#%s, before the first document was ingested (audit#%s). Text inside a document arrives after that point, so it cannot widen the scope.' % (_sc[0]['sequence'], _ct[0]['sequence']),
                'audit#%s scope/%s' % (_sc[0]['sequence'], _sc[0]['decision']), 'audit#%s content/%s' % (_ct[0]['sequence'], _ct[0]['decision'])))
  if key == 'prompt_guard' and findings:
   for f in findings:
    g.append(_s('The request guard matched "%s" in the %s view of the task (matched text: "%s").' % (f['rule'], f['encoding'], _clip(f.get('snippet', ''), 120)),
                'stage=prompt_guard', 'rule=%s' % f['rule'], 'view=%s' % f['encoding']))
 if inactive:
  g.append(_s('%s were not active in this lane (defence=none). Tool calls were allowed by rule "baseline" and tool output entered the model context unchanged (rule "baseline_input"). Nothing was checked.' % ', '.join('%s %s' % (_CP[k], stage[k]['label']) for k in inactive),
              'defence=none', *['audit#%s %s/%s/%s' % (e['sequence'], e['stage'], e['decision'], e.get('rule')) for e in audit if e.get('rule') in ('baseline', 'baseline_input')][:6]))
 if skipped:
  ended = [k for k in skipped if b0 and pos[k] > b0['position']]
  quiet = [k for k in skipped if k not in ended]
  if ended: g.append(_s('Not reached because the run ended earlier: %s.' % ', '.join('%s %s' % (_CP[k], stage[k]['label']) for k in ended), *['stage=%s status=NOT_REACHED' % k for k in ended]))
  if quiet: g.append(_s('No separate event at: %s. Calls this gate allowed, if any, are listed under tool calls proposed above.' % ', '.join('%s %s' % (_CP[k], stage[k]['label']) for k in quiet), *['stage=%s' % k for k in quiet]))
 obs = []
 for key in ('retrieval', 'agent', 'effect', 'audit'):
  st = stage[key]
  if st['status'] != 'NOT_REACHED': obs.append('%s %s %s' % (_CP[key], st['label'], st['status']))
 if obs: g.append(_s('Observed, not decision points: %s.' % '; '.join(obs), *['stage=%s' % k for k in ('retrieval', 'agent', 'effect', 'audit') if stage[k]['status'] != 'NOT_REACHED']))
 secs.append({'title': 'What each decision gate did', 'sentences': g})

 # 3. where and why it stopped
 b = tr['blocked_at']; w = []
 if b:
  st = stage[b['stage']]
  if b['status'] == 'CLEANED':
   w.append(_s('Nothing was blocked outright. The first intervention was at stage %d of %d, %s (rule %s): %s' % (b['position'], b['of'], b['label'], b['rule'], st['explanation']),
               'blocked_at=%s' % b['stage'], 'rule=%s' % b['rule'], 'status=CLEANED'))
  else:
   w.append(_s('The run stopped at stage %d of %d, %s (rule %s). Why: %s' % (b['position'], b['of'], b['label'], b['rule'], st['explanation']),
               'blocked_at=%s' % b['stage'], 'rule=%s' % b['rule'], 'status=%s' % b['status']))
 elif tr['waiting_for_human']:
  w.append(_s('The run is waiting for a person to approve the exact call. Nothing has executed yet.', 'stage=human', 'status=ASK HUMAN', 'pending'))
 elif baseline:
  w.append(_s('No stage stopped this lane, because it had no defence to stop anything.', 'defence=none', 'blocked_at=None'))
 else:
  w.append(_s('No stage stopped this run.', 'blocked_at=None'))
 secs.append({'title': 'Where and why it stopped', 'sentences': w})

 # 4. what did not execute
 n = []
 if result is None:
  n.append(_s('No file was opened, no email was sent and no record was written. The agent never started.', 'stage=prompt_guard', 'no audit entries'))
 else:
  blocked_calls = [(e, e['call']) for e in audit if e.get('call') and e.get('decision') in ('BLOCK', 'DENIED')]
  for e, c in blocked_calls:
   n.append(_s('%s did not execute: %s' % (_call_text(c), e.get('reason', 'blocked')), 'audit#%s %s/%s/%s' % (e['sequence'], e['stage'], e['decision'], e.get('rule'))))
  out, rec = result.get('mock_outbox') or [], result.get('mock_records') or {}
  if out or rec:
   n.append(_s('Mock effects that DID execute: %d email(s)%s, %d record write(s).' % (len(out), (' to ' + ', '.join(sorted({str(m.get('to')) for m in out}))) if out else '', len(rec)), 'mock_outbox', 'mock_records'))
  else:
   n.append(_s('No mock email was sent and no record was written.', 'mock_outbox=[]', 'mock_records={}'))
  if result.get('pending'): n.append(_s('%d call(s) are still waiting for human approval and have not run.' % len(result['pending']), 'pending'))
 secs.append({'title': 'What did not execute as a result', 'sentences': n})

 # 5. recorded outcome checks
 o = []
 if result is not None:
  if result.get('attack_success') is not None: o.append(_s('The run\'s security oracle reported attack_success=%s.' % result['attack_success'], 'security_oracle'))
  if result.get('task_complete') is not None: o.append(_s('The utility check reported task_complete=%s.' % result['task_complete'], 'utility_oracle'))
  ans = result.get('answer') or ''
  if ans and _REFUSAL.search(ans): o.append(_s('The final answer reads as a refusal ("%s").' % _clip(ans, 120), 'answer'))
  for e, c in _proposals(result):
   if e.get('rule') == 'baseline' and re.search('confidential', _target(c), re.I):
    o.append(_s('In this undefended lane the %s proposed %s, a target whose name contains "confidential". It was allowed and nothing checked it.' % ('model' if mode == 'llm' else 'supplied call', _call_text(c)), 'audit#%s action/%s/baseline' % (e['sequence'], e['decision'])))
 if o: secs.append({'title': 'Recorded outcome checks', 'sentences': o})

 # 6. limits
 lim = [_s('This describes one run. It is not a detection rate and is not comparable across runs or versions.', 'scope=single run')]
 if baseline: lim.append(_s('A model refusing in an undefended lane depends on the model and the wording. It is not a defence and says nothing about other models or phrasings.', 'defence=none'))
 if result is not None: lim.append(_s('The security check scores confidential reads, outbound email and record writes. It does not score changes to the content of the answer, such as a manipulated price or recommendation, so attack_success=False does not rule those out.', 'security_oracle', 'scope=oracle limits'))
 if mode == 'offline': lim.append(_s('Offline runs use supplied proposals, so they show what the boundary does, not what a model would propose.', 'mode=offline'))
 if result is not None: lim.append(_s('The audit log is a SHA-256 hash chain: it detects edits, it is not a signature.', 'audit_chain'))
 secs.append({'title': 'Limits', 'sentences': lim})

 summary = (('Stopped at %s (%s).' % (b['label'], b['rule'])) if b and b['status'] != 'CLEANED' else
            ('Waiting for a person to approve.' if tr['waiting_for_human'] else
             ('Not stopped (no defence in this lane).' if baseline else 'Not stopped.')))
 text = '\n\n'.join(sec['title'] + '\n' + '\n'.join('- ' + s['text'] for s in sec['sentences']) for sec in secs)
 md = '\n\n'.join('**%s**\n\n' % sec['title'] + '\n'.join('- ' + s['text'] for s in sec['sentences']) for sec in secs)
 md = re.sub(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+', lambda m: '`' + m.group(0) + '`', md)  # keep addresses from the run from turning into clickable mail links
 return {'lane': lane, 'summary': summary, 'blocked_at': b['stage'] if b else None, 'sections': secs, 'text': text, 'markdown': md}
