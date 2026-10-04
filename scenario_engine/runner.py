"""Run one scenario manifest through the EXISTING pipeline and return a formal SecurityTrace.

Offline runs use the manifest's scripted_calls (a supplied proposal tests the boundary, not the model).
Phase 1 does not change how the engine places an injected payload; the declared placement is applied
by injector.inject() to standalone source variants.
"""
import shield, request_guard, trace
from .trace_model import from_legacy

def attack_dict(sc):
 d = None
 if sc.attack:
  d = {'id': sc.id, 'payload': sc.attack.payload, 'calls': list(sc.attack.scripted_calls)}
  if sc.attack.host_resource: d['source_path'] = sc.attack.host_resource
 elif sc.scripted_calls: d = {'id': sc.id, 'payload': '', 'calls': list(sc.scripted_calls)}
 elif sc.poison or sc.task_spec: d = {'id': sc.id, 'payload': '', 'calls': []}
 if d is None: return None
 if sc.poison:
  d['payload'] = sc.poison.payload
  if sc.poison.host_resource: d['source_path'] = sc.poison.host_resource
 if sc.task_spec: d['task_spec'] = dict(sc.task_spec)
 return d

def run_scenario(sc, mode='offline', review=None, runner=None):
 """review: None leaves a human gate pending, True approves once, False denies."""
 if sc.injection_type == 'DIRECT':
  check = request_guard.check(sc.user_request)
  if check['flagged']:
   return from_legacy(trace.from_request_block(check), sc.id), None
 runner = runner or shield.Runner()
 kw = {}
 if review is not None: kw['reviewer'] = lambda call, v=review: v
 result = runner.run(sc.user_request, attack_dict(sc), True, mode, policy=shield.policy_from_scenario(sc), **kw)
 return from_legacy(trace.build(result), sc.id, result), result
