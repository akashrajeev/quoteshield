"""Run one scenario manifest through the EXISTING pipeline and return a formal SecurityTrace.

Offline runs use the manifest's scripted_calls (a supplied proposal tests the boundary, not the model).
Phase 1 does not change how the engine places an injected payload; the declared placement is applied
by injector.inject() to standalone source variants.
"""
import shield, request_guard, trace
from .trace_model import from_legacy

def attack_dict(sc):
 if sc.attack: return {'id': sc.id, 'payload': sc.attack.payload, 'calls': list(sc.attack.scripted_calls)}
 if sc.scripted_calls: return {'id': sc.id, 'payload': '', 'calls': list(sc.scripted_calls)}
 return None

def run_scenario(sc, mode='offline', review=None, runner=None):
 """review: None leaves a human gate pending, True approves once, False denies."""
 if sc.injection_type == 'DIRECT':
  check = request_guard.check(sc.user_request)
  if check['flagged']:
   return from_legacy(trace.from_request_block(check), sc.id), None
 runner = runner or shield.Runner()
 kw = {}
 if review is not None: kw['reviewer'] = lambda call, v=review: v
 result = runner.run(sc.user_request, attack_dict(sc), True, mode, **kw)
 return from_legacy(trace.build(result), sc.id, result), result
