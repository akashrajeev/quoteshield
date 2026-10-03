"""Formal SecurityTrace, built from the existing trace.build() output. No new decisions.

penetration_depth = position (1..10) of the stage that stopped the run, or the number of stages when
nothing stopped it. It is a per-run label, never averaged. blocked_at is observed, never an input.
latency_ms is filled only where the run measured it, else None.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional
import trace as legacy

STATUSES = ('PASS', 'BLOCK', 'ASK', 'NOT_REACHED', 'ERROR')
_MAP = {'ALLOW': 'PASS', 'READY': 'PASS', 'PASS': 'PASS', 'CLEANED': 'PASS', 'SCRIPTED': 'PASS', 'LIVE': 'PASS', 'NONE': 'PASS',
        'TRACKED': 'PASS', 'EXECUTED': 'PASS', 'APPROVED': 'PASS', 'NOT_TRIGGERED': 'PASS',
        'BLOCK': 'BLOCK', 'DENIED': 'BLOCK', 'QUARANTINED': 'BLOCK', 'ASK HUMAN': 'ASK',
        'NOT_REACHED': 'NOT_REACHED', 'NOT_RUN': 'NOT_REACHED', 'NOT_NEEDED': 'NOT_REACHED', 'FAIL': 'ERROR'}
# Which engine timing key measures which stage. Anything else stays None.
_LATENCY = {'scope': 'scope_ms', 'content_firewall': 'firewall_ms', 'action_guard': 'guard_ms', 'agent': 'agent_ms'}

@dataclass
class StageResult:
 name: str
 status: str
 decision: str
 evidence: str
 latency_ms: Optional[float] = None

@dataclass
class SecurityTrace:
 scenario_id: str
 model: Optional[str]
 stages: list
 blocked_at: Optional[str]
 penetration_depth: int
 attack_success: Optional[bool]
 task_complete: Optional[bool]
 effect_executed: bool
 evidence: list = field(default_factory=list)
 timings: dict = field(default_factory=dict)

 def to_dict(self): return asdict(self)

def from_legacy(trace_dict, scenario_id, result=None):
 timings = dict((result or {}).get('timings') or {})
 stages = []
 for s in trace_dict['stages']:
  raw = s['status']
  if raw not in _MAP: raise ValueError('unmapped stage status %r' % raw)
  lat = timings.get(_LATENCY.get(s['stage']))
  stages.append(StageResult(s['stage'], _MAP[raw], raw, s['explanation'], lat))
 b = trace_dict['blocked_at']
 depth = b['position'] if b else len(legacy.ORDER)
 evidence = [{'stage': i['stage'], 'status': i['status'], 'rule': i['rule']} for i in trace_dict['interventions']]
 return SecurityTrace(scenario_id=scenario_id, model=(result or {}).get('model'), stages=stages,
                      blocked_at=b['stage'] if b else None, penetration_depth=depth,
                      attack_success=trace_dict.get('attack_success'), task_complete=(result or {}).get('task_complete'),
                      effect_executed=trace_dict['effect_executed'], evidence=evidence, timings=timings)
