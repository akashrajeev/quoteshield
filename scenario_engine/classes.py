"""Three separate questions, three separate types, plus the checkpoint list.

A  prompt attack classification  (BENIGN / MALICIOUS / UNCERTAIN)   the classifier slot
B  data classification           (PUBLIC .. SECRET)                 from resource metadata/policy, never an LLM
C  action authorization          (ALLOW / BLOCK / ASK)              deterministic from task, tool, resource, recipient, class, provenance, policy
"""
from .schema import CLASSIFICATIONS

PROMPT_VERDICTS = ('BENIGN', 'MALICIOUS', 'UNCERTAIN')
ACTION_DECISIONS = ('ALLOW', 'BLOCK', 'ASK')

# (checkpoint, engine stage name, label, is_decision_gate). Only gates decide; the rest are observed.
CHECKPOINTS = (
 ('L0', 'prompt_guard', 'User prompt guard', True),
 ('L1', 'scope', 'Scope engine', True),
 ('L2', 'retrieval', 'Retrieval / tool output', False),
 ('L3', 'content_firewall', 'Content firewall', True),
 ('L4', 'agent', 'Agent reasoning', False),
 ('L5', 'action_guard', 'Action guard', True),
 ('L6', 'taint', 'Provenance / taint', True),
 ('L7', 'human', 'Human approval', True),
 ('L8', 'effect', 'Mock tool effect', False),
 ('L9', 'audit', 'Audit chain', False),
)
DECISION_GATES = tuple(c[1] for c in CHECKPOINTS if c[3])

def classify_data(scenario, path):
 """B: from the scenario's declared resource metadata. Unknown paths are INTERNAL, never guessed from content."""
 for r in scenario.resources:
  if r.path == path: return r.classification
 return 'INTERNAL'

def prompt_verdict_from_request_check(check):
 """A: map the rules-only request guard. Flagged by rule = MALICIOUS; clean = BENIGN. No score is claimed."""
 if check is None: return 'UNCERTAIN'
 return 'MALICIOUS' if check.get('flagged') else 'BENIGN'

def action_decision(audit_decision):
 """C: normalize an engine audit decision."""
 d = str(audit_decision).upper()
 if d in ('ALLOW', 'PASS'): return 'ALLOW'
 if d in ('ASK HUMAN', 'ASK'): return 'ASK'
 if d in ('BLOCK', 'DENIED', 'QUARANTINE'): return 'BLOCK'
 raise ValueError('unmapped decision %r' % audit_decision)
