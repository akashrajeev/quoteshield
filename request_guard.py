"""Request guard: checks the user's OWN task prompt before the scope contract is built.

Off by default. Enable with SHIELD_REQUEST_GUARD=1. When it flags a request the
run does not start; the caller (UI or script) must show the reason and rerun with
request_confirmed=True. It never silently refuses and never rewrites the request.

Only three kinds of signal are used, because the document rules would false-flag
normal requests ("email the result to buyer@acme.example" is a legitimate task):
  - instruction-override wording, fake system markers and covert-execution wording (negated clauses such as
    "Do not email or modify records" are removed first),
  - hidden invisible characters,
  - the same two rule kinds appearing inside a decoded view (base64, hex, URL...),
  - the optional local classifier (local_classifier.py), when enabled.
Not a benchmark claim. A confirmed request still goes through scope, firewall and guard.
"""
from __future__ import annotations
import os, re, unicodedata

STRIPPED_RULES = ('instruction override', 'authority impersonation')  # checked after negated clauses are removed
RAW_RULES = ('covert execution request',)  # checked on the full text: "do not tell" is the signal itself
NEGATED = re.compile(r"(?i)\b(?:do not|don.t|never|must not|should not|shouldn.t|cannot|can.t)\b[^.;!?\n]*")

class RequestNeedsConfirmation(ValueError):
 """Raised by Runner.run for a flagged request that was not confirmed."""
 def __init__(self, result):
  self.result = result
  reasons = '; '.join('%s (%s)' % (f['rule'], f['encoding']) for f in result['findings'])
  super().__init__('Request guard: please confirm this task before it runs. Flagged: ' + reasons)

def enabled():
 return os.environ.get('SHIELD_REQUEST_GUARD', '').lower() in ('1', 'true', 'yes')

def check(request, classifier=None):
 """Returns {'flagged': bool, 'findings': [...]}. classifier defaults to the local one if enabled."""
 import shield, local_classifier
 findings = []
 if any(unicodedata.category(c) == 'Cf' for c in request):
  findings.append({'rule': 'hidden characters', 'encoding': 'raw', 'snippet': 'invisible format characters in the request'})
 for label, value in shield.decode_views(request):
  stripped = NEGATED.sub(' ', value)
  for name, pattern in shield.PATTERNS:
   if name not in STRIPPED_RULES + RAW_RULES: continue
   m = re.search(pattern, stripped if name in STRIPPED_RULES else value, re.I | re.S)
   if m and name not in [f['rule'] for f in findings]:
    findings.append({'rule': name, 'encoding': label, 'snippet': m[0][:180]})
 if classifier is None: classifier = local_classifier.get()  # False disables
 if classifier:
  findings += classifier.findings(shield.decode_views(request))
 return {'flagged': bool(findings), 'findings': findings}
