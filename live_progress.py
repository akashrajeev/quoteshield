"""Live layer progress for a run in flight (L0-L9).

Two sources, kept apart on purpose:
  - LaneProgress.on_event: built only from audit events as the real run emits them.
  - final_statuses: built from trace.build(result), the same data the Security Trace tab and the
    explanation use, so the end state of the live panel cannot differ from them.
The "running" marker only means: this is the next layer after the last one that produced an event.
It is not a measurement. Any pacing delay between events is for visibility and changes no data.
"""
from __future__ import annotations
import html
import trace as legacy
from scenario_engine.classes import CHECKPOINTS

ORDER = legacy.ORDER
LABEL = dict(legacy.STAGES)
CODE = {stage: cp for cp, stage, _label, _gate in CHECKPOINTS}
# Layers that do not exist in the unprotected lane (same set the explanation reports as not active).
BASELINE_INACTIVE = ('content_firewall', 'action_guard', 'taint', 'human')
_NORMAL = {'QUARANTINE': 'QUARANTINED', 'SANITIZE': 'CLEANED'}
_STOP = ('BLOCK', 'DENIED', 'QUARANTINED')
_RANK = {'PASS': 0, 'CONFIRMED': 1, 'CLEANED': 2, 'ASK HUMAN': 3, 'QUARANTINED': 4, 'DENIED': 4, 'BLOCK': 5}

class LaneProgress:
    def __init__(self, lane, protected=True):
        self.lane, self.protected = lane, protected
        self.status = {s: None for s in ORDER}
        self.finished = False
        self.started = False   # set when this lane begins; only the lane in flight shows a running layer
        self.last = -1

    def on_event(self, event):
        stage = legacy._stage_of(event)
        if stage is None:
            return
        st = _NORMAL.get(event.get('decision'), event.get('decision'))
        cur = self.status[stage]
        if cur is None or _RANK.get(st, 0) >= _RANK.get(cur, 0):
            self.status[stage] = st
        self.last = max(self.last, ORDER.index(stage))

    def running(self):
        if self.finished or not self.started:
            return None
        for i in range(self.last + 1, len(ORDER)):
            if not self.protected and ORDER[i] in BASELINE_INACTIVE:
                continue
            return ORDER[i]
        return None

    def finish(self, result):
        self.finished = True
        self.status = final_statuses(result)

def final_statuses(result):
    built = legacy.build(result)
    out = {s['stage']: s['status'] for s in built['stages']}
    if result.get('defence') == 'none':
        for k in BASELINE_INACTIVE:
            out[k] = 'NOT_ACTIVE'
    return out

_GOOD = ('PASS', 'ALLOW', 'SCRIPTED', 'LIVE', 'NONE', 'NOT_TRIGGERED', 'NOT_NEEDED', 'TRACKED', 'EXECUTED', 'APPROVED')
_AMBER = ('CONFIRMED', 'CLEANED', 'ASK HUMAN')
_BAD = ('BLOCK', 'DENIED', 'QUARANTINED', 'FAIL')

def _style(status, running):
    if running:
        return '#fff3c4', '#4d3a00', '&#9696;', 'running...'
    if status is None:
        return '#ece7e1', '#4f4a44', '&#9675;', 'pending'
    if status in _BAD:
        return '#fde2e0', '#7a1a14', '&#10005;', status
    if status in _AMBER:
        return '#fff3c4', '#4d3a00', '&#9650;', status
    if status in _GOOD:
        return '#dff3e0', '#14451a', '&#10003;', status
    return '#ece7e1', '#4f4a44', '&#8212;', status.replace('_', ' ').lower()

def render(progress, title):
    running = progress.running()
    rows = []
    for stage in ORDER:
        bg, fg, mark, text = _style(progress.status[stage], stage == running)
        rows.append('<div style="display:flex;justify-content:space-between;background:%s;color:%s;padding:5px 10px;border-radius:5px;margin:3px 0;font-size:0.92rem">'
                    '<span>%s <b>%s</b> %s</span><span>%s</span></div>' % (bg, fg, mark, CODE[stage], html.escape(LABEL[stage]), html.escape(text)))
    return '<div><div style="font-weight:700;margin-bottom:4px">%s</div>%s</div>' % (html.escape(title), ''.join(rows))
