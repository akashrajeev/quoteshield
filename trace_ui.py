"""Streamlit panel for the SecurityTrace. Pure rendering: it shows what trace.build() derived
from a real run. Nothing here animates, times or invents a stage."""
import json
import streamlit as st
import trace

MARK = {'PASS': ('✓', '#1F6F5C'), 'ALLOW': ('✓', '#1F6F5C'), 'READY': ('✓', '#1F6F5C'), 'APPROVED': ('✓', '#1F6F5C'),
        'CLEANED': ('✂', '#C99A2E'), 'TRACKED': ('✓', '#C99A2E'), 'ASK HUMAN': ('?', '#C99A2E'),
        'BLOCK': ('✗', '#B5442B'), 'QUARANTINED': ('✗', '#B5442B'), 'DENIED': ('✗', '#B5442B'),
        'SCRIPTED': ('✓', '#6b7280'), 'LIVE': ('✓', '#1F6F5C'), 'EXECUTED': ('!', '#B5442B'), 'FAIL': ('✗', '#B5442B')}

def _pill(s, stopped):
 mark, color = MARK.get(s['status'], ('○', '#9ca3af'))
 weight = '700' if s['stage'] == stopped else '500'
 ring = 'box-shadow:0 0 0 2px %s;' % color if s['stage'] == stopped else ''
 return ('<span style="display:inline-block;margin:2px 3px;padding:4px 9px;border-radius:14px;border:1px solid %s;color:%s;font-weight:%s;font-size:.82rem;%s">%s %s</span>'
         % (color, color, weight, ring, mark, s['label']))

def render(t, title=None, mode_note=None):
 st.markdown('**QUOTESHIELD - SECURITY TRACE**' + (' &nbsp; ' + title if title else ''))
 if mode_note: st.caption(mode_note)
 b = t['blocked_at']
 st.markdown(''.join(_pill(s, b['stage'] if b else None) for s in t['stages']), unsafe_allow_html=True)
 if t.get('findings'):
  st.markdown('**Prompt classification (from the request guard)**')
  for f in t['findings']: st.write('- %s (found in the %s view): "%s"' % (f['rule'], f['encoding'], str(f.get('snippet', ''))[:140]))
 if b: st.error('Stopped at stage %d of %d: %s (%s)' % (b['position'], b['of'], b['label'], b['rule']))
 elif t.get('waiting_for_human'): st.warning('Waiting for a person to approve the exact call. Nothing has been sent.')
 else: st.success('No stage stopped this run.')
 st.markdown('**Tool execution: %s**' % ('EXECUTED (mock effect captured)' if t['effect_executed'] else 'NOT EXECUTED'))
 if b:
  st.markdown('**Why it was stopped**')
  st.write(next(s['explanation'] for s in t['stages'] if s['stage'] == b['stage']))
 audit = next(s for s in t['stages'] if s['stage'] == 'audit')
 st.caption('Audit: ' + audit['explanation'])
 st.markdown('**What each stage did**')
 for s in t['stages']:
  with st.expander('%s · %s%s' % (s['label'], s['status'], (' · ' + s['rule']) if s['rule'] else '')):
   st.write(s['explanation'])
   st.json({k: s[k] for k in ('stage', 'status', 'rule', 'events')})
 st.caption('Depth is a label for this one run. It is not a detection rate and is not averaged or compared across runs or versions.')


def comparison_rows(items):
 """items: [(title, trace)]. One row per run; each row describes that run only."""
 rows = []
 for title, t in items:
  b = t['blocked_at']
  rows.append({'Scenario': title, 'Stopped at': ('%d/%d %s' % (b['position'], b['of'], b['label'])) if b else ('waiting for a person' if t.get('waiting_for_human') else 'not stopped'),
               'Rule': (b or {}).get('rule') or '', 'Tool executed': 'yes' if t['effect_executed'] else 'no',
               'Stages with events': t['stages_with_events']})
 return rows

def depth_bars(items):
 """Plain text bar per run: how far the run got before it was stopped. Descriptive, not a rate."""
 out = []
 for title, t in items:
  b = t['blocked_at']; n = b['position'] if b else len(trace.ORDER)
  out.append('%-62s %s%s  %s' % (title[:62], '#' * n, '.' * (len(trace.ORDER) - n), ('stopped at ' + b['label']) if b else 'not stopped'))
 return '\n'.join(out)
