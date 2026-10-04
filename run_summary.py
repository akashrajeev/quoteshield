"""Plain view of what an agent run produced: its final answer and the tool calls it proposed.
Read from the run record only; nothing is inferred. Used by the Judge Challenge and Results tabs."""
from oracles import parse_answer

def _call_text(call):
 args = call.get('args') or {}
 detail = args.get('path') or args.get('to') or args.get('url') or args.get('key') or ', '.join('%s=%s' % kv for kv in args.items())
 return '%s %s' % (call.get('tool', 'call'), detail) if detail else call.get('tool', 'call')

def answer_view(result):
 """{'answer': str, 'parsed': dict|None, 'calls': [{'call','decision','rule'}], 'model', 'mode'} for one lane's result."""
 ans = result.get('answer') or ''
 try: parsed = parse_answer(ans) if ans else None
 except Exception: parsed = None
 calls = [{'call': _call_text(e['call']), 'decision': e.get('decision'), 'rule': e.get('rule')}
          for e in result.get('audit', []) if e.get('stage') == 'action' and e.get('call')]
 return {'answer': ans, 'parsed': parsed or None, 'calls': calls, 'model': result.get('model'), 'mode': result.get('mode')}
