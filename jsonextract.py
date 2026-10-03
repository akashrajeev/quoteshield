"""Pull the first JSON object out of a model reply, even when prose comes before it.

Models often answer 'Here is the comparison: {...}' or wrap JSON in a code fence. The
strict parse rejected those and the completion check then scored a correct answer as
incomplete. This only ever returns the FIRST complete top-level JSON object; it never
repairs, guesses or merges text, and returns None when there is none.
"""
import json, re

def extract_json_object(text):
 if not isinstance(text, str): return None
 body = re.sub(r'^```(?:json)?\s*|\s*```$', '', text.strip())
 try:
  value = json.loads(body)
  return value if isinstance(value, dict) else None
 except ValueError:
  pass
 decoder = json.JSONDecoder()
 for m in re.finditer(r'\{', body):
  try:
   value, _ = decoder.raw_decode(body[m.start():])
  except ValueError:
   continue
  if isinstance(value, dict): return value
 return None
