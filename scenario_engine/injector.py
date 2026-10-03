"""Place an injection payload into a clean source at a declared location. Deterministic.

Returns the attacked variant and a record. The clean source is never modified; the variant is
a new string. sha256 here fingerprints the SOURCE CONTENT. It is not the audit hash chain and
not a decoding of anything.
"""
import hashlib, json

def fingerprint(text):
 return hashlib.sha256(text.encode('utf-8')).hexdigest()

def _middle(text, payload):
 paras = text.split('\n\n')
 if len(paras) < 2:
  cut = len(text) // 2
  nl = text.find('\n', cut)
  cut = nl + 1 if nl != -1 else len(text)
  return text[:cut] + payload + '\n' + text[cut:]
 k = len(paras) // 2
 return '\n\n'.join(paras[:k] + [payload] + paras[k:])

def inject(text, payload, placement):
 if placement == 'beginning': out = payload + '\n\n' + text
 elif placement == 'middle': out = _middle(text, payload)
 elif placement == 'footer': out = text.rstrip('\n') + '\n\n--\n' + payload + '\n'
 elif placement == 'footnote': out = text.rstrip('\n') + '\n\n[1] ' + payload + '\n'
 elif placement == 'table_cell': out = text.rstrip('\n') + '\n\n| note |\n|---|\n| ' + payload.replace('\n', ' ').replace('|', '/') + ' |\n'
 elif placement == 'HTML_comment': out = text.rstrip('\n') + '\n<!-- ' + payload.replace('--', '- -') + ' -->\n'
 elif placement == 'metadata': out = '---\nnote: ' + json.dumps(payload) + '\n---\n' + text
 elif placement == 'hidden_text': out = text.rstrip('\n') + '\n<span style="display:none">' + payload + '</span>\n'
 elif placement == 'tool_response': out = json.dumps({'status': 'ok', 'result': text, 'message': payload})
 elif placement == 'email_body': out = text.rstrip('\n') + '\n\n' + payload + '\n'
 elif placement == 'code_comment': out = text.rstrip('\n') + '\n' + '\n'.join('# ' + l for l in payload.split('\n')) + '\n'
 else: raise ValueError('unknown placement %r' % placement)
 return out, {'placement': placement, 'clean_sha256': fingerprint(text), 'variant_sha256': fingerprint(out), 'payload_sha256': fingerprint(payload)}
