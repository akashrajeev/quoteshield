"""Small policy primitives. No I/O and no model-derived authority."""
import hashlib,json
from datetime import datetime,timezone

def canonical(value):
 return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)

class AuditLog:
 """Tamper-evident local chain; not a trusted external signature."""
 def __init__(self,sink=None):self.entries=[];self.sink=sink
 def append(self,entry):
  entry={'timestamp':datetime.now(timezone.utc).isoformat(),**entry,'sequence':len(self.entries)+1,'previous_hash':self.entries[-1]['hash'] if self.entries else '0'*64}
  entry['hash']=hashlib.sha256(canonical(entry).encode()).hexdigest()
  self.entries.append(entry)
  if self.sink:self.sink(dict(entry))
  return entry
 @staticmethod
 def verify(entries):
  prev='0'*64
  for i,e in enumerate(entries,1):
   if e.get('sequence')!=i or e.get('previous_hash')!=prev:return False
   content={k:v for k,v in e.items() if k!='hash'}
   if hashlib.sha256(canonical(content).encode()).hexdigest()!=e.get('hash'):return False
   prev=e['hash']
  return True

def tool_schema_error(call):
 required={'read_file':['path'],'search_web':['url'],'send_email':['to','subject','body'],'write_record':['key','value']}
 if call.tool not in required:return 'Unknown tool.'
 if not isinstance(call.args,dict):return 'Tool arguments must be an object.'
 fields=required[call.tool]
 if set(call.args)-set(fields):return 'Unexpected tool argument.'
 # Optional subject retained for compatibility with existing focused unit tests.
 mandatory=[f for f in fields if not(call.tool=='send_email' and f=='subject')]
 if any(k not in call.args for k in mandatory):return 'Required tool argument missing.'
 if any(not isinstance(v,str) or len(v)>32768 for v in call.args.values()):return 'Arguments must be bounded strings.'
 return None
