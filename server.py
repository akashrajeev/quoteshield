"""Loopback-only local demo. JSON API never creates real tool effects."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import argparse,json,uuid
from shield import paired,ModelAdapter,Scope,Sandbox,Guard,ToolCall
ROOT=Path(__file__).parent
SESSIONS={}
class Handler(BaseHTTPRequestHandler):
 def reply(self,status,data,ctype='application/json'):
  content=json.dumps(data).encode() if ctype=='application/json' else data
  self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(content)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(content)
 def do_GET(self):
  route=urlparse(self.path).path
  if route=='/api/catalog':return self.reply(200,{'attacks':[{k:a[k] for k in ['id','title','category','split']} for a in json.loads((ROOT/'data/attacks.json').read_text())],'llm_available':ModelAdapter().available})
  if route=='/api/results':
   return self.reply(200,{p.stem:json.loads(p.read_text()) for p in (ROOT/'artifacts').glob('offline-*.json')})
  if route in ['/','/index.html']:return self.reply(200,(ROOT/'static/index.html').read_bytes(),'text/html; charset=utf-8')
  self.reply(404,{'error':'not found'})
 def do_POST(self):
  if self.headers.get('Origin') not in [None,'http://127.0.0.1:8765','http://localhost:8765']:return self.reply(403,{'error':'cross-origin request blocked'})
  try:
   length=int(self.headers.get('Content-Length',0))
   if length>8192:return self.reply(413,{'error':'request too large'})
   data=json.loads(self.rfile.read(length));route=urlparse(self.path).path
   if route=='/api/run':
    corpus=json.loads((ROOT/'data/attacks.json').read_text());attack=next((a for a in corpus if a['id']==data.get('id')),None)
    if attack is None:return self.reply(400,{'error':'Unknown attack identifier'})
    mode=data.get('mode','offline')
    if mode not in ['offline','llm']:return self.reply(400,{'error':'invalid mode'})
    return self.reply(200,paired(attack,mode))
   if route=='/api/human/prepare':
    token=uuid.uuid4().hex;call=ToolCall('send_email',{'to':'reviewer@example.test','subject':'Quotation comparison','body':'Beacon: $11,900, 21 days, 12-month warranty. Cedar: $13,200, 10 days, 36 months. Atlas: $12,400, 14 days, 24 months.'})
    scope=Scope(tools=['send_email'],resources=[],recipients=['reviewer@example.test']);sb=Sandbox();guard=Guard(scope,sb);SESSIONS[token]=(call,guard,sb)
    from dataclasses import asdict
    return self.reply(200,{'token':token,'call':asdict(call),'decision':asdict(guard.inspect(call))})
   if route=='/api/human/resolve':
    state=SESSIONS.pop(data.get('token',''),None)
    if state is None:return self.reply(400,{'error':'expired or consumed confirmation'})
    call,guard,sb=state
    if data.get('approve') is not True:return self.reply(200,{'decision':'DENIED','mock_outbox':[]})
    from dataclasses import asdict
    d=guard.inspect(call,asdict(call))
    if d.verdict=='ALLOW':sb.execute(call)
    return self.reply(200,{'decision':d.verdict,'mock_outbox':sb.emails})
   self.reply(404,{'error':'not found'})
  except Exception as e:self.reply(400,{'error':str(e)})
 def log_message(self,*args):pass
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8765);a=p.parse_args();print(f'QuoteShield listening on http://127.0.0.1:{a.port}',flush=True);ThreadingHTTPServer(('127.0.0.1',a.port),Handler).serve_forever()
