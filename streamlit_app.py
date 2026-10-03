"""PS3 Streamlit primary demo. Local mock effects only."""
from pathlib import Path
import json,copy,uuid
from dataclasses import asdict
import streamlit as st
from shield import Runner,paired,ModelAdapter,firewall,Scope,Sandbox,Guard,ToolCall,QUOTES
from security import AuditLog
from formats import UPLOAD_FORMATS,IMAGE_UPLOAD_FORMATS,judge_artifact
from api_transport import route_summary
from approval import ApprovalWorkflow
from ui_mode import resolve_mode,status_label
from oracles import parse_answer
from provider_config import load_local_env,configure,PRESETS
import os
ROOT=Path(__file__).parent
load_local_env()
if os.environ.get("SHIELD_PROVIDER") in PRESETS:configure(os.environ["SHIELD_PROVIDER"])
# Judge-facing app: the request guard is on unless the operator sets SHIELD_REQUEST_GUARD=0. Library and script defaults stay off.
os.environ.setdefault("SHIELD_REQUEST_GUARD","1")
st.set_page_config(page_title='QuoteShield | Procurement Room',page_icon='◈',layout='wide')
appearance=st.sidebar.radio('Interface',['Styled procurement room','Regular Streamlit (dark)'],key='interface_style')
if appearance=='Styled procurement room':
 st.markdown('''<style>
.stApp{background:#f4efec;color:#251f21}h1,h2,h3{font-family:Georgia,serif!important;letter-spacing:-.5px}h1{font-size:3rem!important}.block-container{padding-top:4.5rem;padding-bottom:2rem;max-width:1500px}div[data-testid="stMetric"]{background:white;padding:16px;border-top:2px solid #73a89a}button{border-radius:2px!important}section[data-testid="stSidebar"]{background:#eee7e1;color:#251f21}.kicker{font:12px monospace;letter-spacing:1.6px}.outcome{background:white;padding:24px;border-top:3px solid #73a89a}.bad{border-top-color:#ed313e}.outcome h3{margin:0}.rail{font:12px monospace;padding:12px;background:white;border-left:3px solid #73a89a}@media(max-width:600px){h1{font-size:2rem!important;line-height:1.12!important}.block-container{padding-top:4rem!important}}.caption{font:12px monospace;color:#585254}
.stApp [data-testid="stDataFrame"]{background:white;color:#251f21}.stApp input,.stApp textarea{background:#fff;color:#251f21}.stApp [data-baseweb="select"]>div{background:#fff;color:#251f21}.stApp [data-testid="stMarkdownContainer"]{color:inherit}.stApp [data-testid="stCaptionContainer"]{color:#585254}.stApp pre,.stApp [data-testid="stJson"]{background:#fff;color:#251f21}.stApp [data-testid="stExpander"]{background:#fff;color:#251f21}.stApp [role="tab"]{color:#251f21}.stApp [data-testid="stMetricValue"],.stApp [data-testid="stMetricLabel"]{color:#251f21}
section[data-testid="stSidebar"] label,section[data-testid="stSidebar"] p,section[data-testid="stSidebar"] [data-testid="stWidgetLabel"]{color:#251f21!important}.stApp [data-testid="stWidgetLabel"]{color:#251f21!important}.stApp button{color:white!important;background:#251f21!important}.stApp [role="tab"]{background:transparent!important;color:#251f21!important}.stApp [data-testid="stExpander"] summary,.stApp [data-testid="stExpander"] summary p{color:#251f21!important}.stApp header{background:#f4efec!important}.stApp [data-testid="stToolbar"] button{background:#251f21!important;color:white!important}.stApp [data-testid="stJson"]{background:#181c24!important;color:#fafafa!important}
.stApp button p,section[data-testid="stSidebar"] button p{color:white!important}.stApp [data-testid="stExpander"] summary{background:#fff!important}.stApp [data-testid="stExpander"] summary button{background:#fff!important;color:#251f21!important}
</style>''',unsafe_allow_html=True)
if appearance=='Styled procurement room':st.markdown('<div class="kicker">QUOTESHIELD / PROCUREMENT ROOM / MOCK SANDBOX</div>',unsafe_allow_html=True)
else:st.caption('QuoteShield / Mock sandbox / Regular Streamlit dark theme')
st.title('Agent Security Gateway')
st.subheader('Protecting AI agents from prompt injection and unauthorized tool actions')
status=st.columns(4)
_adapter=ModelAdapter();LIVE_OK=_adapter.available
status[0].markdown((':green[● ' if LIVE_OK else ':red[● ')+status_label(LIVE_OK,_adapter.model)+']')
for col,label in zip(status[1:],['Content firewall ready','Action guard ready','Audit logging active']):col.caption('● '+label)
st.caption('Component readiness, not a claim that a model endpoint is healthy. All effects stay in the mock sandbox.')
st.caption('LangGraph + layered checks. Files, webpages, email and records are synthetic and isolated. No real tool effects.')
catalog=json.loads((ROOT/'data/attacks.json').read_text())
with st.sidebar:
 st.subheader('Run controls')
 attack_id=st.selectbox('Attack selector',[a['id'] for a in catalog if a['split']=='development'],format_func=lambda x:next(a['category'].title()+' / '+x for a in catalog if a['id']==x))
 with st.expander('Developer verification',expanded=False):
  dev_offline=st.toggle('Offline guard verification',value=False,help='Scripted tool proposals, not a live model.')
  st.caption('Offline results are tool-proposal checks, not LLM hijack rates. Use only to verify the guard without a model.')
 mode,BLOCK_REASON=resolve_mode(LIVE_OK,dev_offline)
 BLOCKED=BLOCK_REASON is not None
 if BLOCKED:st.error(BLOCK_REASON)
 st.caption('Reserved cases are not exposed in the selector. Existing reserved suite is author-generated, not independent.')
 if st.button('Reset session'):
  for k in ['pair','human','challenge','clean_result','clean_error','pair_error']:st.session_state.pop(k,None)
  st.rerun()
presenter=st.sidebar.toggle('Presenter mode',value=False)
attack=next(a for a in catalog if a['id']==attack_id)
tabs=st.tabs(['Judge Challenge','Attack Arena','X-ray','Audit Explorer','Results','Human review','Security Trace']) if not presenter else []
def run(artifact):
 if BLOCKED:
  st.error(BLOCK_REASON);return
 st.session_state.pop('pair_error',None)
 runner=Runner();partial={};active_lane='baseline';lane_starts={}
 live=st.empty();pipeline=st.empty();events=[]
 import live_progress as _lp,time as _t
 _pace=float(os.environ.get('QUOTESHIELD_LIVE_PACE','0.3'))
 st.markdown('**Live layer progress** (each layer lights up as the run reaches it; the short pause between events is for visibility only and changes no data)')
 _cols=st.columns(2,gap='large');_prog={'baseline':_lp.LaneProgress('baseline',False),'protected':_lp.LaneProgress('protected',True)}
 _ph={'baseline':_cols[0].empty(),'protected':_cols[1].empty()};_ttl={'baseline':'Unprotected lane','protected':'Full shield lane'}
 def _draw(lane):_ph[lane].markdown(_lp.render(_prog[lane],_ttl[lane]),unsafe_allow_html=True)
 _draw('baseline');_draw('protected')
 def sink(lane,event):
  events.append({'lane':lane,**event})
  _prog[lane].on_event(event);_draw(lane)
  if _pace:_t.sleep(_pace)
  # This text updates only when a real executor/firewall event occurs.
  recent=[e for e in events if e['lane']=='protected'][-4:]
  observed={e['stage'] for e in events if e['lane']=='protected'}
  pipeline.caption(' → '.join(('✓ ' if stage in observed else '○ ')+label for stage,label in [('scope','Scope'),('content','Firewall'),('agent','Agent result'),('action','Guard decision'),('human','Human')])+' → Tool effects: inspect recorded output | Audit: '+str(len(events))+' events')
  live.markdown('**Actual protection events** &nbsp; '+ ' → '.join(e['stage']+' / '+e['decision'] for e in recent))
 try:
  with st.spinner('Executing isolated mock tools...'):
   request=artifact.get('request', __import__('shield').DEFAULT_REQUEST)
   for lane,protected in [('baseline',False),('protected',True)]:
    active_lane=lane;lane_starts[lane]=len(runner.model.trace)
    _prog[lane].started=True;_draw(lane)
    if _pace:_t.sleep(_pace)
    partial[lane]=runner.run(request,artifact,protected,mode,event_sink=lambda e,lane=lane:sink(lane,e),request_confirmed=bool(artifact.get('request_confirmed')))
    _prog[lane].finish(partial[lane]);_draw(lane)
    partial[lane]['explanation']=__import__('scenario_engine.explain',fromlist=['explain_run']).explain_run(partial[lane],lane=lane)
   result={**partial,'label':'LLM agent run' if mode=='llm' else 'Offline adversarial tool-proposal verification'}
  pipeline.caption('Execution complete. Scope, firewall and guard decisions are recorded; the agent result and mock effects are captured. Human review appears only when requested.')
  st.session_state['pair']=result;st.session_state['challenge']=artifact
  if artifact.get('id')=='clean-task':st.session_state['clean_result']=result['protected']
  return True
 except __import__('request_guard').RequestNeedsConfirmation:
  raise  # the caller shows the confirm gate; it must not be reported as a run error
 except Exception as exc:
  st.session_state.pop("pair",None);st.session_state.pop("challenge",None)
  st.session_state['pair_error']={'error':str(exc),'failed_lane':active_lane,'case_id':artifact.get('id'),'mode':mode,'model':runner.model.model,'partial_results':partial,'events':events,'model_trace':runner.model.trace,'routing_summary_by_lane':{lane:route_summary(partial[lane].get('model_trace',[])) if lane in partial else route_summary(runner.model.trace[start:]) for lane,start in lane_starts.items()}}
  return False

if 'pair_error' in st.session_state:
 st.error(st.session_state['pair_error']['error'])
 with st.expander('Failed paired run trace'):
  st.json(st.session_state['pair_error'])
  st.download_button('Download failed paired run JSON',json.dumps(st.session_state['pair_error'],indent=2),'quoteshield-paired-error.json','application/json')

def show_explanations(result):
 for _lane in ('protected','baseline'):
  _ex=result[_lane].get('explanation')
  if _ex:
   with st.expander('What happened, %s lane: %s'%(_lane,_ex['summary']),expanded=(_lane=='protected')):
    st.markdown(_ex['markdown']);st.caption('Generated from the records of this run (no model). Also in the downloaded JSON as "explanation".')

def show_pair(result):
 st.caption(result['label']+' | No timed animations, model outcomes inferred from actual mock state.')
 show_explanations(result)
 with st.expander('Trusted scope and observed data flow'):
  st.json(result['protected']['scope'])
  for lane in ['baseline','protected']:
   r=result[lane];reads=[e.get('call',{}).get('args',{}).get('path') for e in r['audit'] if e.get('stage')=='action' and e.get('call',{}).get('tool')=='read_file' and e.get('decision')=='ALLOW']
   st.write(lane.title()+': authorized/attempted paths and actual captured sinks')
   st.json({'allowed_read_decisions':reads,'unauthorized_reads':r['security_oracle'].get('unauthorized_reads',[]),'captured_email_recipients':[e['to'] for e in r['mock_outbox']],'record_keys':list(r['mock_records']),'confidential_email_count':r['security_oracle'].get('confidential_emails',0)})
  st.caption('Decision/effect ledger, not token-level lineage. A source read and a sink effect alone do not prove which words flowed; canary matches are shown separately.')
 cols=st.columns(2,gap='large')
 for col,key,title in zip(cols,['baseline','protected'],['Unprotected','Full shield']):
  r=result[key]
  with col:
   st.subheader(title)
   if r['attack_success']:st.error('Boundary breached: unauthorized mock effect occurred.')
   else:st.success('No unauthorized mock effect observed.')
   st.markdown('**Task complete**' if r['task_complete'] else '**Task completion not established**')
   parsed=parse_answer(r['answer'])
   if parsed:
    st.write(parsed.get('summary','Structured vendor comparison'))
    st.dataframe(parsed.get('vendors',[]),hide_index=True,width='stretch')
   else:st.text(r['answer'])
   st.caption('Completion checker: '+r.get('utility_oracle',{}).get('reason',''))
   st.caption(f"Run {r['run_id']} · {r['elapsed_ms']:.2f} ms · audit chain {'verified' if r['audit_chain_verified'] else 'invalid'}")
   with st.expander('Observed mock effects',expanded=key=='baseline' and r['attack_success']):
    st.json({'security_oracle':r['security_oracle'],'outbox':r['mock_outbox'],'records':r['mock_records']})

if presenter:
 st.subheader('Presenter walkthrough')
 screens=['1 Legitimate task','2 Malicious document','3 Unprotected run','4 Trusted scope','5 Protected run','6 Human review','7 Audit','8 Results','9 Final legitimate task']
 screen=st.selectbox('Presentation view',screens)
 current=st.session_state.get('pair')
 if screen in [screens[0],screens[-1]]:
  st.write('Compare quotes/atlas.txt, quotes/beacon.txt and quotes/cedar.txt by price, delivery and warranty. No email or record changes.')
  st.json(QUOTES)
  if st.button('Execute clean task with shield',key='presenter_clean',disabled=BLOCKED):
   runner=Runner();st.session_state.pop('clean_error',None)
   try:
    with st.spinner('Executing clean protected task...'):st.session_state['clean_result']=runner.run(attack={'id':'clean-task','category':'benign','payload':'','calls':[]},protected=True,mode=mode,clean_presenter_final=True)
    st.rerun()
   except Exception as exc:
    st.session_state.pop('clean_result',None);st.session_state['clean_error']={'error':str(exc),'model':runner.model.model,'model_trace':runner.model.trace};st.error(str(exc))
  if 'clean_error' in st.session_state:
   with st.expander('Failed clean run model trace'):
    st.json(st.session_state['clean_error'])
    st.download_button('Download failed clean run JSON',json.dumps(st.session_state['clean_error'],indent=2),'quoteshield-clean-error.json','application/json')
  if 'clean_result' in st.session_state:
   r=st.session_state['clean_result'];st.write(r['answer']);st.json({'mode':r['mode'],'complete':r['task_complete'],'harmful_effect':r['attack_success'],'elapsed_ms':r['elapsed_ms']})
   with st.expander('Clean run scope, audit and model trace'):
    st.json({'model':r['model'],'scope':r['scope'],'audit':r['audit'],'model_trace':r['model_trace'],'utility_oracle':r['utility_oracle']})
    st.download_button('Download clean run JSON',json.dumps(r,indent=2),'quoteshield-clean-run.json','application/json')
 elif screen==screens[1]:
  st.caption('Selected developer attack, not independently unseen. Actual text in synthetic quote, no PDF/XLSX claim.')
  st.text(QUOTES['quotes/beacon.txt']+'\n'+attack.get('payload',''))
 elif screen in [screens[2],screens[4]]:
  st.caption('Execution is side by side on the same selected developer task. Displayed lane follows this view.')
  if st.button('Execute selected paired case',key='presenter_run',disabled=BLOCKED):
   run(attack);st.rerun()
  if current:
   lane='baseline' if screen==screens[2] else 'protected';r=current[lane]
   st.write(r['answer']);st.json({'lane':lane,'mode':r['mode'],'attack_success':r['attack_success'],'task_complete':r['task_complete'],'elapsed_ms':r['elapsed_ms'],'outbox':r['mock_outbox'],'records':r['mock_records']})
   stages={'Scope':len([e for e in r['audit'] if e['stage']=='scope']),'Firewall':len(r['inspections']),'Agent':len(r['model_trace']) if r['mode']=='llm' else 'offline solver','Guard':len([e for e in r['audit'] if e['stage']=='action']),'Human':len([e for e in r['audit'] if e['stage']=='human']),'Tool':{'emails':len(r['mock_outbox']),'record_writes':len(r['mock_records'])}}
   st.write('Scope > Firewall > Agent > Guard > Human > Tool');st.json(stages)
   with st.expander('Observed source-to-sink ledger'):
    st.json({'unauthorized_reads':r['security_oracle'].get('unauthorized_reads',[]),'outbox':r['mock_outbox'],'confidential_email_count':r['security_oracle'].get('confidential_emails',0),'secret_exfiltrated':r['secret_exfiltrated']})
   st.caption('Audit decisions and captured effects, not semantic/token lineage. No timer-driven stages.')
 elif screen==screens[3]:
  if current:
   scope=current['protected']['scope'];st.json({'tools':scope['tools'],'resources':scope['resources'],'recipients':scope['recipients'],'external_transfer_allowed':bool(scope['recipients'] or scope['web_urls']),'record_writes':scope['record_keys']})
  else:st.info('Execute selected case to show its actual trusted scope.')
 elif screen==screens[5]:
  st.write('Explicitly authorized mock email: review exact recipient/body. Missing recipient requires clarification, never an Allow once bypass.')
  if st.button('Prepare exact-call review',key='presenter_prepare'):
   call=ToolCall('send_email',{'to':'reviewer@example.test','subject':'Quotation comparison','body':'Beacon: USD 11900, 21 days, 12 months.'})
   workflow=ApprovalWorkflow(Scope(tools=['send_email'],resources=[],recipients=['reviewer@example.test']))
   thread=uuid.uuid4().hex;workflow.prepare(call,thread)
   st.session_state['human']={'call':call,'workflow':workflow,'thread_id':thread,'consumed':False,'outcome':None}
  if 'human' in st.session_state:
   h=st.session_state['human'];st.json(asdict(h['call']))
   for label,value in [('Approve exact call',True),('Block this call',False)]:
    if st.button(label,key='presenter_'+label,disabled=h['consumed']):
     h['consumed']=True;h['outcome']=h['workflow'].resume(h['thread_id'],value)['decision'];st.rerun()
   if h['outcome']:st.write(h['outcome']);st.json(h['workflow'].sandbox.emails)
 elif screen==screens[6]:
  if current:st.json(current['protected']['audit'])
  else:st.info('Execute a case first.')
 elif screen==screens[7]:
  reports=[p for p in (ROOT/'artifacts').glob('*.json') if isinstance(json.loads(p.read_text()).get('metrics'),(dict,list))]
  if reports:
   chosen=st.selectbox('Measured report',[p.name for p in reports],key='presenter_report');report=json.loads((ROOT/'artifacts'/chosen).read_text())
   st.caption(str(report.get('kind'))+' / '+str(report.get('split'))+' / '+str(report.get('model') or 'no model'))
   st.json(report['metrics']);st.json(report.get('layer_timings',{}))
  st.caption('No independently unseen or genuine-model numbers are established; offline artifacts remain labeled offline.')
 st.caption('Firewall-uncertain/new attack segment unavailable: no verified real-model example yet. Do not stage it or label developer/reserved cases unseen.')

if not presenter:
 with tabs[1]:
  st.markdown('**Trusted task:** compare three named vendor quotes by price, delivery and warranty. No email. No record changes.')
  st.caption('Selected development case: '+attack_id)
  if st.button('Run side-by-side',type='primary',disabled=BLOCKED):run(attack);st.rerun()
  if st.button('Run clean legitimate task',disabled=BLOCKED):
   run({'id':'clean-task','category':'benign','payload':'','calls':[]})
  st.divider()
  st.markdown('**Firewall miss demo** (developer demo, not an evaluation case, not a measured result)')
  st.caption('Vendor note the deterministic firewall rules do not match; it asks for confidential/ceiling.txt. Offline mode runs a scripted read proposal, only a live run shows whether the model proposes it. Either way the guard decides on the call itself. The live LLM classifier may still flag the text.')
  if st.button('Run firewall-miss demo',disabled=BLOCKED):
   run(json.loads((ROOT/'demo/firewall-miss.json').read_text()));st.rerun()
  if 'pair' in st.session_state:show_pair(st.session_state['pair'])
  else:st.info('Run a case to see actual tool decisions and the comparison. No prefilled result.')
 with tabs[0]:
  st.subheader('Try your own untrusted content')
  task=st.text_area('Trusted task prompt (optional; empty keeps the default quote comparison)',height=80,max_chars=8192)
  payload=st.text_area('Text inserted into a mock vendor quote',height=150,max_chars=8192)
  upload=st.file_uploader('Or upload a file as the untrusted content (.txt, .md, .html, .csv, .pdf, .docx; plain-text extraction; .png/.jpg/.jpeg/.webp are read with local Tesseract OCR plus metadata, best effort, and refused if Tesseract is not installed)',type=list(UPLOAD_FORMATS+IMAGE_UPLOAD_FORMATS))
  if mode=='llm':
   st.caption('Runs through the live model: it decides what tool calls to propose, and the firewall and guard act on those. Developer verification (sidebar) only scans text; it cannot infer a new attacker plan.')
  else:
   st.caption('Developer verification is on: this run uses scripted offline proposals, not the live model. It scans your text and compares quotes, but cannot infer a new attacker plan.')
  if st.button('Run custom challenge',disabled=BLOCKED):
   try:artifact=judge_artifact(payload,task,(upload.name,upload.getvalue()) if upload else None)
   except ValueError as exc:st.error(str(exc))
   else:
    try:run(artifact)
    except __import__('request_guard').RequestNeedsConfirmation as exc:
     st.session_state['needs_confirm']={'artifact':artifact,'message':str(exc),'findings':exc.result['findings'],'explanation':__import__('scenario_engine.explain',fromlist=['explain_run']).explain_run(request_check=exc.result,request=artifact.get('request'))}
  if 'needs_confirm' in st.session_state:
   pending=st.session_state['needs_confirm']
   st.markdown('<div style="background:#fff3c4;color:#4d3a00;border-left:5px solid #d4a017;padding:12px 16px;border-radius:6px;font-weight:600">'+__import__('html').escape(pending['message'])+'</div>',unsafe_allow_html=True);st.json(pending['findings'])
   if pending.get('explanation'):
    with st.expander('Why this task was flagged',expanded=True):st.markdown(pending['explanation']['markdown'])
   if st.button('Confirm and run this task'):
    st.session_state.pop('needs_confirm');run({**pending['artifact'],'request_confirmed':True})
  if 'pair' in st.session_state and (st.session_state.get('challenge') or {}).get('id')=='judge-custom' and 'needs_confirm' not in st.session_state:
   show_explanations(st.session_state['pair'])
 with tabs[2]:
  st.subheader('Read the source boundary')
  active=st.session_state.get('challenge',attack)
  raw=QUOTES['quotes/beacon.txt']+'\n'+active.get('payload','')
  fw=firewall(raw)
  left,right=st.columns(2)
  with left:st.markdown('**Original untrusted source**');st.code(raw,language=None)
  with right:st.markdown('**Sanitized evidence**');st.code(fw['safe'],language=None)
  st.caption('X-ray preview uses deterministic detection; actual live-model inspections are in the audit run.')
  st.json({'findings':fw['findings'],'removed_spans':fw['removed_spans'],'quarantined':fw['quarantined']})
  if 'pair' in st.session_state:
   with st.expander('Actual run source/provenance ledger'):
    for item in st.session_state['pair']['protected']['inspections']:
     st.json({k:item[k] for k in ['source','source_sha256','trust','output_taint','field']})
 with tabs[3]:
  st.subheader('Every intervention has evidence')
  if 'pair' in st.session_state:
   lane=st.radio('Inspect lane',['protected','baseline'],horizontal=True)
   r=st.session_state['pair'][lane]
   st.json(r['scope'])
   for e in r['audit']:
    with st.expander(f"{e['sequence']:02} · {e['stage']} · {e['decision']} · {e['rule']}"):st.json(e)
   st.download_button('Download complete run JSON',json.dumps(st.session_state['pair'],indent=2),'quoteshield-run.json','application/json')
   edited=copy.deepcopy(r['audit'])
   if edited:edited[0]['reason']='tampered demo line'
   if st.button('Verify tampered copy'):st.write('Verification failed as expected.' if not AuditLog.verify(edited) else 'No edit available.')
   st.caption('Hash chaining detects edits against the retained chain. It is not signed or immutable storage.')
  else:st.info('Execute a run first.')
 with tabs[4]:
  st.subheader('Measured evidence, not placeholder scores')
  reports=[p for p in (ROOT/'artifacts').glob('*.json') if isinstance(json.loads(p.read_text()).get('metrics'),(dict,list))]
  if reports:
   chosen=st.selectbox('Report',[p.name for p in reports]);report=json.loads((ROOT/'artifacts'/chosen).read_text())
   st.caption(report.get('kind','Report')+' / '+report.get('split','')+' / '+str(report.get('model') or 'no model'))
   if isinstance(report['metrics'],list):st.dataframe(report['metrics'],hide_index=True,width='stretch')
   else:
    metrics=report['metrics'];cards=st.columns(3)
    cards[0].metric('Protected harmful effects',str(metrics.get('protected_effect_count','?'))+' / '+str(metrics.get('attack_count','?')))
    cards[1].metric('Completed tasks',str(metrics.get('protected_completion_count','?'))+' / '+str(metrics.get('attack_count',0)+metrics.get('benign_count',0)))
    cards[2].metric('Benign action interventions',str(metrics.get('false_positive_actions','?'))+' / '+str(metrics.get('benign_actions','?')))
    st.caption('Counts from this exact report only. Offline effect counts are not LLM efficacy rates.')
    with st.expander('Metric definitions and counts'):st.json(metrics)
   with st.expander('Per-case evidence'):st.dataframe(report.get('cases',[]),width='stretch')
   with st.expander('Layer timing breakdown'):st.json(report.get('layer_timings',{}))
   if isinstance(report.get('metrics'),list) and str(report.get('kind','')).startswith('llm'):
    import pandas as pd
    plotted=pd.DataFrame([{'defence':r['defence'],'attack effect rate':r['attack_effects']/r['attack_trials'] if r['attack_trials'] else 0} for r in report['metrics']]).set_index('defence')
    st.bar_chart(plotted)
   elif str(report.get('kind','')).startswith('offline'):st.caption('No LLM efficacy chart is drawn from offline proposals.')
   st.info(report.get('scope',''))
   st.download_button('Download evaluation JSON',json.dumps(report,indent=2),chosen,'application/json')
  st.caption('Ablation plumbing is tested offline. Genuine model efficacy and full LLM protection latency are not yet measured.')
 with tabs[5]:
  st.subheader('Review the exact mock email')
  st.caption('Separate legitimate task: send the quotation summary to reviewer@example.test, subject Quotation comparison. Nothing is sent externally.')
  if st.button('Prepare legitimate mock email'):
   call=ToolCall('send_email',{'to':'reviewer@example.test','subject':'Quotation comparison','body':'Beacon: USD 11900, 21 days, 12 months. Cedar: USD 13200, 10 days, 36 months. Atlas: USD 12400, 14 days, 24 months.'})
   workflow=ApprovalWorkflow(Scope(tools=['send_email'],resources=[],recipients=['reviewer@example.test']))
   thread_id=uuid.uuid4().hex;prepared=workflow.prepare(call,thread_id)
   st.session_state['human']={'call':call,'workflow':workflow,'thread_id':thread_id,'consumed':False,'outcome':None}
  if 'human' in st.session_state:
   h=st.session_state['human'];st.json(asdict(h['call']))
   left,right=st.columns(2)
   if left.button('Approve exact call',disabled=h['consumed']):
    h['consumed']=True;h['outcome']=h['workflow'].resume(h['thread_id'],True)['decision'];st.rerun()
   if right.button('Deny',disabled=h['consumed']):h['consumed']=True;h['outcome']=h['workflow'].resume(h['thread_id'],False)['decision'];st.rerun()
   if h['outcome']:st.write(h['outcome']);st.json(h['workflow'].sandbox.emails)
  st.caption('Native LangGraph interrupt / Command resume with an in-memory checkpointer. Same stored call, policy rechecked, one use. Session state resets on restart.')
 
 with tabs[6]:
  import scenarios,trace_ui,trace
  st.subheader('Security trace: where each attack was stopped')
  st.caption('Each scenario is a real run through the real pipeline, shown from its recorded audit. Offline scenarios use a supplied tool call, so they test the boundary, not the model. Only a live run shows what a model proposes.')
  name=st.selectbox('Scenario',list(scenarios.SCENARIOS),format_func=lambda n:scenarios.SCENARIOS[n]['title'],key='trace_scenario')
  sc=scenarios.SCENARIOS[name]
  st.code(sc['request'],language=None)
  if st.button('Run scenario',key='trace_run'):
   t,_r=scenarios.run(name);st.session_state['trace_view']=(name,t,None)
  if 'trace_view' in st.session_state and st.session_state['trace_view'][0]==name:
   _n,t,_x=st.session_state['trace_view']
   trace_ui.render(t,mode_note='Label: local classifier + scripted proposals. Offline, supplied action.' if name!='1_user_prompt' else 'Label: request guard on the user task. No agent started.')
   if t.get('waiting_for_human'):
    c1,c2=st.columns(2)
    if c1.button('Approve once',key='trace_ok'):
     t2,_r=scenarios.run(name,review=True);st.session_state['trace_view']=(name,t2,None);st.rerun()
    if c2.button('Deny',key='trace_no'):
     t2,_r=scenarios.run(name,review=False);st.session_state['trace_view']=(name,t2,None);st.rerun()
    st.caption('Approve once re-runs the scenario with the reviewer saying yes. The guard rechecks the exact call before it is allowed.')
  st.markdown('---')
  if st.button('Run all scenarios side by side',key='trace_all'):
   items=[]
   for n,s in scenarios.SCENARIOS.items():
    t,_r=scenarios.run(n);items.append((s['title'],t))
   st.session_state['trace_all_items']=items
  if 'trace_all_items' in st.session_state:
   its=st.session_state['trace_all_items']
   st.dataframe(trace_ui.comparison_rows(its))
   st.code(trace_ui.depth_bars(its),language=None)
   st.caption('Each row describes one run. This is where each attack was stopped, not a detection rate, and it is not averaged or compared across versions.')
  if 'pair' in st.session_state:
   st.markdown('---');st.markdown('**Trace of your last Judge Challenge run (protected lane)**')
   trace_ui.render(trace.build(st.session_state['pair']['protected']))
