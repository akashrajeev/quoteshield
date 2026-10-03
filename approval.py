"""Native LangGraph interrupt/resume for exact mock calls."""
from dataclasses import asdict
from typing import TypedDict
from langgraph.graph import StateGraph,END
from langgraph.types import interrupt,Command
from langgraph.checkpoint.memory import InMemorySaver
from shield import Guard,Sandbox,Scope,ToolCall
class ReviewState(TypedDict,total=False):
 call:dict
 decision:str
 outbox:list
class ApprovalWorkflow:
 def __init__(self,scope:Scope,sandbox=None):
  self.sandbox=sandbox or Sandbox();self.guard=Guard(scope,self.sandbox)
  def review(state):
   # Precheck hard denies before showing an approval prompt.
   exact=ToolCall(**state['call']);decision=self.guard.inspect(exact)
   if decision.verdict=='BLOCK':return {'decision':'BLOCK','outbox':self.sandbox.emails}
   if decision.verdict=='ASK HUMAN':
    choice=interrupt({'call':state['call'],'reason':decision.reason,'review':'Approve or deny this exact mock call.'})
    if choice is not True:return {'decision':'DENIED','outbox':self.sandbox.emails}
   # Resume rechecks all policy, including new confidential taint.
   decision=self.guard.inspect(exact,state['call'])
   if decision.verdict=='ALLOW':self.sandbox.execute(exact)
   return {'decision':decision.verdict,'outbox':self.sandbox.emails}
  graph=StateGraph(ReviewState);graph.add_node('review',review);graph.set_entry_point('review');graph.add_edge('review',END)
  self.graph=graph.compile(checkpointer=InMemorySaver());self.consumed=set()
 def prepare(self,call,thread_id):
  if thread_id in self.consumed:raise ValueError('Review already consumed')
  config={'configurable':{'thread_id':thread_id}}
  return self.graph.invoke({'call':asdict(call)},config)
 def resume(self,thread_id,approve):
  config={'configurable':{'thread_id':thread_id}}
  state=self.graph.get_state(config)
  if thread_id in self.consumed or not state.next:raise ValueError('Review missing or already consumed')
  self.consumed.add(thread_id)
  return self.graph.invoke(Command(resume=approve is True),config)
