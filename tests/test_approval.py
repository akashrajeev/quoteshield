import unittest
from approval import *
class ApprovalTests(unittest.TestCase):
 def workflow(self):
  return ApprovalWorkflow(Scope(tools=['send_email'],recipients=['reviewer@example.test']))
 def call(self):return ToolCall('send_email',{'to':'reviewer@example.test','subject':'Comparison','body':'Safe mock summary'})
 def test_interrupt_resume(self):
  w=self.workflow();result=w.prepare(self.call(),'one');self.assertTrue(result['__interrupt__']);self.assertEqual(len(w.sandbox.emails),0)
  r=w.resume('one',True);self.assertEqual(r['decision'],'ALLOW');self.assertEqual(len(r['outbox']),1)
  with self.assertRaises(ValueError):w.resume('one',True)
 def test_denial(self):
  w=self.workflow();w.prepare(self.call(),'two');self.assertEqual(w.resume('two',False)['decision'],'DENIED');self.assertFalse(w.sandbox.emails)
 def test_revalidation(self):
  w=self.workflow();w.prepare(self.call(),'three');w.sandbox.execute(ToolCall('read_file',{'path':'confidential/ceiling.txt'}));self.assertEqual(w.resume('three',True)['decision'],'BLOCK');self.assertFalse(w.sandbox.emails)
 def test_hard_deny_no_interrupt(self):
  w=self.workflow();r=w.prepare(ToolCall('send_email',{'to':'outside@example.test','body':'safe'}),'four');self.assertNotIn('__interrupt__',r);self.assertEqual(r['decision'],'BLOCK')
