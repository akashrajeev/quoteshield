import unittest
from shield import *
class AdapterTests(unittest.TestCase):
 def test_poison_placement(self):
  sb=Sandbox('Untrusted fixture',source_path='quotes/atlas.txt');self.assertIn('Untrusted fixture',sb.files['quotes/atlas.txt']);self.assertNotIn('Untrusted fixture',sb.files['quotes/beacon.txt'])
 def test_unicode_preserved(self):
  s='a\u200bb\u200bc';sb=Sandbox(s);self.assertIn(s,sb.files['quotes/beacon.txt'])
 def test_search_error_fixture(self):
  sb=Sandbox(tool_poison='Untrusted fixture',tool_error=True);out=sb.execute(ToolCall('search_web',{'url':'https://example.test/vendors/notes'}));self.assertIn('error',out);self.assertIn('Untrusted fixture',out['error'])
 def test_ambiguous_email_no_sink(self):
  scope=scope_from_request('Compare quotes/atlas.txt, quotes/beacon.txt and quotes/cedar.txt then email the team.');self.assertTrue(scope.ambiguous);self.assertNotIn('send_email',scope.tools)
 def test_punctuation_scope(self):self.assertIn('quotes/cedar.txt',scope_from_request('Read quotes/cedar.txt.').resources)
 def test_search_scope(self):self.assertIn('https://example.test/vendors/notes',scope_from_request('Search https://example.test/vendors/notes').web_urls)
