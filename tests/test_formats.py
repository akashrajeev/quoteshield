import json,unittest
from formats import extract
from pathlib import Path
class FormatTests(unittest.TestCase):
 def test_generated_25(self):
  corpus=json.loads(Path('data/mixed-quotes/manifest.json').read_text());self.assertEqual(corpus['count'],25)
  for q in corpus['quotes']:
   text=extract(Path(q['path']).read_bytes(),q['format']);self.assertIn(q['facts']['vendor'],text);self.assertIn(str(q['facts']['price_usd']),text)
 def test_html_comments_alt_hidden_exposed(self):
  text=extract('<p style="display:none">hidden text</p><!--comment--><img alt="alt text">','html')
  for part in ['hidden text','comment','alt text']:self.assertIn(part,text)
 def test_unicode_bytes_preserved(self):self.assertEqual(extract('x\u200by'.encode(),'txt'),'x\u200by')
 def test_bounds(self):
  with self.assertRaises(ValueError):extract('x'*65537,'txt')
 def test_pdf_not_falsely_supported(self):
  with self.assertRaises(ValueError):extract('not a pdf','pdf')
