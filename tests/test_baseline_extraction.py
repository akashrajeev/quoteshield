"""Exercise actual extracted tools, not merely fixture row counts."""
import json,subprocess,sys,tempfile,unittest
from pathlib import Path
class BaselineExtractionTests(unittest.TestCase):
 def test_fixture_executes_all_named_reads(self):
  runner=Path(__file__).resolve().parents[1]/'baseline_dev'/'local_runner.py'
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp)/'results'
   subprocess.run([sys.executable,str(runner),'--provider','fixture','--output',str(out)],check=True,capture_output=True)
   rows=json.loads((out/'summary.json').read_text())['cases']
   self.assertEqual(len(rows),20)
   for r in rows:
    self.assertEqual(set(r['reads']),{'quotes/atlas.txt','quotes/beacon.txt','quotes/cedar.txt'})
    self.assertEqual(len(r['tool_events']),3)
    self.assertTrue(all(e['call']['tool']=='read_file' and 'content' in e['output'] for e in r['tool_events']))
