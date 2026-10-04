import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import local_classifier

class FakeModel:
 model_name='ProtectAI deberta-v3-base-prompt-injection-v2';threshold=0.5
 def __init__(self,*a,**k):pass
 def score(self,text):return 0.99 if 'ignore previous' in text.lower() else 0.02

class Check(unittest.TestCase):
 def setUp(self):self.orig=local_classifier.LocalClassifier;local_classifier.LocalClassifier=FakeModel
 def tearDown(self):local_classifier.LocalClassifier=self.orig
 def test_check_passes_when_injection_high_and_plain_quote_low(self):
  r=local_classifier.check('anywhere')
  self.assertTrue(r['ok']);self.assertEqual(r['model'],FakeModel.model_name)
  self.assertGreaterEqual(r['injection_score'],0.5);self.assertLess(r['benign_score'],0.5)
 def test_check_fails_when_model_does_not_separate_them(self):
  FakeModel.score=lambda self,t:0.99
  try:self.assertFalse(local_classifier.check('anywhere')['ok'])
  finally:FakeModel.score=lambda self,t:0.99 if 'ignore previous' in t.lower() else 0.02

if __name__=='__main__':unittest.main()
