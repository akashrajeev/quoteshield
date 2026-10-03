"""Optional local prompt-injection classifier for the content firewall.

Model: ProtectAI deberta-v3-base-prompt-injection-v2 (Apache 2.0, English only,
ONNX, CPU). It is OFF by default. Enable with SHIELD_LOCAL_CLASSIFIER=1 and point
SHIELD_LOCAL_CLASSIFIER_DIR at a folder holding tokenizer.json and
onnx/model.onnx (python local_classifier.py --download DIR fetches them once;
the model file is about 739 MB and is never committed).

Findings use the firewall's existing 'semantic' shape, so line removal and the
whole-document quarantine fallback in shield.firewall work unchanged. If it is
enabled but cannot load, the run stops (fail closed), like the LLM classifier.
Not a benchmark claim: it is a text-layer signal; the action guard decides actions.
"""
from __future__ import annotations
import os, sys, urllib.request
from pathlib import Path

RULE = 'local classifier'
MODEL_REPO = 'protectai/deberta-v3-base-prompt-injection-v2'
MODEL_FILES = ['config.json', 'tokenizer.json', 'onnx/model.onnx']
MAX_CHUNK_CHARS = 1200      # about 300 tokens; the model reads at most 512
MAX_CHUNKS = 64             # scan budget per firewall call; beyond it we quarantine
MAX_FINDINGS = 8

class LocalClassifier:
 def __init__(self, model_dir, threshold=0.5):
  import numpy as np, onnxruntime as ort
  from tokenizers import Tokenizer
  d = Path(model_dir)
  if not (d/'tokenizer.json').is_file() or not (d/'onnx'/'model.onnx').is_file():
   raise RuntimeError('Local classifier files missing in %s; run: python local_classifier.py --download DIR' % d)
  self.np = np; self.threshold = float(threshold); self.cache = {}
  self.tokenizer = Tokenizer.from_file(str(d/'tokenizer.json')); self.tokenizer.enable_truncation(512)
  options = ort.SessionOptions(); options.intra_op_num_threads = 2
  # Lower peak memory (about 1.3 GB measured) at some speed cost.
  options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_DISABLE_ALL
  options.enable_cpu_mem_arena = False; options.enable_mem_pattern = False
  self.session = ort.InferenceSession(str(d/'onnx'/'model.onnx'), options, providers=['CPUExecutionProvider'])
 def score(self, text):
  """Probability of the INJECTION label (label index 1)."""
  if text in self.cache: return self.cache[text]
  np = self.np; enc = self.tokenizer.encode(text)
  logits = self.session.run(None, {'input_ids': np.array([enc.ids], dtype=np.int64), 'attention_mask': np.array([enc.attention_mask], dtype=np.int64)})[0][0]
  e = np.exp(logits - logits.max()); value = float((e/e.sum())[1])
  if len(self.cache) < 4096: self.cache[text] = value
  return value
 def findings(self, views):
  """views: [(label, text)] from shield.decode_views. Returns firewall findings."""
  out = []; budget = MAX_CHUNKS; seen = set()
  for label, text in views:
   for chunk in _chunks(text):
    if chunk in seen: continue
    seen.add(chunk)
    if budget <= 0:
     return out + [{'rule': RULE, 'encoding': 'semantic', 'snippet': '', 'reason': 'scan budget exceeded; document quarantined'}]
    budget -= 1
    if self.score(chunk) < self.threshold: continue
    hits = [(line, self.score(line)) for line in chunk.splitlines() if line.strip() and line not in seen]
    hits = [(l, s) for l, s in hits if s >= self.threshold]
    if not hits: hits = [(chunk, self.score(chunk))]   # multi-line pattern: cannot localise, firewall quarantines
    for line, s in hits[:MAX_FINDINGS]:
     out.append({'rule': RULE, 'encoding': 'semantic', 'snippet': line[:180], 'reason': 'ProtectAI deberta-v3-base-prompt-injection-v2 score %.2f in view "%s"' % (s, label)})
   if len(out) >= MAX_FINDINGS: break
  return out[:MAX_FINDINGS]

def _chunks(text):
 chunk = ''
 for line in text.splitlines():
  if chunk and len(chunk) + len(line) + 1 > MAX_CHUNK_CHARS:
   yield chunk; chunk = ''
  chunk = (chunk + '\n' + line) if chunk else line
  while len(chunk) > MAX_CHUNK_CHARS:
   yield chunk[:MAX_CHUNK_CHARS]; chunk = chunk[MAX_CHUNK_CHARS:]
 if chunk.strip(): yield chunk

_instance = None; _override = False

def configure(classifier):
 """Tests and callers can install a classifier object (or None to turn it off)."""
 global _instance, _override
 _instance = classifier; _override = True

def get():
 global _instance
 if _override: return _instance
 if os.environ.get('SHIELD_LOCAL_CLASSIFIER', '').lower() not in ('1', 'true', 'yes'): return None
 if _instance is None:
  directory = os.environ.get('SHIELD_LOCAL_CLASSIFIER_DIR', '')
  if not directory: raise RuntimeError('SHIELD_LOCAL_CLASSIFIER is on but SHIELD_LOCAL_CLASSIFIER_DIR is not set')
  _instance = LocalClassifier(directory, os.environ.get('SHIELD_LOCAL_CLASSIFIER_THRESHOLD', '0.5'))
 return _instance

def download(directory):
 for name in MODEL_FILES:
  target = Path(directory)/name; target.parent.mkdir(parents=True, exist_ok=True)
  if not target.exists():
   urllib.request.urlretrieve('https://huggingface.co/%s/resolve/main/%s' % (MODEL_REPO, name), target)
 return str(directory)

if __name__ == '__main__':
 if len(sys.argv) == 3 and sys.argv[1] == '--download': print(download(sys.argv[2]))
 else: print('usage: python local_classifier.py --download DIR')
