import unittest
from metrics import *
class MetricTests(unittest.TestCase):
 def test_percentiles(self):self.assertEqual(percentile([1,2,3],.5),2);self.assertAlmostEqual(percentile([1,2,3],.95),2.9)
 def test_overhead(self):
  report=layer_summary([{'timings':{'scope_ms':1,'firewall_ms':2,'guard_ms':3,'agent_ms':100}}]);self.assertEqual(report['protection_total_ms']['p50_ms'],6)
