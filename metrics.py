"""Transparent task/action metrics and empirical percentile reporting."""
import math,statistics

def percentile(values,p):
 if not values:return None
 s=sorted(values);rank=(len(s)-1)*p;lo=math.floor(rank);hi=math.ceil(rank)
 return s[lo]+(s[hi]-s[lo])*(rank-lo)

def layer_summary(results):
 summary={}
 for key in ['scope_ms','firewall_ms','guard_ms','agent_ms']:
  values=[r['timings'][key] for r in results]
  summary[key]={'p50_ms':percentile(values,.5),'p95_ms':percentile(values,.95),'max_ms':max(values) if values else None,'n':len(values)}
 overhead=[r['timings']['scope_ms']+r['timings']['firewall_ms']+r['timings']['guard_ms'] for r in results]
 summary['protection_total_ms']={'p50_ms':percentile(overhead,.5),'p95_ms':percentile(overhead,.95),'max_ms':max(overhead) if overhead else None,'n':len(overhead)}
 return summary
