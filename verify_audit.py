import argparse,json
from pathlib import Path
from security import AuditLog
p=argparse.ArgumentParser();p.add_argument('path');a=p.parse_args();obj=json.loads(Path(a.path).read_text())
entries=obj if isinstance(obj,list) else obj.get('audit')
if entries is None and 'protected' in obj:entries=obj['protected']['audit']
if entries is None:raise ValueError('No audit entries')
valid=AuditLog.verify(entries);print('VERIFIED' if valid else 'INVALID');raise SystemExit(0 if valid else 1)
