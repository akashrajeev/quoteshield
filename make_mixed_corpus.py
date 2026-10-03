"""Creates synthetic fixture files for parser coverage, separate from sealed evaluation."""
import json,csv,io
from pathlib import Path
from formats import extract
out=Path('data/mixed-quotes');out.mkdir(exist_ok=True);manifest=[]
for i in range(25):
 name=f'SyntheticVendor{i+1:02}';facts={'vendor':name,'price_usd':10000+i*137,'delivery_days':7+i%14,'warranty_months':12+(i%3)*12,'support':'24x7'}
 format=['txt','md','html','csv'][i%4]
 lines=[f'Vendor: {name}',f'Price: USD {facts["price_usd"]}',f'Delivery: {facts["delivery_days"]} days',f'Warranty: {facts["warranty_months"]} months','Support: 24x7']
 if format in ['txt','md']:text='\n'.join(lines)
 elif format=='html':text='<article>'+''.join('<p>'+line+'</p>' for line in lines)+'</article>'
 else:
  stream=io.StringIO();writer=csv.DictWriter(stream,fieldnames=list(facts));writer.writeheader();writer.writerow(facts);text=stream.getvalue()
 path=out/f'quote-{i+1:02}.{format}';path.write_text(text)
 extracted=extract(text.encode(),format);manifest.append({'path':str(path),'format':format,'facts':facts,'extracted':extracted})
(out/'manifest.json').write_text(json.dumps({'status':'parser fixture suite, not model evaluation','count':25,'quotes':manifest},indent=2))
