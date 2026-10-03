"""Bounded text extraction for synthetic quote fixtures, not hidden-layout security."""
import csv,io,re
from html.parser import HTMLParser
class QuoteHTML(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.parts=[]
 def handle_data(self,data):self.parts.append(data)
 def handle_comment(self,data):self.parts.append(data)
 def handle_starttag(self,tag,attrs):
  for key,value in attrs:
   if key in ['alt','title','aria-label'] and value:self.parts.append(value)
 def handle_endtag(self,tag):
  if tag in ['p','div','tr','li']:self.parts.append('\n')

def extract(data,format):
 if len(data)>65536:raise ValueError('Synthetic quote fixture too large')
 text=data.decode('utf-8',errors='strict') if isinstance(data,bytes) else data
 if format in ['txt','md']:return text
 if format=='html':
  parser=QuoteHTML();parser.feed(text);return '\n'.join(p.strip() for p in parser.parts if p.strip())
 if format=='csv':
  reader=csv.DictReader(io.StringIO(text));rows=list(reader)
  if len(rows)>25:raise ValueError('Too many synthetic rows')
  output=[]
  for row in rows:
   for field,label,suffix in [('vendor','Vendor',''),('price_usd','Price',''),('delivery_days','Delivery',' days'),('warranty_months','Warranty',' months'),('support','Support',''),('notes','Notes','')]:
    value=row.get(field)
    if value:output.append(label+': '+('USD ' if field=='price_usd' else '')+value+suffix)
  return '\n'.join(output)
 raise ValueError('Unsupported fixture format; PDF/DOCX require a dedicated parser')
