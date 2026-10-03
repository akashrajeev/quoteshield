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


UPLOAD_FORMATS=('txt','md','html','csv','pdf','docx')
DOC_UPLOAD_FORMATS=('pdf','docx')
UPLOAD_REFUSED_FORMATS=('png','jpg','jpeg','webp')  # offered by the uploader only so the explicit OCR-not-supported refusal is shown
def upload_text(filename,data):
 """Plain-text extraction of one uploaded file for the Judge Challenge slot. No layout fidelity and no OCR. PDF/DOCX go through extractors_doc; images are refused."""
 name=str(filename or '');ext=name.rsplit('.',1)[-1].lower() if '.' in name else ''
 if ext in DOC_UPLOAD_FORMATS or ext in UPLOAD_REFUSED_FORMATS:
  from extractors_doc import extract_document
  return extract_document(name,data)
 if ext not in UPLOAD_FORMATS:raise ValueError('Unsupported file type. Upload '+', '.join('.'+f for f in UPLOAD_FORMATS)+' only. Images are not supported (no OCR yet) and other formats are not parsed.')
 if not isinstance(data,(bytes,bytearray)):raise ValueError('Upload must be raw bytes.')
 try:text=extract(bytes(data),ext)
 except UnicodeDecodeError:raise ValueError('File is not valid UTF-8 text.')
 if not text.strip():raise ValueError('No text could be extracted from this file.'+(' CSV extraction keeps only the vendor, price_usd, delivery_days, warranty_months, support and notes columns.' if ext=='csv' else ''))
 return text

def judge_artifact(payload='',task='',upload=None):
 """Build the Judge Challenge artifact. upload is (filename,bytes) or None. An empty task keeps the default trusted request."""
 if upload is not None and payload.strip():raise ValueError('Use either the text box or a file, not both.')
 text=upload_text(*upload) if upload is not None else payload
 artifact={'id':'judge-custom','payload':text,'calls':[]}
 if task.strip():
  if len(task)>8192:raise ValueError('Task exceeds the 8192 character limit.')
  artifact['request']=task.strip()
 return artifact
