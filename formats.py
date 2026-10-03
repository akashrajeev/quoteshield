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


FIREWALL_SCAN_LIMIT=32768  # the firewall only scans/passes the first 32768 characters; longer uploads are refused, never truncated
UPLOAD_FORMATS=('txt','md','html','csv','pdf','docx')
DOC_UPLOAD_FORMATS=('pdf','docx')
IMAGE_UPLOAD_FORMATS=('png','jpg','jpeg','webp')  # read by extractors_image (local Tesseract OCR + metadata); refused loudly if Tesseract is missing
UPLOAD_REFUSED_FORMATS=()  # nothing is offered only to be refused any more; other types are rejected as unsupported
def upload_text(filename,data):
 """Plain-text extraction of one uploaded file for the Judge Challenge slot. No layout fidelity. PDF/DOCX go through extractors_doc; png/jpg/jpeg/webp go through extractors_image (best-effort OCR + metadata, refused loudly when OCR cannot run)."""
 name=str(filename or '');ext=name.rsplit('.',1)[-1].lower() if '.' in name else ''
 if ext in IMAGE_UPLOAD_FORMATS:
  from extractors_image import extract_image
  return _within_scan_limit(extract_image(name,data))
 if ext in DOC_UPLOAD_FORMATS:
  from extractors_doc import extract_document
  return _within_scan_limit(extract_document(name,data))
 if ext not in UPLOAD_FORMATS:raise ValueError('Unsupported file type. Upload '+', '.join('.'+f for f in UPLOAD_FORMATS)+' only. Images ('+', '.join('.'+f for f in IMAGE_UPLOAD_FORMATS)+') need local Tesseract OCR; other formats are not parsed.')
 if not isinstance(data,(bytes,bytearray)):raise ValueError('Upload must be raw bytes.')
 try:text=extract(bytes(data),ext)
 except UnicodeDecodeError:raise ValueError('File is not valid UTF-8 text.')
 if not text.strip():raise ValueError('No text could be extracted from this file.'+(' CSV extraction keeps only the vendor, price_usd, delivery_days, warranty_months, support and notes columns.' if ext=='csv' else ''))
 return _within_scan_limit(text)

def _within_scan_limit(text):
 """Fail closed on the FULL source the firewall will see: the existing Beacon quote + a joining newline + the payload.
 Anything past FIREWALL_SCAN_LIMIT would be dropped unscanned, so the upload is refused instead of truncated."""
 from shield import QUOTES
 total=len(QUOTES['quotes/beacon.txt'])+1+len(text)
 if total>FIREWALL_SCAN_LIMIT:
  room=max(FIREWALL_SCAN_LIMIT-len(QUOTES['quotes/beacon.txt'])-1,0)
  raise ValueError('Combined source is %d characters (existing Beacon quote + joining newline + your %d); the firewall scans at most %d, so at most %d characters of upload text fit. Refused; nothing was truncated or passed on unscanned.'%(total,len(text),FIREWALL_SCAN_LIMIT,room))
 return text

def judge_artifact(payload='',task='',upload=None):
 """Build the Judge Challenge artifact. upload is (filename,bytes) or None. An empty task keeps the default trusted request."""
 if upload is not None and payload.strip():raise ValueError('Use either the text box or a file, not both.')
 text=upload_text(*upload) if upload is not None else _within_scan_limit(payload)
 artifact={'id':'judge-custom','payload':text,'calls':[]}
 if task.strip():
  if len(task)>8192:raise ValueError('Task exceeds the 8192 character limit.')
  artifact['request']=task.strip()
 return artifact
