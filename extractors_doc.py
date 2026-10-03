"""Best-effort text extraction for PDF and DOCX uploads. Images are refused (no OCR in this version). Output feeds the firewall as UNTRUSTED text.
Not layout fidelity, not a security guarantee. Anything unsupported fails loudly; nothing is silently skipped."""
import io,re,zipfile,zlib
import xml.etree.ElementTree as ET

MAX_BYTES=5*1024*1024;MAX_TEXT=65536;MAX_PDF_PAGES=20
MAX_DOCX_ENTRIES=200;MAX_DOCX_MEMBER=2*1024*1024;MAX_DOCX_TOTAL=10*1024*1024
DOC_FORMATS=('pdf','docx')
IMAGE_FORMATS=('png','jpg','jpeg','webp','gif','bmp','tif','tiff')
W='{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'

def _fail(msg):raise ValueError(msg)
def _cap(parts,label):
 text='\n'.join(p for p in parts if p and p.strip())
 if len(text)>MAX_TEXT:_fail(label+' text exceeds the 64 KB extraction limit.')
 if not text.strip():_fail('No text could be extracted from this '+label+'.')
 return text

def extract_pdf(data):
 try:from pypdf import PdfReader
 except ImportError:_fail('PDF support needs the pypdf package.')
 try:
  reader=PdfReader(io.BytesIO(data))
  if reader.is_encrypted:_fail('Encrypted PDFs are not supported.')
  root=reader.trailer['/Root']
  if '/OpenAction' in root or '/AA' in root:_fail('PDFs with automatic actions are not supported.')
  names=root.get('/Names',{})
  names=names.get_object() if hasattr(names,'get_object') else names
  if '/EmbeddedFiles' in names or '/JavaScript' in names:_fail('PDFs with embedded files or JavaScript are not supported.')
  if len(reader.pages)>MAX_PDF_PAGES:_fail('PDF has more than %d pages.'%MAX_PDF_PAGES)
  parts=[];meta=reader.metadata or {}
  for key in ['/Title','/Author','/Subject','/Keywords']:
   if meta.get(key):parts.append('[pdf metadata %s] %s'%(key[1:],meta.get(key)))
  def walk(outline):
   for item in outline:
    if isinstance(item,list):walk(item)
    else:parts.append('[pdf bookmark] '+str(getattr(item,'title',item)))
  walk(reader.outline)
  page_text=0
  for number,page in enumerate(reader.pages,1):
   if page.get('/AA'):_fail('PDFs with automatic actions are not supported.')
   text=page.extract_text() or ''
   if text.strip():page_text+=1;parts.append(text)
   for annot in page.get('/Annots') or []:
    annot=annot.get_object()
    if annot.get('/A') and annot['/A'].get_object().get('/S') in ('/JavaScript','/Launch'):_fail('PDFs with script or launch actions are not supported.')
    for key,label in [('/Contents','annotation'),('/V','form field')]:
     value=annot.get(key)
     if value not in (None,'') and str(value).strip():parts.append('[pdf %s p%d] %s'%(label,number,value))
  if not page_text:_fail('PDF has no text layer (scanned PDF). Page OCR is not supported in this version, so the PDF was refused.')
 except ValueError:raise
 except Exception as exc:_fail('Corrupt or unreadable PDF ('+type(exc).__name__+').')
 return _cap(parts,'PDF')

def _xml_text(root):
 out=[]
 for para in root.iter(W+'p'):
  runs=[]
  for node in para.iter():
   if node.tag in (W+'t',W+'delText',W+'instrText') and node.text:runs.append(node.text)
   elif node.tag==W+'tab':runs.append('\t')
  line=''.join(runs)
  if line.strip():out.append(line)
 return out

def _member_xml(z,name):
 """Read and parse one DOCX part; every read/parse failure becomes a bounded ValueError."""
 try:return ET.fromstring(z.read(name))
 except ET.ParseError:_fail('Corrupt DOCX part (invalid XML): '+name[:80])
 except (zipfile.BadZipFile,zlib.error,NotImplementedError,RuntimeError,EOFError,OSError,KeyError):_fail('Corrupt or unsupported DOCX part: '+name[:80])

def extract_docx(data):
 try:z=zipfile.ZipFile(io.BytesIO(data))
 except (zipfile.BadZipFile,OSError,EOFError):_fail('Not a valid DOCX (zip) file.')
 infos=z.infolist()
 if len(infos)>MAX_DOCX_ENTRIES:_fail('DOCX has too many parts.')
 if sum(i.file_size for i in infos)>MAX_DOCX_TOTAL or any(i.file_size>MAX_DOCX_MEMBER for i in infos if i.filename.endswith('.xml')):_fail('DOCX is too large when unpacked.')
 names=[i.filename for i in infos]
 if 'word/document.xml' not in names:_fail('Not a DOCX document (word/document.xml missing).')
 if any('vbaProject' in n or n.startswith('word/embeddings/') or n.startswith('word/activeX/') for n in names):_fail('DOCX with macros, embedded objects or ActiveX is not supported.')
 if any(i.flag_bits&1 for i in infos):_fail('Encrypted DOCX is not supported.')
 parts=[]
 def read(name,label):
  root=_member_xml(z,name)
  lines=_xml_text(root)
  if lines:parts.append('[docx %s]\n'%label+'\n'.join(lines))
  return root
 body=read('word/document.xml','body')
 for n in sorted(names):
  m=re.fullmatch(r'word/(header\d*|footer\d*|footnotes|endnotes|comments)\.xml',n)
  if m:read(n,m.group(1))
 if 'docProps/core.xml' in names:
  for el in _member_xml(z,'docProps/core.xml'):
   if el.text and el.text.strip():parts.append('[docx metadata %s] %s'%(el.tag.rsplit('}',1)[-1],el.text.strip()))
 for el in body.iter():
  if el.tag.endswith('}docPr'):
   for key in ('descr','title'):
    if el.get(key):parts.append('[docx image %s] %s'%(key,el.get(key)))
 return _cap(parts,'DOCX')

def extract_document(filename,data):
 """Return extracted plain text for a pdf/docx/png/jpg/webp upload. Raises ValueError with a clear message otherwise."""
 name=str(filename or '');ext=name.rsplit('.',1)[-1].lower() if '.' in name else ''
 if ext in IMAGE_FORMATS:_fail('Image text extraction (OCR) is not supported yet. The image was refused, not treated as clean.')
 if ext not in DOC_FORMATS:_fail('Unsupported file type. Supported here: '+', '.join('.'+f for f in DOC_FORMATS)+'.')
 if not isinstance(data,(bytes,bytearray)):_fail('Upload must be raw bytes.')
 data=bytes(data)
 if len(data)>MAX_BYTES:_fail('File exceeds the 5 MB limit.')
 if ext=='pdf':
  if not data.startswith(b'%PDF-'):_fail('File does not look like a PDF.')
  return extract_pdf(data)
 if ext=='docx':return extract_docx(data)
 return extract_image(data)
