"""Best-effort OCR text extraction for PNG/JPEG/WebP uploads. NOT a security guarantee.
OCR can miss or garble text, so an injection can survive extraction unnoticed. Output is UNTRUSTED text for the firewall.
Needs the Tesseract binary on PATH or at SHIELD_TESSERACT_PATH. Missing binary, bad images and empty results all fail loudly;
an image is never accepted as clean when OCR could not run."""
import io,os,shutil,subprocess,tempfile

MAX_BYTES=5*1024*1024;MAX_PIXELS=20_000_000;MAX_TEXT=65536;OCR_TIMEOUT=20
IMAGE_FORMATS=('png','jpg','jpeg','webp')
INSTALL_NOTE=('OCR is not installed, so image text cannot be read and the image was refused (not treated as clean). On Windows, install Tesseract from the '
 'UB Mannheim build (https://github.com/UB-Mannheim/tesseract/wiki), then either add the folder that contains tesseract.exe to PATH or set the '
 'SHIELD_TESSERACT_PATH environment variable to the full path of tesseract.exe, and restart the app.')

def _printable(text):
 return bool(text) and all(c.isprintable() or c in '\n\r\t' for c in text)
def _decode_exif_bytes(raw,tag,endian=None):
 """Decode an EXIF bytes value strictly. UserComment honours its declared 8-byte charset prefix. Unsupported, undefined, undecodable or byte-order-ambiguous values refuse the image; nothing is decoded with replacement characters and then reported as scanned."""
 if tag==0x9C9C:
  try:return raw.decode('utf-16-le').replace('\x00','')
  except UnicodeDecodeError:_fail('Image XPComment metadata is not valid UTF-16; image refused.')
 if tag!=0x9286:
  try:return raw.decode('utf-8').replace('\x00','')
  except UnicodeDecodeError:_fail('Image metadata is not valid UTF-8; image refused.')
 prefix,body=raw[:8],raw[8:]
 if not body.replace(b'\x00',b'').strip():return ''
 if prefix==b'ASCII\x00\x00\x00':
  try:return body.decode('ascii').replace('\x00','')
  except UnicodeDecodeError:_fail('Image UserComment is declared ASCII but contains non-ASCII bytes; image refused.')
 if prefix==b'UNICODE\x00':
  if body[:2] in (b'\xff\xfe',b'\xfe\xff'):
   try:return body.decode('utf-16').replace('\x00','')
   except UnicodeDecodeError:_fail('Image UserComment UTF-16 text is invalid; image refused.')
  cands={}
  for name,codec in (('<','utf-16-le'),('>','utf-16-be')):
   try:t=body.decode(codec)
   except UnicodeDecodeError:continue
   if _printable(t.replace('\x00','')):cands[name]=t.replace('\x00','')
  if len(cands)==1:return next(iter(cands.values()))  # only one byte order yields valid printable text
  ascii_only=[t for t in cands.values() if all(ord(c)<0x80 for c in t)]
  if len(cands)==2 and len(ascii_only)==1:return ascii_only[0]
  if len(cands)==2 and endian in cands and all(ord(c)<0x80 for c in cands[endian]):return cands[endian]
  _fail('Image UserComment UTF-16 byte order could not be validated; image refused.')
 if prefix==b'JIS\x00\x00\x00\x00\x00':_fail('Image UserComment uses the JIS charset, which is not supported; image refused rather than left unscanned.')
 _fail('Image UserComment has an undefined or unknown charset prefix; image refused rather than left unscanned.')

def _fail(msg):raise ValueError(msg)

def find_tesseract():
 """Configured path first (SHIELD_TESSERACT_PATH), then PATH. Returns None when unavailable."""
 configured=os.environ.get('SHIELD_TESSERACT_PATH','').strip().strip('"')
 if configured:
  return configured if os.path.isfile(configured) else None
 return shutil.which('tesseract')

def extract_image(filename,data):
 """Return OCR text plus embedded text metadata for one image. Raises ValueError with a clear message otherwise."""
 name=str(filename or '');ext=name.rsplit('.',1)[-1].lower() if '.' in name else ''
 if ext not in IMAGE_FORMATS:_fail('Unsupported image type. Supported: '+', '.join('.'+f for f in IMAGE_FORMATS)+'.')
 if not isinstance(data,(bytes,bytearray)):_fail('Upload must be raw bytes.')
 data=bytes(data)
 if len(data)>MAX_BYTES:_fail('Image exceeds the 5 MB limit.')
 try:from PIL import Image
 except ImportError:_fail('Image support needs the Pillow package (installed with Streamlit).')
 try:img=Image.open(io.BytesIO(data))  # header only; pixels are not decoded yet
 except Exception:_fail('Corrupt or unsupported image.')
 if img.format not in ('PNG','JPEG','WEBP'):_fail('Only PNG, JPEG and WebP images are supported.')
 if img.width*img.height>MAX_PIXELS:_fail('Image exceeds the 20 megapixel limit.')  # checked BEFORE verify()/load()
 try:
  Image.open(io.BytesIO(data)).verify();img=Image.open(io.BytesIO(data))
  img.load()
 except Exception:_fail('Corrupt or unsupported image.')
 parts=[]
 for key,value in (getattr(img,'text',None) or {}).items():
  if str(value).strip():parts.append('[image metadata %s] %s'%(key,value))
 try:exif=img.getexif()
 except Exception:exif={}
 for tag,label in [(0x010E,'ImageDescription'),(0x9286,'UserComment'),(0x013B,'Artist'),(0x8298,'Copyright'),(0x9C9C,'XPComment')]:
  value=exif.get(tag)
  if isinstance(value,(bytes,bytearray)):
   raw=bytes(value);value=_decode_exif_bytes(raw,tag,getattr(exif,'endian','<'))
  if value and str(value).strip():parts.append('[image exif %s] %s'%(label,value))
 binary=find_tesseract()
 if not binary:_fail(INSTALL_NOTE)
 with tempfile.TemporaryDirectory() as tmp:
  path=os.path.join(tmp,'in.png');img.convert('RGB').save(path)
  try:run=subprocess.run([binary,path,'stdout','-l','eng','--psm','6'],capture_output=True,timeout=OCR_TIMEOUT,text=True,encoding='utf-8',errors='replace')
  except subprocess.TimeoutExpired:_fail('OCR timed out after %d seconds; image refused.'%OCR_TIMEOUT)
  except OSError as exc:_fail('OCR could not be started: '+str(exc)[:120])
 if run.returncode!=0:_fail('OCR failed: '+(run.stderr or '').strip()[:160])
 if not run.stdout.strip():_fail('OCR found no text in this image. Not accepted as clean.')
 parts.append('[image OCR, best effort, not a security guarantee]\n'+run.stdout)
 text='\n'.join(parts)
 if len(text)>MAX_TEXT:_fail('Extracted image text exceeds the 64 KB limit.')
 return text
