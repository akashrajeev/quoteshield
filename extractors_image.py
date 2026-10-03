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
   raw=bytes(value);value=(raw[8:] if raw[:8] in (b'ASCII\x00\x00\x00',b'UNICODE\x00',b'JIS\x00\x00\x00\x00\x00') and tag==0x9286 else raw).decode('utf-16-le' if raw[:8]==b'UNICODE\x00' or tag==0x9C9C else 'utf-8',errors='replace').replace('\x00','')
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
