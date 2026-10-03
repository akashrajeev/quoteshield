import io,os,shutil,subprocess,unittest
from unittest import mock
import extractors_image as ei
from extractors_image import extract_image
FONT='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
def png(text='Vendor: Beacon Price 11900',size=(700,100),info=None,fmt='PNG'):
 from PIL import Image,ImageDraw,ImageFont
 from PIL.PngImagePlugin import PngInfo
 im=Image.new('RGB',size,'white')
 if text:ImageDraw.Draw(im).text((10,30),text,fill='black',font=ImageFont.truetype(FONT,18))
 b=io.BytesIO();meta=None
 if info and fmt=='PNG':
  meta=PngInfo();meta.add_text('Comment',info)
 im.save(b,fmt,**({'pnginfo':meta} if meta else {}));return b.getvalue()
def blank_png(size=(40,20),fmt='PNG'):
 from PIL import Image
 b=io.BytesIO();Image.new('RGB',size,'white').save(b,fmt);return b.getvalue()
HAVE=bool(shutil.which('tesseract')) and os.path.exists(FONT)
class OcrTests(unittest.TestCase):
 @unittest.skipUnless(HAVE,'tesseract/font not available')
 def test_text_and_png_metadata(self):
  t=extract_image('a.png',png(info='metadata comment'))
  self.assertIn('Vendor: Beacon',t);self.assertIn('metadata comment',t);self.assertIn('not a security guarantee',t)
 @unittest.skipUnless(HAVE,'tesseract/font not available')
 def test_jpeg_and_webp(self):
  for ext,fmt in [('a.jpg','JPEG'),('a.webp','WEBP')]:self.assertIn('Beacon',extract_image(ext,png(fmt=fmt)))
 @unittest.skipUnless(HAVE,'tesseract/font not available')
 def test_blank_image_refused(self):
  with self.assertRaisesRegex(ValueError,'no text'):extract_image('a.png',png(text=''))
 @unittest.skipUnless(HAVE,'tesseract/font not available')
 def test_env_path_override(self):
  with mock.patch.dict(os.environ,{'SHIELD_TESSERACT_PATH':shutil.which('tesseract')}):self.assertIn('Beacon',extract_image('a.png',png()))
class FailureTests(unittest.TestCase):
 def test_missing_engine_is_loud_with_install_note(self):
  with mock.patch.dict(os.environ,{},clear=False),mock.patch('extractors_image.shutil.which',return_value=None):
   os.environ.pop('SHIELD_TESSERACT_PATH',None)
   with self.assertRaisesRegex(ValueError,'not installed') as cm:extract_image('a.png',blank_png())
  self.assertIn('UB-Mannheim',str(cm.exception));self.assertIn('SHIELD_TESSERACT_PATH',str(cm.exception))
 def test_bad_configured_path_is_missing_engine(self):
  with mock.patch.dict(os.environ,{'SHIELD_TESSERACT_PATH':'/nonexistent/tesseract'}):
   with self.assertRaisesRegex(ValueError,'not installed'):extract_image('a.png',blank_png())
 def test_rejections(self):
  for name,data in [('a.png',b'junk'),('a.gif',blank_png()),('a.pdf',b'%PDF'),('noext',b'x'),('a.png',b'x'*(5*1024*1024+1))]:
   with self.assertRaises(ValueError,msg=name):extract_image(name,data)
  with self.assertRaises(ValueError):extract_image('a.png','text')
 def test_wrong_extension_real_format(self):
  from PIL import Image
  b=io.BytesIO();Image.new('RGB',(10,10)).save(b,'GIF')
  with self.assertRaisesRegex(ValueError,'Only PNG'):extract_image('a.png',b.getvalue())
 def test_pixel_limit(self):
  with mock.patch.object(ei,'MAX_PIXELS',100):
   with self.assertRaisesRegex(ValueError,'megapixel'):extract_image('a.png',blank_png())
 def test_timeout_failure_and_oserror(self):
  with mock.patch('extractors_image.find_tesseract',return_value='/x/t'):
   with mock.patch('extractors_image.subprocess.run',side_effect=subprocess.TimeoutExpired('t',1)):
    with self.assertRaisesRegex(ValueError,'timed out'):extract_image('a.png',blank_png())
   with mock.patch('extractors_image.subprocess.run',return_value=mock.Mock(returncode=1,stderr='bad',stdout='')):
    with self.assertRaisesRegex(ValueError,'failed'):extract_image('a.png',blank_png())
   with mock.patch('extractors_image.subprocess.run',side_effect=OSError('nope')):
    with self.assertRaisesRegex(ValueError,'could not be started'):extract_image('a.png',blank_png())
 def test_exif_scanned_even_before_ocr_result(self):
  from PIL import Image
  im=Image.new('RGB',(50,50),'white');ex=Image.Exif();ex[0x010E]='exif injected note'
  b=io.BytesIO();im.save(b,'JPEG',exif=ex)
  with mock.patch('extractors_image.find_tesseract',return_value='/x/t'),mock.patch('extractors_image.subprocess.run',return_value=mock.Mock(returncode=0,stderr='',stdout='ocr words')):
   t=extract_image('a.jpg',b.getvalue())
  self.assertIn('exif injected note',t);self.assertIn('ocr words',t)

 def test_pixel_limit_checked_before_decode(self):
  data=blank_png((40,20))
  with mock.patch.object(ei,'MAX_PIXELS',100),mock.patch('PIL.Image.Image.load',side_effect=AssertionError('decoded oversized image')),mock.patch('PIL.Image.Image.verify',side_effect=AssertionError('verified oversized image')):
   with self.assertRaisesRegex(ValueError,'megapixel'):extract_image('a.png',data)
class WindowsShapedMockedTests(unittest.TestCase):
 WINPATH='C:\\Program Files\\Tesseract-OCR\\tesseract.exe'
 def run_with(self,env,run=None,isfile=True):
  p=[mock.patch.dict(os.environ,env),mock.patch('extractors_image.os.path.isfile',return_value=isfile),mock.patch('extractors_image.shutil.which',return_value=None)]
  if run is not None:p.append(mock.patch('extractors_image.subprocess.run',**run))
  return p
 def test_quoted_path_is_unquoted(self):
  with mock.patch.dict(os.environ,{'SHIELD_TESSERACT_PATH':'"%s"'%self.WINPATH}),mock.patch('extractors_image.os.path.isfile',return_value=True):
   self.assertEqual(ei.find_tesseract(),self.WINPATH)
 def test_path_with_spaces_passed_as_single_argv_no_shell(self):
  ok=mock.Mock(returncode=0,stderr='',stdout='some words')
  with mock.patch.dict(os.environ,{'SHIELD_TESSERACT_PATH':self.WINPATH}),mock.patch('extractors_image.os.path.isfile',return_value=True),mock.patch('extractors_image.subprocess.run',return_value=ok) as run:
   text=extract_image('a.png',blank_png())
  self.assertIn('some words',text);args,kwargs=run.call_args
  self.assertEqual(args[0][0],self.WINPATH);self.assertNotIn('shell',kwargs);self.assertEqual(kwargs['timeout'],ei.OCR_TIMEOUT)
 def test_invalid_path_refused_with_install_note(self):
  with mock.patch.dict(os.environ,{'SHIELD_TESSERACT_PATH':self.WINPATH}),mock.patch('extractors_image.os.path.isfile',return_value=False),mock.patch('extractors_image.shutil.which',return_value='/usr/bin/tesseract'):
   with self.assertRaisesRegex(ValueError,'not installed') as cm:extract_image('a.png',blank_png())
  self.assertIn('UB-Mannheim',str(cm.exception))
 def test_timeout_oserror_nonzero_and_empty_stdout(self):
  cases=[({'side_effect':subprocess.TimeoutExpired('t',1)},'timed out'),({'side_effect':OSError('[WinError 193] not a valid Win32 application')},'could not be started'),
   ({'return_value':mock.Mock(returncode=1,stderr='Error opening data file',stdout='')},'failed'),({'return_value':mock.Mock(returncode=0,stderr='',stdout='  \n')},'no text')]
  for run,msg in cases:
   with mock.patch.dict(os.environ,{'SHIELD_TESSERACT_PATH':self.WINPATH}),mock.patch('extractors_image.os.path.isfile',return_value=True),mock.patch('extractors_image.subprocess.run',**run):
    with self.assertRaisesRegex(ValueError,msg):extract_image('a.png',blank_png())

if __name__=='__main__':unittest.main()
