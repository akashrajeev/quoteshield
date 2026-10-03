import sys
import subprocess,time,urllib.request,json
from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).parent
(root/"artifacts/screenshots").mkdir(parents=True,exist_ok=True)
server=subprocess.Popen([sys.executable,'-m','streamlit','run','streamlit_app.py','--server.port','8501','--server.headless','true'],cwd=root,stdout=open('/tmp/ps3-dark.log','w'),stderr=subprocess.STDOUT)
try:
 for _ in range(80):
  try:urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health');break
  except Exception:time.sleep(.25)
 with sync_playwright() as p:
  b=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox'],headless=True)
  page=b.new_page(viewport={'width':1500,'height':1100},color_scheme='dark');errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  page.goto('http://127.0.0.1:8501');page.get_by_text('Regular Streamlit (dark)',exact=True).click();page.get_by_text('QuoteShield / Mock sandbox / Regular Streamlit dark theme',exact=True).wait_for()
  page.get_by_role('button',name='Run side-by-side',exact=True).click();page.get_by_text('No unauthorized mock effect observed.',exact=True).wait_for()
  names=['Attack Arena','Judge Challenge','X-ray','Audit Explorer','Results','Human review']
  for i,name in enumerate(names,1):
   page.get_by_role('tab',name=name,exact=True).click()
   if name=='Human review':page.get_by_role('button',name='Prepare legitimate mock email',exact=True).click();page.get_by_role('button',name='Approve exact call',exact=True).wait_for()
   page.evaluate("document.querySelector('[data-testid=stMain]').scrollTop=0")
   page.screenshot(path=f'artifacts/screenshots/quoteshield-dark-{i:02}.png',full_page=True)
   assert not page.locator('[data-testid="stException"]').count()
  assert not errors,errors
  print('Dark tabs passed',names)
  print('Theme background',page.locator('.stApp').evaluate('e=>getComputedStyle(e).backgroundColor'))
  page.get_by_text('Styled procurement room',exact=True).click();page.get_by_role('tab',name='Attack Arena',exact=True).click();page.screenshot(path='artifacts/screenshots/quoteshield-styled-retained.png',full_page=True)
  b.close()
finally:server.terminate();server.wait(timeout=10)
