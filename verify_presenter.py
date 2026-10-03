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
  page=b.new_page(viewport={'width':1500,'height':1200},color_scheme='dark');errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  page.goto('http://127.0.0.1:8501');page.get_by_text('Regular Streamlit (dark)',exact=True).click();page.get_by_text('QuoteShield / Mock sandbox / Regular Streamlit dark theme',exact=True).wait_for()
  page.get_by_role('button',name='Run side-by-side',exact=True).click();page.get_by_text('No unauthorized mock effect observed.',exact=True).wait_for()
  page.get_by_text('Presenter mode',exact=True).click();page.get_by_text('Presenter walkthrough',exact=True).wait_for()
  names=['1 Legitimate task','2 Malicious document','3 Unprotected run','4 Trusted scope','5 Protected run','6 Human review','7 Audit','8 Results','9 Final legitimate task']
  for i,name in enumerate(names,1):
   page.get_by_role('combobox',name='Presentation view').click();page.get_by_role('option',name=name,exact=True).click()
   if i in [1,9]:
    page.get_by_role('button',name='Execute clean task with shield',exact=True).click();page.get_by_text('harmful_effect',exact=True).wait_for()
   if i==6:
    page.get_by_role('button',name='Prepare exact-call review',exact=True).click();page.get_by_role('button',name='Approve exact call',exact=True).wait_for()
    page.screenshot(path='/downloads/quoteshield-human-pending.png',full_page=True)
    page.get_by_role('button',name='Approve exact call',exact=True).click();page.get_by_text('ALLOW',exact=True).wait_for()
   page.get_by_text('Presenter walkthrough',exact=True).scroll_into_view_if_needed()
   page.screenshot(path=f'/downloads/quoteshield-presenter-{i:02}.png',full_page=True)
   assert not page.locator('[data-testid="stException"]').count()
  assert not errors,errors
  print('Presenter views passed',names)
  page.get_by_text('Styled procurement room',exact=True).click();page.get_by_text('QUOTESHIELD / PROCUREMENT ROOM / MOCK SANDBOX',exact=True).wait_for();page.get_by_text('Presenter walkthrough',exact=True).scroll_into_view_if_needed();page.screenshot(path='/downloads/quoteshield-presenter-styled.png',full_page=True)
  b.close()
finally:server.terminate();server.wait(timeout=10)
