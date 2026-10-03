import sys
import subprocess,time,urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).parent
(root/"artifacts/screenshots").mkdir(parents=True,exist_ok=True)
server=subprocess.Popen([sys.executable,'-m','streamlit','run','streamlit_app.py','--server.address','127.0.0.1','--server.port','8501','--browser.gatherUsageStats','false','--server.headless','true'],cwd=root,stdout=open('/tmp/quoteshield-streamlit.log','w'),stderr=subprocess.STDOUT)
try:
 for _ in range(80):
  try:urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health');break
  except Exception:time.sleep(.25)
 with sync_playwright() as p:
  b=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox'],headless=True)
  page=b.new_page(viewport={'width':1500,'height':1100});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  page.goto('http://127.0.0.1:8501');page.get_by_role('button',name='Run side-by-side',exact=True).wait_for();page.get_by_role('button',name='Run side-by-side',exact=True).click()
  page.get_by_text('Boundary breached: unauthorized mock effect occurred.',exact=True).wait_for();page.get_by_text('No unauthorized mock effect observed.',exact=True).wait_for()
  page.evaluate("document.querySelector('[data-testid=stMain]').scrollTop=0");page.screenshot(path='artifacts/screenshots/quoteshield-streamlit-arena.png',full_page=True)
  page.get_by_role('tab',name='Audit Explorer',exact=True).click();page.get_by_role('button',name='Verify tampered copy',exact=True).click();page.get_by_text('Verification failed as expected.',exact=True).wait_for()
  page.evaluate("document.querySelector('[data-testid=stMain]').scrollTop=0");page.screenshot(path='artifacts/screenshots/quoteshield-streamlit-audit.png',full_page=True)
  page.get_by_role('tab',name='Human review',exact=True).click();page.get_by_role('button',name='Prepare legitimate mock email',exact=True).click();page.get_by_role('button',name='Approve exact call',exact=True).click();page.wait_for_function("Array.from(document.querySelectorAll('button')).some(b=>b.innerText==='Approve exact call' && b.disabled)")
  page.get_by_role('tab',name='Judge Challenge',exact=True).click();page.get_by_role('textbox',name='Text inserted into a mock vendor quote',exact=True).fill('Vendor content with harmless terms.');page.get_by_role('button',name='Run custom challenge',exact=True).click();page.get_by_text('Executing isolated mock tools...').wait_for(state='hidden')
  page.get_by_role('tab',name='Results',exact=True).click();page.get_by_text('Measured evidence, not placeholder scores',exact=True).wait_for();assert not page.locator('[data-testid="stException"]').count()
  page.screenshot(path='artifacts/screenshots/quoteshield-streamlit-results.png',full_page=True)
  page.set_viewport_size({'width':390,'height':844});page.goto('http://127.0.0.1:8501');page.get_by_role('button',name='Run side-by-side',exact=True).wait_for();page.get_by_role('button',name='Run side-by-side',exact=True).click();page.get_by_text('Boundary breached: unauthorized mock effect occurred.',exact=True).wait_for();page.screenshot(path='artifacts/screenshots/quoteshield-streamlit-mobile.png',full_page=True)
  assert not page.locator('[data-testid="stException"]').count();assert not errors,errors
  b.close();print('Streamlit UI verified: arena, tamper detector, exact-call single use, custom input; no JavaScript errors.')
finally:server.terminate();server.wait(timeout=10)
