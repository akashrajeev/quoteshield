import sys
import json,subprocess,time,urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).parent
(root/"artifacts/screenshots").mkdir(parents=True,exist_ok=True)
server=subprocess.Popen([sys.executable,'server.py'],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for _ in range(50):
  try:urllib.request.urlopen('http://127.0.0.1:8765');break
  except Exception:time.sleep(.1)
 with sync_playwright() as p:
  browser=p.chromium.launch(executable_path='/usr/bin/google-chrome',headless=True,args=['--no-sandbox'])
  page=browser.new_page(viewport={'width':1360,'height':1200});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  page.goto('http://127.0.0.1:8765');page.wait_for_function("document.getElementById('protectedResult').textContent==='Boundary held'")
  page.screenshot(path='artifacts/screenshots/quoteshield-desktop.png',full_page=True)
  assert page.locator('#baselineResult').inner_text()=='Boundary breached'
  assert page.locator('#s2').inner_text().startswith('Complete')
  page.select_option('#attack','encoded-01');page.click('#run');page.wait_for_function("document.getElementById('run').disabled===false");assert 'base64' in page.locator('#audit').inner_text()
  page.click('#humanDemo');page.wait_for_selector('#human',state='visible');assert 'reviewer@example.test' in page.locator('#humanCall').inner_text();page.click('#approve');page.wait_for_function("document.getElementById('humanOutcome').textContent.includes('1 captured')")
  page.screenshot(path='artifacts/screenshots/quoteshield-confirmation.png',full_page=True)
  page.set_viewport_size({'width':390,'height':844});page.goto('http://127.0.0.1:8765');page.wait_for_function("document.getElementById('protectedResult').textContent==='Boundary held'");assert page.evaluate('document.documentElement.scrollWidth <= innerWidth');page.screenshot(path='artifacts/screenshots/quoteshield-mobile.png',full_page=True)
  assert not errors,errors
  # Genuine-mode absence is an explicit failure, not a silent replay.
  res=page.request.post('http://127.0.0.1:8765/api/run',data={'id':'plain-01','mode':'llm'});assert res.status==400
  browser.close();print(json.dumps({'ui':'passed','javascript_errors':errors,'desktop':'artifacts/screenshots/quoteshield-desktop.png','confirmation':'artifacts/screenshots/quoteshield-confirmation.png','mobile':'artifacts/screenshots/quoteshield-mobile.png'}))
finally:server.terminate();server.wait(timeout=5)
