import sys
"""Records actual offline UI behavior, visibly labeled. No fabricated model run."""
import subprocess,time,urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright
root=Path(__file__).parent
(root/"artifacts/screenshots").mkdir(parents=True,exist_ok=True)
server=subprocess.Popen([sys.executable,'-m','streamlit','run','streamlit_app.py','--server.address','127.0.0.1','--server.port','8501','--browser.gatherUsageStats','false','--server.headless','true'],cwd=root,stdout=open('/tmp/ps3-record.log','w'),stderr=subprocess.STDOUT)
try:
 for _ in range(80):
  try:urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health');break
  except Exception:time.sleep(.25)
 with sync_playwright() as p:
  browser=p.chromium.launch(executable_path='/usr/bin/google-chrome',args=['--no-sandbox'],headless=True)
  ctx=browser.new_context(viewport={'width':1440,'height':1080},record_video_dir='artifacts/screenshots/ps3-recordings',record_video_size={'width':1440,'height':1080})
  page=ctx.new_page();page.goto('http://127.0.0.1:8501');page.get_by_role('button',name='Run side-by-side',exact=True).wait_for()
  def label(text):
   page.evaluate("text=>{let n=document.getElementById('recordLabel');if(!n){n=document.createElement('div');n.id='recordLabel';n.style.cssText='position:fixed;bottom:0;left:0;right:0;z-index:99999;padding:15px 24px;background:#251f21;color:white;font:16px Arial';document.body.appendChild(n)}n.textContent=text}",text)
  label('RECORDED OFFLINE DEMO | Actual mock-tool verification. Not live model evidence.');page.wait_for_timeout(3500)
  page.get_by_role('button',name='Run side-by-side',exact=True).click();page.get_by_text('Boundary breached: unauthorized mock effect occurred.',exact=True).wait_for();label('1 / Same task: unauthorized mock effects on the left, protected task complete on the right.');page.wait_for_timeout(6500)
  page.get_by_role('tab',name='X-ray',exact=True).click();label('2 / X-ray: original source, removed text and retained vendor facts.');page.wait_for_timeout(6000)
  page.get_by_role('tab',name='Audit Explorer',exact=True).click();page.get_by_role('button',name='Verify tampered copy',exact=True).click();page.get_by_text('Verification failed as expected.',exact=True).wait_for();page.get_by_role('button',name='Verify tampered copy',exact=True).scroll_into_view_if_needed();label('3 / Edit a copy of one audit line: verification fails against the retained chain.');page.wait_for_timeout(5500)
  page.get_by_role('tab',name='Human review',exact=True).click();page.get_by_role('button',name='Prepare legitimate mock email',exact=True).click();label('4 / Native LangGraph interrupt: inspect the exact mock recipient, subject and body.');page.wait_for_timeout(4500)
  page.get_by_role('button',name='Approve exact call',exact=True).click();page.wait_for_function("Array.from(document.querySelectorAll('button')).some(b=>b.innerText==='Approve exact call' && b.disabled)");label('5 / Resume the same call once, recheck policy, capture only in the mock outbox.');page.wait_for_timeout(4000)
  page.get_by_role('tab',name='Results',exact=True).click();label('6 / Results from real offline executions. Genuine model benchmark is the next milestone.');page.wait_for_timeout(6000)
  video=page.video;ctx.close();path=video.path();browser.close();Path('/tmp/ps3-record-path.txt').write_text(path);print(path)
finally:server.terminate();server.wait(timeout=10)
