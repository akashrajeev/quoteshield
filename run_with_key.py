"""Local operator-only secret prompt; never writes the key to disk."""
import argparse,getpass,os,subprocess,sys
p=argparse.ArgumentParser(description='Run QuoteShield locally with a Gemini key held only in process memory. Use a free-tier-only project; do not enter the key into chat.')
p.add_argument('--model',required=True,help='Exact tool-capable model ID available to your API project')
p.add_argument('--command',choices=['demo','development','ablations','freeze'],default='demo')
a=p.parse_args()
os.environ['SHIELD_MODEL_URL']='https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'
os.environ['SHIELD_MODEL_NAME']=a.model
os.environ['SHIELD_MODEL_KEY']=getpass.getpass('Gemini API key (hidden, not saved): ')
cmd={'demo':['-m','streamlit','run','streamlit_app.py','--server.address','127.0.0.1','--browser.gatherUsageStats','false'],'development':['evaluate.py','--mode','llm','--split','development'],'ablations':['ablate.py','--mode','llm','--repeats','3'],'freeze':['freeze.py']}[a.command]
try:sys.exit(subprocess.call([sys.executable,*cmd],env=os.environ))
finally:os.environ.pop('SHIELD_MODEL_KEY',None)
