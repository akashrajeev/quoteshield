"""Local provider configuration; credentials never enter run artifacts."""
import os
from pathlib import Path
from dotenv import load_dotenv
PRESETS={
 'gemini':{'model':'gemini-2.5-flash','base':'https://generativelanguage.googleapis.com/v1beta/openai','key_env':'GEMINI_API_KEY'},
 'groq':{'model':'openai/gpt-oss-120b','base':'https://api.groq.com/openai/v1','key_env':'GROQ_API_KEY'},
 'openrouter':{'model':'nvidia/nemotron-3.5-lightning:free','base':'https://openrouter.ai/api/v1','key_env':'OPENROUTER_API_KEY'},
 'nvidia':{'model':'nvidia/llama-3.1-nemotron-nano-8b-v1','base':'https://integrate.api.nvidia.com/v1','key_env':'NVIDIA_API_KEY'}
}
for name,cfg in PRESETS.items():
 cfg['endpoint']=cfg['base']+'/chat/completions'
 cfg['models_endpoint']=cfg['base']+'/models'
def load_local_env(path=None):
 load_dotenv(path or Path(__file__).parent/'.env',override=False)
def configure(provider,model=None):
 cfg=PRESETS[provider];prefix=provider.upper()
 os.environ['SHIELD_MODEL_URL']=os.environ.get(prefix+'_BASE_URL',cfg['base']).rstrip('/')+'/chat/completions'
 os.environ['SHIELD_MODEL_NAME']=model or os.environ.get(prefix+'_MODEL') or cfg['model']
 key=os.environ.get(cfg['key_env']) or os.environ.get('SHIELD_MODEL_KEY','')
 if key:os.environ['SHIELD_MODEL_KEY']=key
 return cfg,key
