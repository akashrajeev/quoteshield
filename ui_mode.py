"""Execution-mode policy for the UI: live model is the primary path; offline is developer verification only."""
NOT_CONFIGURED='Live model not configured. Set SHIELD_MODEL_URL and SHIELD_MODEL_NAME (and SHIELD_MODEL_KEY if the endpoint needs one), then restart. Runs are disabled; they are not silently replaced by an offline run.'

def resolve_mode(live_available,developer_offline):
 """Return (mode, blocked_reason). Offline runs only when the developer explicitly opts in."""
 if developer_offline:return 'offline',None
 if live_available:return 'llm',None
 return 'llm',NOT_CONFIGURED

def status_label(live_available,model_name=''):
 return ('Live model: '+model_name) if live_available else 'Live model not configured'
