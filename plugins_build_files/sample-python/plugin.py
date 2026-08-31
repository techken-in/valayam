import json
from extism_pdk import plugin_fn, Host

@plugin_fn
def run_scan():
    input_data = Host.input_string()
    ctx = json.loads(input_data)
    
    findings = [{
        "title": "Sample Finding",
        "severity": "INFO",
        "description": f"Scanned target: {ctx.get('target', 'unknown')}"
    }]
    
    Host.output_string(json.dumps(findings))
