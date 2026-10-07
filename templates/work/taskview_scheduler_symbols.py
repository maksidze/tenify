import json
s=json.load(open('work/compat-research/host-twinui/all-public-symbols.json'))
for r in s:
 if 'MultitaskingViewTaskScheduler' in r['name'] and not any(t in r['name'] for t in ('lambda','Details@WRL','std@@','_tlg','Telemetry','CWeakReference','ComPtr','MakeAndInitialize')):print(hex(r['rva']),r['name'])
