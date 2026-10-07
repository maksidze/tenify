import json
s=json.load(open('work/compat-research/host-twinui/all-public-symbols.json'))
for r in s:
 if any(t in r['name'] for t in ('QueueTask@','QueueTaskInternal@','EnqueueTask@','MultitaskingViewServiceProvider@@','QueueMultitasking')) and not any(t in r['name'] for t in ('lambda','WRL','std@@','_tlg','ComPtr')):print(hex(r['rva']),r['name'])
