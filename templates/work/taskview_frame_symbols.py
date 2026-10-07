import json
s=json.load(open('work/compat-research/host-twinui/all-public-symbols.json'))
for r in s:
 if any(t in r['name'] for t in ('TaskViewFrame@@','TaskViewFrame@')) and (r['name'].startswith('??_7') or any(t in r['name'] for t in ('?Show@','?Initialize@','?Create@','?OnViewLoaded@','?OnContainerShow@'))):print(hex(r['rva']),r['name'])
