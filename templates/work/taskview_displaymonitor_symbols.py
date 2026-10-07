import json
s=json.load(open('work/compat-research/host-udkshellcommon/all-public-symbols.json'))
for r in s:
 if 'DisplayMonitorInfoCollection' in r['name'] and ('Server' in r['name'] and 'AddOrUpdate' in r['name']):print(hex(r['rva']),r['name'])


