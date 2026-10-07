import json
for label in ('old','host'):
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'))
 a=[r for r in s if 'VirtualDesktopNotification' in r['name'] or 'VirtualDesktopCreated' in r['name'] or 'VirtualDesktopDestroyed' in r['name'] or 'CurrentVirtualDesktopChanged' in r['name']]
 open(f'work/{label}-vdnotify-symbols.txt','w').write('\n'.join(f"{r['rva']:x} {r['name']}" for r in a))
 print(label,len(a))
 for r in a:
  if not any(t in r['name'] for t in ('Details','WRL','lambda','OnCompleted','operator')):print(hex(r['rva']),r['name'])
