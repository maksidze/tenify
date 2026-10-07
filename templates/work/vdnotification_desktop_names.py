import json
for label in ('old','host'):
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'))
 print(label)
 for r in s:
  if (r['name'].startswith('??_7') and ('CVirtualDesktop@@' in r['name'] or 'IVirtualDesktop@@@' in r['name'])) or ('CanCastTo' in r['name'] and 'UIVirtualDesktop@@' in r['name']):print(hex(r['rva']),r['name'])
