import json
for label in ('old','host'):
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'))
 print(label)
 for r in s:
  if any(t in r['name'] for t in ('AllUpView','IAllUp','ToggleView','ToggleTaskView','e053969d')) and not any(t in r['name'] for t in ('tlg','lambda','operator','std@@')):print(hex(r['rva']),r['name'])
