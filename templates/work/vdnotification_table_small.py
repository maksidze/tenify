import json
s=json.load(open('work/vdnotification-vtables.json'))
for label,target,n in [('old','0x53fb18',10),('host','0x6fa948',14)]:
 a=next(x for x in s[label] if x['rva']==target);print(label,a['name'])
 for r in a['slots'][:n]:
  ns=[v for v in r['names'] if 'CVirtualDesktopNotifications' in v or v.startswith('?') and not any(t in v for t in ('WRL','lambda'))]
  print(r['slot'],r['rva'],ns[:6])
