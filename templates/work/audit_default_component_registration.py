from pathlib import Path
import json,winreg
rows=json.loads(Path('work/windowwatcher/all-component-descriptors.json').read_text());audit=[]
for row in rows:
 if row['flags']!=0 or row['required']!=1 or row['unknownWrites']:continue
 item=dict(row);item['hostClassRegistered']=False;item['hostValues']={}
 try:
  key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Classes\\CLSID\\{'+row['CLSID']+'}');item['hostClassRegistered']=True
  for sub in ['','InprocServer32','LocalServer32']:
   try:item['hostValues'][sub or '(default)']=winreg.QueryValueEx(winreg.OpenKey(key,sub),'')[0]
   except OSError:pass
  winreg.CloseKey(key)
 except OSError:pass
 audit.append(item)
info={'descriptorCount':len(rows),'knownRequiredDefaultCount':len(audit),'missing':[x['index'] for x in audit if not x['hostClassRegistered']],'readOnly':True,'excludedUnknownFlags':[x['index'] for x in rows if x['unknownWrites']],'entries':audit}
Path('work/windowwatcher/required-default-component-audit.json').write_text(json.dumps(info,indent=2));print('Required default count',len(audit),'missing',info['missing'])
