from pathlib import Path
import sys,json
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));from Registry import Registry
reg=Registry.Registry(str(root/'outputs/Windows10-Components/Image/4/Windows/System32/config/SOFTWARE'));results=[]
for keypath in ['Microsoft\\Windows\\CurrentVersion\\Control Panel','Microsoft\\Windows\\CurrentVersion\\Explorer','Classes\\CLSID']:
 def walk(key):
  path=key.path()
  if 'PowerAndSleep' in path:results.append({'path':path,'values':{v.name():str(v.value()) for v in key.values()}})
  for v in key.values():
   val=str(v.value())
   if 'SystemSettings_PowerAndSleep' in val:results.append({'path':path,'matchingValue':v.name(),'data':val[:3000]})
  for child in key.subkeys():walk(child)
 try:walk(reg.open(keypath))
 except Registry.RegistryKeyNotFoundException:pass
out=Path(__file__).resolve().parent/'old-power-registration.json';out.write_text(json.dumps(results,indent=2,ensure_ascii=False));print('matches',len(results));print(json.dumps(results[:10],indent=2,ensure_ascii=False))
