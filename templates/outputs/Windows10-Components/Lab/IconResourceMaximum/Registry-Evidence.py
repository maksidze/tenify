from pathlib import Path
import sys,json,winreg,re
lab=Path(__file__).resolve().parent;root=lab.parents[3];sys.path.insert(0,str(root/'work/pylib'))
from Registry import Registry
reg=Registry.Registry(str(root/'outputs/Windows10-Components/Image/4/Windows/System32/config/SOFTWARE'))
items=[]
for classes in ['Classes/CLSID','Classes']:
 try:keys=reg.open(classes.replace('/','\\')).subkeys()
 except Exception:continue
 for k in keys:
  try:old=k.subkey('DefaultIcon').value('(default)').value()
  except Exception:continue
  path=k.path().split('\\',1)[-1]
  if path.startswith('Classes\\'):path=path[len('Classes\\'):]
  try:
   with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,path+'\\DefaultIcon') as current:host=winreg.QueryValueEx(current,None)[0]
  except OSError:continue
  def normalize(s):
   s=s.strip('"').replace('\\','/').lower();m=re.search(r'([^/]+\.(?:dll|exe|cpl))[^,]*,\s*(-?\d+)\s*$',s)
   return list(m.groups()) if m else None
  a=normalize(old);b=normalize(host)
  if a and b:items.append(dict(Key=path,Old=old,Host=host,OldNormalized=a,HostNormalized=b,SameResourceContract=a==b))
(lab/'registry-icon-evidence.json').write_text(json.dumps(items,indent=2,ensure_ascii=False));print(json.dumps(dict(PairedDefaultIcons=len(items),SameContract=sum(x['SameResourceContract'] for x in items))))
