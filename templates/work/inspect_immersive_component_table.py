from pathlib import Path
import sys,struct,uuid,json,winreg
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile
from Registry import Registry
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/twinui.pcshell.dll');base=p.OPTIONAL_HEADER.ImageBase
reg=Registry.Registry('outputs/Windows10-Components/Image/4/Windows/System32/config/SOFTWARE');rows=[]
for i in range(139):
 raw=p.get_data(0x649270+24*i,24);ptr,flags,other=struct.unpack('<QQQ',raw)
 if not base<ptr<base+p.OPTIONAL_HEADER.SizeOfImage:continue
 guid=str(uuid.UUID(bytes_le=p.get_data(ptr-base,16)));path='Classes\\CLSID\\{'+guid+'}'
 old=[];host=[]
 try:
  key=reg.open(path)
  for k in [key,*key.subkeys()]:old.append({'key':k.path(),'values':{v.name():v.value() for v in k.values()}})
 except Registry.RegistryKeyNotFoundException:pass
 try:
  k=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\'+path);host.append({'keyExists':True})
  try:host.append({'default':winreg.QueryValueEx(k,'')[0]})
  except OSError:pass
  for sub in ['InprocServer32','LocalServer32']:
   try:host.append({sub:winreg.QueryValueEx(winreg.OpenKey(k,sub),'')[0]})
   except OSError:pass
 except OSError:pass
 rows.append({'index':i,'CLSID':guid,'flags':hex(flags),'other':hex(other),'oldRegistration':old,'hostRegistration':host})
Path('work/windowwatcher/immersive-component-table.json').write_text(json.dumps(rows,indent=2,default=str))
print('rows',len(rows),'missing native registration',sum(not x['hostRegistration'] for x in rows))
for r in rows:
 if not r['hostRegistration']:print(r['index'],r['CLSID'],r['flags'],r['oldRegistration'])
