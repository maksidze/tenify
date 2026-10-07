from pathlib import Path
import sys,json,struct
sys.path.insert(0,'work/pylib');import pefile
for n,path in [('old','work/settings-datamodel-image/4/Windows/System32/SystemSettings.DataModel.dll'),('host','C:/Windows/System32/SystemSettings.DataModel.dll')]:
 s=json.loads(Path('work/compat-research/'+n+'-settings-datamodel/all-public-symbols.json').read_text());names={x['rva']:x['name'] for x in s};p=pefile.PE(path);base=p.OPTIONAL_HEADER.ImageBase
 print(n)
 for x in s:
  if x['name'] in ['??_7CSettingsDatabase@DataModel@SystemSettings@@6BISettingsDatabase@12@@','??_7CSettingItem@DataModel@SystemSettings@@6BISettingItem@12@@']:
   print(x['name'])
   for i in range(21):
    ptr=struct.unpack('<Q',p.get_data(x['rva']+8*i,8))[0]-base;print(i,hex(ptr),names.get(ptr,'?'))
