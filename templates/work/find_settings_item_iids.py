from pathlib import Path
import json,sys,uuid
sys.path.insert(0,'work/pylib');import pefile
for label,path in [('old',Path('work/settings-datamodel-image/4/Windows/System32/SystemSettings.DataModel.dll')),('host',Path('C:/Windows/System32/SystemSettings.DataModel.dll'))]:
 s=json.loads(Path('work/compat-research/'+label+'-settings-datamodel/all-public-symbols.json').read_text());p=pefile.PE(str(path));print(label)
 for x in s:
  if ('SettingsDatabase' in x['name'] or 'ISettingItem' in x['name']) and (x['name'].startswith(('IID_','__uuidof','??_7CSettingsDatabase')) or 'ActivationFactory' in x['name']):
   print(hex(x['rva']),x['name'][:145],str(uuid.UUID(bytes_le=p.get_data(x['rva'],16))) if x['name'].startswith(('IID_','__uuidof')) else '')

