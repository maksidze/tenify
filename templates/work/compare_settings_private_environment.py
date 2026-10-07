import sys,json,struct
from pathlib import Path
sys.path.insert(0,'work/pylib');import pefile
rows={}
for key,mod in [('old','outputs/Windows10-Components/Image/4/Windows/System32/SettingsEnvironment.Desktop.dll'),('host','C:/Windows/System32/SettingsEnvironment.Desktop.dll')]:
 p=pefile.PE(mod);s=json.load(open(f'work/compat-research/{key}-settings-environment/all-public-symbols.json'));d={x['rva']:x['name'] for x in s};v=next(x for x in s if x['name']=='??_7SettingsEnvironmentImpl@Environment@SystemSettings@@6B@');rows[key]=[{'slot':i,'rva':hex(a-p.OPTIONAL_HEADER.ImageBase),'symbol':d.get(a-p.OPTIONAL_HEADER.ImageBase,'?')} for i,a in enumerate(struct.unpack('<16Q',p.get_data(v['rva'],128)))];print(key,hex(v['rva']));print('\n'.join(str(x['slot'])+' '+x['symbol'] for x in rows[key]))
Path('work/settings-private-environment-abi.json').write_text(json.dumps(rows,indent=2))
