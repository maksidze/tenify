from pathlib import Path
import re,json
out={}
for mode,p in [('old',Path('outputs/Windows10-Components/Image/4/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll')),('native',Path('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll'))]:
 data=p.read_bytes();ss=[]
 for m in re.finditer(rb'(?:[\x20-\x7e]\x00){5,}',data):
  st=m.group().decode('utf-16le')
  if any(x in st for x in ['SystemSettings_','Possible','Timeout','Item','Value','Enum']):ss.append({'offset':hex(m.start()),'text':st})
 out[mode]=ss;print(mode);print('\n'.join(x['offset']+' '+x['text'] for x in ss[:65]))
Path('outputs/Windows10-Components/Lab/SettingsPowerCompat/power-provider-strings.json').write_text(json.dumps(out,indent=2))
