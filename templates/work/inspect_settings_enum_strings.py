from pathlib import Path
import json,struct
root=Path(__file__).resolve().parents[1];lab=root/'outputs/Windows10-Components/Lab/SettingsEnumCompat'
report={}
for p in (lab/'old').glob('*.xbf'):
 b=p.read_bytes();start=12;major,minor=struct.unpack_from('<II',b,start);offs=struct.unpack_from('<6Q',b,start+8);at=start+offs[0];n=struct.unpack_from('<I',b,at)[0];at+=4;ss=[]
 for _ in range(n):
  num=struct.unpack_from('<I',b,at)[0];at+=4;ss.append(b[at:at+2*num].decode('utf-16le'));at+=2*num+(2 if minor>=1 else 0)
 report[p.name]={'allStrings':ss,'settingIds':[s for s in ss if s.startswith('SystemSettings_') or s.startswith('SettingsGroup')]}
 print(p.name);print('\n'.join(report[p.name]['settingIds']))
(lab/'xbf-setting-ids.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf8')
syms={}
for label in ['old-settings-datamodel','host-settings-datamodel','old-settings-viewmodel']:
 s=json.loads((root/'work/compat-research'/label/'all-public-symbols.json').read_text());matches=[r for r in s if any(t in r['name'].lower() for t in ['powerandsleep','powerandsuspend','sleepafter','monitorpower','enumerationitem','enumsetting','getenumeration','getitems','enumvalues','enumerated'])];syms[label]=matches
 print(label,len(matches))
 for row in matches[:45]:print(hex(row['rva']),row['name'][:170])
(lab/'enumeration-symbols.json').write_text(json.dumps(syms,indent=2),encoding='utf8')

