from pathlib import Path
import json,struct
H=Path(__file__).resolve().parent;R=H.parents[3]
for p in (H/'old').glob('*PageViewModel.xbf'):
 b=p.read_bytes();offs=struct.unpack_from('<6Q',b,20);minor=struct.unpack_from('<I',b,16)[0];a=12+offs[0];n=struct.unpack_from('<I',b,a)[0];a+=4;strings=[]
 for _ in range(n):
  length=struct.unpack_from('<I',b,a)[0];a+=4;strings.append(b[a:a+2*length].decode('utf-16-le'));a+=length*2+(2 if minor>=1 else 0)
 (p.with_suffix('.strings.json')).write_text(json.dumps(strings,ensure_ascii=False,indent=2),encoding='utf-8')
for folder in ['old-settings-viewmodel','old-settings-datamodel','host-settings-datamodel','old-settings-environment','host-settings-environment']:
 syms=json.loads((R/'work/compat-research'/folder/'all-public-symbols.json').read_text())
 matches=[s for s in syms if any(x in s['name'] for x in ['Description','get_DisplayName','GetDynamicText','IsDynamicText','ResourcePropertyBag','GetSettingItem','GetItem@','GetProperty@'])]
 (H/(folder+'-relevant-symbols.json')).write_text(json.dumps(matches,indent=2),encoding='utf-8')
 print(folder,len(matches))
