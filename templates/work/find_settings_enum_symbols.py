from pathlib import Path
import json
r=Path('work/compat-research');out={}
for n in ['old-settings-datamodel','host-settings-datamodel','old-settings-viewmodel']:
 s=json.loads((r/n/'all-public-symbols.json').read_text());matches=[x for x in s if any(t in x['name'].lower() for t in ['enumerat','possible','collection','selection','options','settingitem','powerandsleep','power_','timeout','sleep_'])];out[n]=matches
 print(n,len(matches));print('\n'.join(hex(x['rva'])+' '+x['name'][:190] for x in matches[:65]))
Path('outputs/Windows10-Components/Lab/SettingsEnumCompat/enumeration-symbols.json').write_text(json.dumps(out,indent=2))
