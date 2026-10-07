from pathlib import Path
import json
for n in ['old-settings-viewmodel','old-settings-datamodel','host-settings-datamodel']:
 ss=json.loads((Path('work/compat-research')/n/'all-public-symbols.json').read_text());rows=[x for x in ss if ('SettingEntry' in x['name'] or 'ListSetting' in x['name'] or 'SettingItem' in x['name']) and not any(t in x['name'] for t in ['?$Vector','?$Array','?$Iterator','?$RuntimeClass','GetTrustLevel','GetRuntimeClassName','__abi_AddRef','__abi_Release','__abi_Query','__abi_GetIids'])];print(n,len(rows));print('\n'.join(hex(x['rva'])+' '+x['name'] for x in rows[:65]));Path('outputs/Windows10-Components/Lab/SettingsEnumCompat/'+n+'-setting-items.json').write_text(json.dumps(rows,indent=2))
