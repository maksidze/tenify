import json
from pathlib import Path
for n in ['old-settings-viewmodel','old-settings-datamodel','host-settings-datamodel']:
 ss=json.loads((Path('work/compat-research')/n/'all-public-symbols.json').read_text());print(n)
 for x in ss:
  name=x['name']
  if (name.startswith('?') and 'CSettingItem@DataModel' in name and not any(t in name for t in ['?$','??_'])) or ('SettingEntry@' in name and any(t in name for t in ['Values','Items','Property','Value@','get@?QOptions','Selection'])):print(hex(x['rva']),name[:230])
