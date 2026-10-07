import json
from pathlib import Path
for n in ['old-settings-datamodel','host-settings-datamodel','old-settings-viewmodel']:
 ss=json.loads((Path('work/compat-research')/n/'all-public-symbols.json').read_text());print(n)
 for x in ss:
  if any(t in x['name'] for t in ['?GetSetting@','?LoadSetting@','?GetSettingForUser@','?GetSettingsDatabase@','?GetDatabase@','?GetProperty@','?GetValue@']) and not any(t in x['name'] for t in ['DeepLink','get_','?$consume']):print(hex(x['rva']),x['name'][:200])
