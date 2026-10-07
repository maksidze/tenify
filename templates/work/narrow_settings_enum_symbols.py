import json
from pathlib import Path
for n in ['old-settings-datamodel','host-settings-datamodel','old-settings-viewmodel']:
 s=json.loads((Path('work/compat-research')/n/'all-public-symbols.json').read_text());print(n)
 for x in s:
  name=x['name']
  if any(t in name for t in ['Enumeration','EnumValues','PossibleValues','EnumItem','GetOptions','get_Options','get_Values','EnumList','EnumerationSetting']) and not any(t in name for t in ['QueryInterface','GetTrustLevel','GetRuntimeClass','GetIids','AddRef','Release','?$Array','?$Vector','?$Iterator','?$Naive','?$Async','RuntimeClassImpl']):print(hex(x['rva']),name[:220])
