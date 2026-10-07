from pathlib import Path
import json
r=json.loads(Path('work/user32-legacy-selectors.json').read_text());x=[x for x in r if x['selectorValue']==0x13 and x['operation']=='NtUserCallNoParam'];print(json.dumps(x,indent=2))
