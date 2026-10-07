from pathlib import Path
import json
r=json.loads(Path('work/compat-research/old-twinui/all-public-symbols.json').read_text());rows=[x for x in r if 'WindowManagerBridge' in x['name'] and any(y in x['name'] for y in ['Initialize','WindowWatcher','Shutdown','Stop','Restart'])];print('\n'.join(f"{x['rva']:x} {x['name']}" for x in rows))
