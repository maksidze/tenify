from pathlib import Path
import json
for tag in ['old','host']:
 r=json.loads(Path(f'work/compat-research/{tag}-windowwatcher-ps/all-public-symbols.json').read_text());rows=[x for x in r if 'WindowWatcher' in x['name']];print(tag,len(rows));print('\n'.join(f"{x['rva']:x} {x['name']}" for x in rows));Path(f'work/windowwatcher/{tag}-watcher-symbols.json').write_text(json.dumps(rows,indent=2))
