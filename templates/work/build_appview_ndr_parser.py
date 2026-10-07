from pathlib import Path
import json
for tag in ['old','host']:
 sy=json.loads(Path(f'work/compat-research/{tag}-windowwatcher-ps/all-public-symbols.json').read_text());Path(f'work/windowwatcher/{tag}-appwatcher-symbols.json').write_text(json.dumps([x for x in sy if 'AppViewWatcher' in x['name']],indent=2))
s=Path('work/decode_windowwatcher_ndr.py').read_text().replace('IWindowWatcher','IAppViewWatcher').replace('watcher-symbols.json','appwatcher-symbols.json').replace('ndr-methods.json','appview-ndr-methods.json')
s=s[:s.index('for tag in result:')]+"for tag in result:print(tag,result[tag]['IID'],result[tag]['methodCount'])\n"
Path('work/decode_appviewwatcher_ndr.py').write_text(s)
