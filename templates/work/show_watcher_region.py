from pathlib import Path
import json
r=json.loads(Path('work/windowwatcher/vtable-candidates.json').read_text());print('\n\n'.join(str(x) for x in r if 0x347000<int(x['rva'],16)<0x34c000))
