from pathlib import Path
import json,difflib
r=json.loads(Path('work/windowwatcher/appview-ndr-methods.json').read_text());norm=lambda p:(p['attributes'],p['stackOffset'],p.get('baseType'),p.get('IID'), p.get('typeBytes','')[:12] if 'IID' not in p else '')
f=lambda m:tuple(norm(p) for p in m['parameters']);a=[f(m) for m in r['old']['methods']];b=[f(m) for m in r['host']['methods']]
sm=difflib.SequenceMatcher(None,a,b,autojunk=False)
for op,a0,a1,b0,b1 in sm.get_opcodes():print(op,'old slots',a0+6,a1+6,'host slots',b0+6,b1+6)
for tag in r:
 print(tag)
 for m in r[tag]['methods']:print(m['slot'],str(f(m)))
