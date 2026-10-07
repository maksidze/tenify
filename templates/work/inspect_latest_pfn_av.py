from pathlib import Path
import json
r=json.loads(Path('outputs/Windows10-Components/Lab/PfnCompat/feeds-nullguard-probe.json').read_text(encoding='utf8'));base=int(r['modules'][0]['base'],16);e=next(x for x in r['events'] if x.get('type')=='exceptionContext');rv=int(e['registers']['rip'],16)-base;print(hex(base),hex(rv));syms=json.loads(Path('work/explorer-public-symbols.json').read_text());print([x for x in syms if x[0]<=rv][-4:]);print('Stack nearest symbols:')
import struct
b=bytes.fromhex(e['stackBytes'])
for pos in range(0,len(b),8):
 a=struct.unpack_from('<Q',b,pos)[0];q=a-base
 if 0<q<0x500000:print(hex(pos),hex(q),[x for x in syms if x[0]<=q][-1])
