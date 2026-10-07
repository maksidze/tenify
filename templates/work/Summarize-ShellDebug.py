from pathlib import Path
import json,struct,sys,bisect
root=Path(__file__).resolve().parent.parent;base=root/'outputs/Windows10-Components'
run=Path(sys.argv[1]) if len(sys.argv)>1 else max((p for p in (base/'state-vfs').iterdir() if (p/'debug.jsonl').is_file()),key=lambda p:(p/'debug.jsonl').stat().st_mtime)
events=[json.loads(s) for s in (run/'debug.jsonl').read_text(encoding='utf-8').splitlines()]
modules=sorted((int(e['base'],16),e['path']) for e in events if e['type']=='module')
def locate(address):
 candidates=[(a,p) for a,p in modules if a<=address]
 if not candidates:return hex(address)
 a,p=candidates[-1]
 return str(Path(p).name)+'+'+hex(address-a) if address-a<0x2000000 else hex(address)
out=['RUN '+str(run)]
for e in events[-25:]:
 if e['type']=='debugString':out.append(e['message'].strip())
 elif e['type']=='exception':
  out.append('EXCEPTION '+e['code']+' '+locate(int(e['address'],16))+' first='+str(e['firstChance']))
  if not e['firstChance']:
   out.append('REGS '+str(e.get('registers')));stack=bytes.fromhex(e.get('stackRaw',''))
   out.append('RAW STACK POINTER CANDIDATES (not an unwind)')
   for i in range(0,len(stack)//8*8,8):
    v=struct.unpack_from('<Q',stack,i)[0];loc=locate(v)
    if '+' in loc:out.append(hex(i)+': '+loc)
 elif e['type']=='exit':out.append('EXIT '+str(e['code']))
out='\n'.join(out);(run/'summary.txt').write_text(out,encoding='utf-8');print(out)
