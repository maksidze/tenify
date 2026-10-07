from pathlib import Path
import sys,struct,json,re,bisect
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'));import pefile
for label,targets in [('shell32',[0x47ab64]),('explorerframe',[0x139b50,0x1b8d34])]:
 pe=pefile.PE('C:/Windows/System32/'+label+'.dll');syms=sorted(json.loads((root/'work/compat-research'/('host-'+label)/'all-public-symbols.json').read_text()),key=lambda s:s['rva']);rs=[s['rva'] for s in syms]
 for sec in pe.sections:
  if not sec.Characteristics&0x20000000:continue
  b=sec.get_data()
  for m in re.finditer(rb'\xe8....',b,re.S):
   call=sec.VirtualAddress+m.start();target=call+5+struct.unpack_from('<i',m.group(),1)[0]
   if target not in targets:continue
   fn=next((e.struct.BeginAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=call<e.struct.EndAddress),None)
   s=syms[bisect.bisect_right(rs,fn or call)-1];print(label,hex(target),'at',hex(call),'fn',hex(fn or 0),s['name'])
