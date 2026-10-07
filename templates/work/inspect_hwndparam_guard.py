from pathlib import Path
import json,sys
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/user32.dll');h=pefile.PE('C:/Windows/System32/user32.dll');r=json.loads(Path('work/user32-all-public-symbols.json').read_text());print(type(r),str(r)[:110])
rv=0x1258f;fn=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress);print('fn',hex(fn.BeginAddress),hex(fn.EndAddress));print([x for x in r if (int(x[0],16) if isinstance(x[0],str) else x[0])<=rv][-4:])
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True
for pe,a,b in [(p,fn.BeginAddress,fn.EndAddress)]:
 im={x.address-pe.OPTIONAL_HEADER.ImageBase:(x.name or b'ordinal').decode() for d in pe.DIRECTORY_ENTRY_IMPORT for x in d.imports}
 for i in c.disasm(pe.get_data(a,b-a),a):
  ann=''
  for x in i.operands:
   if x.type==capstone.x86.X86_OP_MEM and x.mem.base==capstone.x86.X86_REG_RIP:ann=im.get(i.address+i.size+x.mem.disp,'')
  print(f'{i.address:x}: {i.mnemonic} {i.op_str} {ann}')
