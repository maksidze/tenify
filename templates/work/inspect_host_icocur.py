from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
p=pefile.PE('C:/Windows/System32/user32.dll');im={x.address-p.OPTIONAL_HEADER.ImageBase:(x.name or b'ordinal').decode() for d in p.DIRECTORY_ENTRY_IMPORT for x in d.imports};iat=next(k for k,v in im.items() if v=='NtUserGetClassIcoCur');c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True;refs=[];lines=[]
for s in p.sections:
 d=s.get_data()
 for k in range(len(d)-6):
  if d[k:k+2]==b'\xff\x15' and s.VirtualAddress+k+6+struct.unpack_from('<i',d,k+2)[0]==iat:refs.append(s.VirtualAddress+k)
for rv in refs:
 fn=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress);lines.append('FUNCTION '+hex(fn.BeginAddress))
 for i in c.disasm(p.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress):
  ann=''
  for x in i.operands:
   if x.type==capstone.x86.X86_OP_MEM and x.mem.base==capstone.x86.X86_REG_RIP:ann=im.get(i.address+i.size+x.mem.disp,'')
  lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str} {ann}')
Path('work/host-getclassicocur-callers.txt').write_text('\n'.join(lines));print('\n'.join(lines))
