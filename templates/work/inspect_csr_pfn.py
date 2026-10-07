from pathlib import Path
import struct,sys
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
h=pefile.PE('C:/Windows/System32/user32.dll');n=pefile.PE('C:/Windows/System32/ntdll.dll');c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True
# Only decode in-file bytes.
def dump(p,start,size):
 imp={x.address-p.OPTIONAL_HEADER.ImageBase:(x.name or str(x.ordinal).encode()).decode() for d in p.DIRECTORY_ENTRY_IMPORT for x in d.imports} if hasattr(p,'DIRECTORY_ENTRY_IMPORT') else {}
 lines=[]
 for i in c.disasm(p.get_data(start,size),start):
  ann=''
  for x in i.operands:
   if x.type==capstone.x86.X86_OP_MEM and x.mem.base==capstone.x86.X86_REG_RIP:ann=imp.get(i.address+i.size+x.mem.disp,'')
  lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str} {ann}')
 return '\n'.join(lines)
nt=next(x.address for x in n.DIRECTORY_ENTRY_EXPORT.symbols if x.name==b'CsrClientConnectToServer')
Path('work/host-ntdll-csrconnect.txt').write_text(dump(n,nt,0x900))
# All host .text IAT refs, enclosing function range.
iat=next(x.address-h.OPTIONAL_HEADER.ImageBase for d in h.DIRECTORY_ENTRY_IMPORT for x in d.imports if x.name==b'CsrClientConnectToServer')
refs=[]
for s in h.sections:
 if not s.Characteristics&0x20000000:continue
 for i in c.disasm(s.get_data(),s.VirtualAddress):
  if i.mnemonic=='call' and any(x.type==capstone.x86.X86_OP_MEM and x.mem.base==capstone.x86.X86_REG_RIP and i.address+i.size+x.mem.disp==iat for x in i.operands):refs.append(i.address)
print('CSR host export',hex(nt),'hostUSER32 refs',list(map(hex,refs)))
for rv in refs:
 fn=next(x.struct for x in h.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress)
 Path('work/host-user32-csr-init.txt').write_text(dump(h,fn.BeginAddress,fn.EndAddress-fn.BeginAddress))
