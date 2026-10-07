from pathlib import Path
import sys,struct,json
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile,capstone
p=pefile.PE(str(B/'Image/4/Windows/System32/SettingsHandlers_nt.dll'));base=p.OPTIONAL_HEADER.ImageBase;names={}
for entry in p.DIRECTORY_ENTRY_IMPORT:
 for i in entry.imports:names[i.address-base]=entry.dll.decode()+':'+(i.name.decode() if i.name else '#'+str(i.ordinal))
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
todo=[(0x168e0,0)];done=set();lines=[]
while todo:
 a,depth=todo.pop(0)
 if a in done:continue
 done.add(a);fn=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress),None)
 if fn:end=fn.EndAddress
 else:end=a+128
 lines.append('\nFUNCTION '+hex(a)+' depth='+str(depth))
 for i in cs.disasm(p.get_data(a,min(end-a,4000)),a):
  notes=[]
  for o in i.operands:
   t=o.imm if o.type==capstone.x86.X86_OP_IMM else i.address+i.size+o.mem.disp if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP else 0
   if t in names:notes.append(names[t])
   elif 0x1000<t<p.OPTIONAL_HEADER.SizeOfImage:
    s=p.get_data(t,256).decode('utf-16-le',errors='replace').split('\0')[0]
    if len(s)>=3 and all(x.isprintable() for x in s):notes.append(repr(s))
   if i.mnemonic in ['call','jmp'] and o.type==capstone.x86.X86_OP_IMM and depth<2 and t>0x1000:todo.append((t,depth+1))
  lines.append(f'{i.address:x} {i.mnemonic} {i.op_str} '+'; '.join(notes))
(H/'nt-description-disasm.txt').write_text('\n'.join(lines),encoding='utf-8');print('functions',len(done),'lines',len(lines))
