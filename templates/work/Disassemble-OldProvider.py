from pathlib import Path
import sys,json,bisect,uuid
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
old='--old' in sys.argv
if old:sys.argv.remove('--old')
pe=pefile.PE(str(root/'outputs/Windows10-Components/Image/4/Windows/System32/windows.immersiveshell.serviceprovider.dll') if old else 'C:/Windows/System32/twinui.pcshell.dll')
syms=json.loads((root/('work/compat-research/old-provider/all-public-symbols.json' if old else 'work/compat-research/host-twinui/all-public-symbols.json')).read_text());byrva={s['rva']:s['name'] for s in syms}
imports={i.address-pe.OPTIONAL_HEADER.ImageBase:(d.dll.decode()+'.'+(i.name.decode() if i.name else '#'+str(i.ordinal))) for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
for address in sys.argv[1:]:
 rva=int(address,16);fn=next(x.struct for x in pe.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rva<x.struct.EndAddress)
 print(hex(fn.BeginAddress),byrva.get(fn.BeginAddress,'?'))
 for i in cs.disasm(pe.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress):
  notes=[]
  for o in i.operands:
   if o.type==capstone.x86.X86_OP_IMM:notes.append(byrva.get(o.imm,''))
   if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP:
    target=i.address+i.size+o.mem.disp;notes.append(hex(target)+' '+byrva.get(target,imports.get(target,'')))
    if i.mnemonic=='lea' and target>0x680000:
     notes.append(str(uuid.UUID(bytes_le=pe.get_data(target,16))))
  print(f'{i.address:x}: {i.mnemonic} {i.op_str}  '+ '; '.join(x for x in notes if x))

