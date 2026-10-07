from pathlib import Path
import sys,json,bisect,uuid
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root/'work/pylib'))
import pefile,capstone
old='--old' in sys.argv
if old:sys.argv.remove('--old')
def option(name,default):
 if name not in sys.argv:return default
 i=sys.argv.index(name);value=sys.argv[i+1];del sys.argv[i:i+2];return value
module=option('--module',str(root/'outputs/Windows10-Components/Image/4/Windows/System32/twinui.pcshell.dll') if old else 'C:/Windows/System32/twinui.pcshell.dll')
symbols=option('--symbols',str(root/('work/compat-research/old-twinui/all-public-symbols.json' if old else 'work/compat-research/host-twinui/all-public-symbols.json')))
pe=pefile.PE(module)
syms=json.loads(Path(symbols).read_text());byrva={s['rva']:s['name'] for s in syms}
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
    if i.mnemonic=='lea' and (target>0x680000 or byrva.get(target,'').startswith(('_GUID','IID_','CLSID_'))):
     candidate=pe.get_data(target,16)
     if len(candidate)==16:notes.append(str(uuid.UUID(bytes_le=candidate)))
  print(f'{i.address:x}: {i.mnemonic} {i.op_str}  '+ '; '.join(x for x in notes if x))
