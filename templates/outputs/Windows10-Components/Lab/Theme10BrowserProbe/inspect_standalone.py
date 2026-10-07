from pathlib import Path
import sys,json,ctypes
H=Path(__file__).resolve().parent;R=H.parents[3]
sys.path.insert(0,str(R/'work/pylib'))
import pefile,capstone
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
p=pefile.PE('C:/Windows/System32/uxtheme.dll')
symbols=json.loads((R/'work/compat-research/host-uxtheme/all-public-symbols.json').read_text())
names={x['rva']:x['name'] for x in symbols}
for d in p.DIRECTORY_ENTRY_IMPORT:
 for i in d.imports:names[i.address-p.OPTIONAL_HEADER.ImageBase]=d.dll.decode()+'!'+(i.name.decode()if i.name else '#'+str(i.ordinal))
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
starts=[0x609c0,0x4720,0x493f0,0x5f7c0,0x49f94,0x58868,0x48c8,0x61394,0x583d0]
starts += [x['rva'] for x in symbols if any(s in x['name']for s in ['CloseThemeFile','OpenThemeFile','Initialize@CUxThemeFile','??1CUxThemeFile','Create@CUxThemeFile'])]
dbg=ctypes.WinDLL('dbghelp');dbg.UnDecorateSymbolName.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint32,ctypes.c_uint32]
lines=[]
for e in p.DIRECTORY_ENTRY_EXPORT.symbols:
 if e.address in starts or e.ordinal in (7,8,9,10,11,12,13,14,15,16,17,92):lines.append(f'export #{e.ordinal} RVA{e.address:x} name={e.name}')
for start in sorted(set(starts)):
 end=next((e.struct.EndAddress for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==start),start+100)
 name=names.get(start,'?');buf=ctypes.create_string_buffer(2048);dbg.UnDecorateSymbolName(name.encode(),buf,2048,0)
 lines.append(f'\n{start:x} {name}\n{buf.value.decode()}')
 for i in md.disasm(p.get_data(start,end-start),start):
  targets=[]
  for o in i.operands:
   a=o.imm if o.type==X86_OP_IMM else i.address+i.size+o.mem.disp if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP else None
   if a in names:targets.append(names[a])
  lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str} '+ '; '.join(targets))
(H/'standalone-theme-disassembly.txt').write_text('\n'.join(lines))
print('\n'.join(lines))
