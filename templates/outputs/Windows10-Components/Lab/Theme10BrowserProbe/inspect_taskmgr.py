from pathlib import Path
import sys,json,bisect
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'work/pylib'))
import pefile,capstone
p=pefile.PE('C:/Windows/System32/Taskmgr.exe');s=json.loads((R/'work/compat-research/host-taskmgr/all-public-symbols.json').read_text());names={x['rva']:x['name']for x in s};keys=sorted(names)
for d in list(getattr(p,'DIRECTORY_ENTRY_IMPORT',[]))+list(getattr(p,'DIRECTORY_ENTRY_DELAY_IMPORT',[])):
 for i in d.imports:names[i.address-p.OPTIONAL_HEADER.ImageBase]='IAT '+d.dll.decode()+'!'+(i.name.decode()if i.name else '#'+str(i.ordinal))
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;lines=[]
for x in s+[{'rva':0x16d650,'name':'worker target of SHCreateThread'},{'rva':0x16c520,'name':'initialization callback target of SHCreateThread'}]:
 if not(x['rva'] in (0x16d650,0x16c520,0x1c6bc0,0xaab80) or x['name'].startswith('?InvokeNewTask@@') or x['name'].startswith('?BasePage_RunNewTask@')):continue
 a=x['rva'];end=next(e.struct.EndAddress for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==a);lines.append(f'\n{a:x} {x["name"]}')
 for i in md.disasm(p.get_data(a,end-a),a):
  extras=[]
  for o in i.operands:
   dest=o.imm if o.type==capstone.x86.X86_OP_IMM else i.address+i.size+o.mem.disp if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP else None
   if dest in names:extras.append(names[dest])
  lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str} '+ '; '.join(extras))
(H/'taskmgr-run-newtask-disassembly.txt').write_text('\n'.join(lines));print('\n'.join(lines))
