from pathlib import Path
import sys,json
sys.path.insert(0,str(Path(__file__).parent/'pylib'))
import pefile,capstone
root=Path(__file__).resolve().parents[1]
p=pefile.PE(r'C:\Windows\System32\twinui.pcshell.dll')
syms=json.loads((root/'work/compat-research/host-twinui/all-public-symbols.json').read_text())
names={v['rva']:v['name'] for v in syms}
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
addresses=[int(x,16) for x in sys.argv[1:]] or [0x176284,0x172f1c,0x173494,0x16e9e0,0x55d5c,0x17f950,0x176350,0x176530,0x172eb0,0x16e638]
out=[]
for start in addresses:
 end=next((x.struct.EndAddress for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==start),start+0x100)
 out.append(f'\n{start:x}..{end:x} {names.get(start)}')
 for x in md.disasm(p.get_data(start,end-start),start):
  extra=''
  for o in x.operands:
   addr=o.imm if o.type==capstone.x86.X86_OP_IMM else (x.address+x.size+o.mem.disp if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP else None)
   if addr in names:extra+=' ; '+names[addr]
  out.append(f'{x.address:x}: {x.mnemonic} {x.op_str}{extra}')
text='\n'.join(out)
(root/('work/host-appview-map-'+('-'.join(sys.argv[1:]) if len(sys.argv)>1 else 'disassembly')+'.txt')).write_text(text,encoding='utf-8')
print(text)
