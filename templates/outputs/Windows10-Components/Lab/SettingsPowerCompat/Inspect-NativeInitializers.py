from pathlib import Path
import sys,json
root=Path(__file__).resolve().parents[4];sys.path.insert(0,str(root/'work/pylib'));import pefile,capstone
p=pefile.PE('C:/Windows/System32/SettingsHandlers_OneCore_PowerAndSleep.dll');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;rows=[]
for i in cs.disasm(p.get_data(0x20c0,0x80),0x20c0):
 notes=[]
 for o in i.operands:
  if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP:notes.append(hex(i.address+i.size+o.mem.disp))
 rows.append(f'{i.address:x} {i.mnemonic} {i.op_str} '+';'.join(notes))
for start in [0x2350,0x2380,0x23b0,0x23e0,0x2410,0x2440,0x2620,0x2650]:
 for i in cs.disasm(p.get_data(start,0x30),start):
  notes=[]
  for o in i.operands:
   if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP:notes.append(hex(i.address+i.size+o.mem.disp))
  rows.append(f'{i.address:x} {i.mnemonic} {i.op_str} '+';'.join(notes))
(Path(__file__).parent/'native-context-initializers.txt').write_text('\n'.join(rows));print('\n'.join(rows[:35]))
