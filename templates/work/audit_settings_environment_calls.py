import sys,json
from pathlib import Path
sys.path.insert(0,'work/pylib');import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
for i in cs.disasm(p.get_data(0x4a528,0x2000),0x4a528):
 if any(o.type==capstone.x86.X86_OP_MEM and o.mem.disp in [0x48,0x50] and o.mem.base not in [capstone.x86.X86_REG_RBP,capstone.x86.X86_REG_RSP,capstone.x86.X86_REG_RIP] for o in i.operands):print(hex(i.address),i.mnemonic,i.op_str)
