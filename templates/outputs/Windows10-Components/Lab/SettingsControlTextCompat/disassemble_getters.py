from pathlib import Path
import sys,json,bisect
sys.stdout.reconfigure(encoding='utf-8')
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile,capstone
targets=[('old-settings-viewmodel',B/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll',[0x3adb0,0x39650,0x405b4,0x69f20,0x6a1a0]),('host-settings-datamodel',Path('C:/Windows/System32/SystemSettings.DataModel.dll'),[0x41830])]
lines=[]
for folder,path,addresses in targets:
 pe=pefile.PE(str(path));symbols=json.loads((R/'work/compat-research'/folder/'all-public-symbols.json').read_text());names={s['rva']:s['name'] for s in symbols};starts=sorted(names)
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 for address in addresses:
  lines.append('\n'+folder+' '+hex(address)+' '+names.get(address,''))
  end=starts[bisect.bisect(starts,address)]
  for i in cs.disasm(pe.get_data(address,min(end-address,2000)),address):
   notes=[]
   for op in i.operands:
    target=op.imm if op.type==capstone.x86.X86_OP_IMM else i.address+i.size+op.mem.disp if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP else 0
    if target:
     if target in names:notes.append(names[target])
     elif target>0x1000:
      try:
       data=pe.get_data(target,160);text=data.decode('utf-16-le',errors='replace').split('\0')[0]
       if text and all(c.isprintable() for c in text):notes.append(repr(text))
      except Exception:pass
   lines.append(f'{i.address:06x}: {i.mnemonic:8} {i.op_str}  '+ '; '.join(notes))
(H/'description-getters.txt').write_text('\n'.join(lines),encoding='utf-8');print('\n'.join(lines))
