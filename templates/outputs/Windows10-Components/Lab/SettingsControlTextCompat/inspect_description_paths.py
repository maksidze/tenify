from pathlib import Path
import sys,json,bisect
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent.parent
sys.path.insert(0,str(R/'work/pylib'));import pefile,capstone
parts=[]
for folder,path in [('old-settings-viewmodel',B/'Image/4/Windows/ImmersiveControlPanel/SystemSettingsViewModel.Desktop.dll'),('old-settings-datamodel',R/'work/settings-datamodel-image/4/Windows/System32/SystemSettings.DataModel.dll'),('host-settings-datamodel',Path('C:/Windows/System32/SystemSettings.DataModel.dll'))]:
 p=pefile.PE(str(path));syms=json.loads((R/'work/compat-research'/folder/'all-public-symbols.json').read_text());names={s['rva']:s['name'] for s in syms};starts=sorted(names);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 selected=set()
 for s in syms:
  n=s['name'];a=s['rva']
  if ('lambda_202b44392e92a32cb0d9e75187166e89' in n or 'lambda_d79ca77dcee652280f7d1dab756444ac' in n):selected.add(a)
  if folder=='old-settings-viewmodel' and ('SettingEntry@' in n or 'ResourcePropertyBag' in n):
   end=starts[min(bisect.bisect(starts,a),len(starts)-1)]
   instructions=list(cs.disasm(p.get_data(a,min(end-a,16000)),a))
   if any(o.type==capstone.x86.X86_OP_MEM and o.mem.disp==0x138 for i in instructions for o in i.operands):selected.add(a)
 for a in sorted(selected):
  end=starts[min(bisect.bisect(starts,a),len(starts)-1)];parts.append('\n'+folder+' '+hex(a)+' '+names.get(a,''))
  for i in cs.disasm(p.get_data(a,min(end-a,16000)),a):
   notes=[]
   for o in i.operands:
    t=o.imm if o.type==capstone.x86.X86_OP_IMM else i.address+i.size+o.mem.disp if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP else 0
    if t in names:notes.append(names[t])
   parts.append(f'{i.address:06x}: {i.mnemonic:8} {i.op_str}  '+ '; '.join(notes))
(H/'description-paths.txt').write_text('\n'.join(parts),encoding='utf-8')
print('Wrote',len(parts),'lines')
