import json,sys
sys.path.insert(0,'work/pylib');import pefile,capstone
from capstone.x86_const import X86_OP_MEM
for label,path in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll'),('host','C:/Windows/System32/twinui.pcshell.dll')]:
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));ns={x['rva']:x['name'] for x in s};p=pefile.PE(path);d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True
 print(label)
 seen=set()
 for r in s:
  if not ('UIVirtualDesktop2@@UIVirtualDesktop@@' in r['name'] and any(t in r['name'] for t in ('CanCastTo','GetIids','QueryInterface'))):continue
  if r['rva'] in seen:continue
  f=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==r['rva']),None)
  if not f:continue
  seen.add(r['rva'])
  for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
   for op in i.operands:
    if op.type==X86_OP_MEM and i.reg_name(op.mem.base)=='rip':
     target=i.address+i.size+op.mem.disp;n=ns.get(target,'')
     if '_GUID' in n:print(hex(i.address),n)
