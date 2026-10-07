import sys,json,struct
sys.path.insert(0,'work/pylib');import pefile,capstone
from capstone.x86_const import X86_OP_MEM
out={}
for label,path in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll'),('host','C:/Windows/System32/twinui.pcshell.dll')]:
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));ns={};p=pefile.PE(path);d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True
 for x in s:ns.setdefault(x['rva'],[]).append(x['name'])
 tables=[];refs=[]
 for r in s:
  if r['name'].startswith('??_7') and 'CAllUpViewService@@6BIAllUpViewService@@@' in r['name']:
   rows=[]
   for k in range(5):
    a=struct.unpack('<Q',p.get_data(r['rva']+k*8,8))[0]-p.OPTIONAL_HEADER.ImageBase;rows.append({'slot':k,'rva':hex(a),'names':ns.get(a)})
   tables.append({'name':r['name'],'rva':hex(r['rva']),'slots':rows});print(label,hex(r['rva']),[(x['slot'],x['rva']) for x in rows])
  if 'CanCastTo' in r['name'] and '$00UIAllUpViewService@@UIEdgeUiTouchInvocation@@UIAllUpViewInvoker' in r['name']:
   f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==r['rva'])
   lines=[]
   for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
    line=f'{i.address:x} {i.mnemonic} {i.op_str}'
    for op in i.operands:
     if op.type==X86_OP_MEM and i.reg_name(op.mem.base)=='rip':
      t=i.address+i.size+op.mem.disp
      for n in ns.get(t,[]):
       if '_GUID' in n:line+=' '+n;print(label,line)
    lines.append(line)
   refs.append({'rva':hex(r['rva']),'name':r['name'],'instructions':lines})
 out[label]={'tables':tables,'casts':refs}
json.dump(out,open('work/taskview-allup-abi.json','w'),indent=2)
