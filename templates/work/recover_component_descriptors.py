"""Static symbolic recovery of only the straight-line CRT table initializer.
No image code is executed. Unknown external return values remain unknown.
"""
from pathlib import Path
import sys,struct,json,uuid
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
from Registry import Registry
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/twinui.pcshell.dll');base=p.OPTIONAL_HEADER.ImageBase
fn=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress==0x3a20)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;regs={};mem={};unknown=[];writes={}
def rn(reg):
 n=cs.reg_name(reg)
 return {'eax':'rax','ecx':'rcx','edx':'rdx','r8d':'r8','r9d':'r9','r10d':'r10','al':'rax'}.get(n,n)
for i in cs.disasm(p.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress):
 ops=i.operands
 if i.mnemonic=='call':
  for n in ['rax','rcx','rdx','r8','r9','r10','r11']:regs[n]=None
 elif i.mnemonic=='lea' and ops[0].type==1:
  m=ops[1].mem
  regs[rn(ops[0].reg)]=base+i.address+i.size+m.disp if m.base==capstone.x86.X86_REG_RIP else (regs.get(rn(m.base))+m.disp if regs.get(rn(m.base)) is not None and not m.index else None)
 elif i.mnemonic=='xor' and len(ops)==2 and ops[0].type==ops[1].type==1 and ops[0].reg==ops[1].reg:regs[rn(ops[0].reg)]=0
 elif i.mnemonic in ('sbb','neg','add') and ops[0].type==1:regs[rn(ops[0].reg)]=None
 elif i.mnemonic in ('mov','movdqa') and len(ops)==2:
  a,b=ops
  if a.type==1:
   value=b.imm if b.type==2 else regs.get(rn(b.reg)) if b.type==1 else p.get_data(i.address+i.size+b.mem.disp,b.size) if b.type==3 and b.mem.base==capstone.x86.X86_REG_RIP else None
   regs[rn(a.reg)]=value
  elif a.type==3 and a.mem.base==capstone.x86.X86_REG_RIP:
   target=i.address+i.size+a.mem.disp;value=b.imm if b.type==2 else regs.get(rn(b.reg)) if b.type==1 else None
   if value is None:unknown.append({'rva':hex(target),'size':a.size,'instruction':hex(i.address)})
   else:
    data=value if isinstance(value,bytes) else (value&((1<<(a.size*8))-1)).to_bytes(a.size,'little')
    for j,c in enumerate(data[:a.size]):mem[target+j]=c
    writes[hex(target)]=hex(i.address)
def read(rv,n):
 raw=p.get_data(rv,n)
 return bytes(mem.get(rv+j,raw[j]) for j in range(n))
reg=Registry.Registry('outputs/Windows10-Components/Image/4/Windows/System32/config/SOFTWARE');rows=[]
for index in range(139):
 rv=0x649270+index*24;ptr,flags,required,feature=struct.unpack('<QIIQ',read(rv,24))
 if not base<ptr<base+p.OPTIONAL_HEADER.SizeOfImage:continue
 guid=str(uuid.UUID(bytes_le=p.get_data(ptr-base,16)));registration=[]
 try:
  key=reg.open('Classes\\CLSID\\{'+guid+'}')
  registration=[{'key':k.path(),'values':{v.name():v.value() for v in k.values()}} for k in [key,*key.subkeys()]]
 except Registry.RegistryKeyNotFoundException:pass
 rows.append({'index':index,'CLSID':guid,'flags':flags,'required':required,'featureCallbackRVA':hex(feature-base) if feature else None,'descriptorRVA':hex(rv),'writes':{k:v for k,v in writes.items() if rv<=int(k,16)<rv+24},'unknownWrites':[x for x in unknown if rv<=int(x['rva'],16)<rv+24],'oldRegistration':registration})
Path('work/windowwatcher/all-component-descriptors.json').write_text(json.dumps(rows,indent=2,default=str));print('Recovered',len(rows),'descriptors; unknown writes',len(unknown));print(next(x for x in rows if x['index']==116))
