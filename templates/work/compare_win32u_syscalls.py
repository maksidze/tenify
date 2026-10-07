from pathlib import Path
import sys,json,csv,collections
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True
def inspect(path):
 p=pefile.PE(str(path));exports={}
 for x in p.DIRECTORY_ENTRY_EXPORT.symbols:
  if not x.name:continue
  name=x.name.decode();instructions=list(c.disasm(p.get_data(x.address,32),x.address));number=None;sample=[]
  for i in instructions:
   sample.append(f'{i.mnemonic} {i.op_str}')
   if i.mnemonic=='mov' and len(i.operands)==2 and i.operands[0].type==capstone.x86.X86_OP_REG and i.operands[0].reg==capstone.x86.X86_REG_EAX and i.operands[1].type==capstone.x86.X86_OP_IMM:number=i.operands[1].imm
   if i.mnemonic=='ret':break
  exports[name]={'ordinal':x.ordinal,'rva':hex(x.address),'syscallNumber':number,'instructions':sample}
 return exports
old=inspect(Path('outputs/Windows10-Components/Image/4/Windows/System32/win32u.dll'));host=inspect(Path('C:/Windows/System32/win32u.dll'));rows=[]
for name in sorted(set(old)|set(host)):
 a=old.get(name);b=host.get(name)
 status='missing-host' if b is None else 'new-host' if a is None else 'unknown-stub' if a['syscallNumber'] is None or b['syscallNumber'] is None else 'same' if a['syscallNumber']==b['syscallNumber'] else 'changed'
 rows.append({'name':name,'status':status,'oldNumber':a['syscallNumber'] if a else None,'hostNumber':b['syscallNumber'] if b else None,'old':a,'host':b})
hostByNumber={x['syscallNumber']:n for n,x in host.items() if x['syscallNumber'] is not None}
for row in rows:
 row['hostOperationForOldNumber']=hostByNumber.get(row['oldNumber'])
result={'oldPath':'outputs/Windows10-Components/Image/4/Windows/System32/win32u.dll','hostPath':'C:/Windows/System32/win32u.dll','summary':dict(collections.Counter(r['status'] for r in rows)),'operations':rows,'executedSyscalls':False}
Path('work/win32u-syscall-comparison.json').write_text(json.dumps(result,indent=2),encoding='utf8')
with Path('work/win32u-syscall-comparison.csv').open('w',newline='',encoding='utf-8-sig') as f:
 w=csv.DictWriter(f,fieldnames=['name','status','oldNumber','hostNumber','hostOperationForOldNumber']);w.writeheader()
 w.writerows({k:r[k] for k in w.fieldnames} for r in rows)
print(result['summary'])
for name in ['NtUserCreateWindowGroup','NtUserDeleteWindowGroup','NtUserGetWindowGroupId','NtUserEnableWindowGroupPolicy','NtUserSetWindowGroup','NtUserCreateWindowEx','NtUserGetMessage','NtUserPeekMessage']:
 row=next((r for r in rows if r['name']==name),None);print({k:row[k] for k in ['name','status','oldNumber','hostNumber','hostOperationForOldNumber']})
