from pathlib import Path
import sys,json,struct
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/user32.dll');w=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/win32u.dll');h=pefile.PE('C:/Windows/System32/user32.dll');hw=pefile.PE('C:/Windows/System32/win32u.dll')
im={x.address-p.OPTIONAL_HEADER.ImageBase:x.name.decode() if x.name else str(x.ordinal) for d in p.DIRECTORY_ENTRY_IMPORT for x in d.imports}
him={x.address-h.OPTIONAL_HEADER.ImageBase:x.name.decode() if x.name else str(x.ordinal) for d in h.DIRECTORY_ENTRY_IMPORT for x in d.imports}
ex={x.name.decode():x for x in h.DIRECTORY_ENTRY_EXPORT.symbols if x.name}
hwe={x.name.decode():x for x in hw.DIRECTORY_ENTRY_EXPORT.symbols if x.name}
wc={x.name.decode():x for x in w.DIRECTORY_ENTRY_EXPORT.symbols if x.name};table=wc['gDispatchTableValues'].address
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True;fncache={};rows=[]
refs=json.loads(Path('work/user32-unsupported-operations.json').read_text())['references']
for r in refs:
 if r['operation'] not in ['NtUserCallNoParam','NtUserCallOneParam','NtUserCallTwoParam']:continue
 rv=int(r['instructionRVA'],16);func=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress),None)
 start=func.BeginAddress if func else max(rv-60,0);end=func.EndAddress if func else rv+10
 if start not in fncache:fncache[start]=list(c.disasm(p.get_data(start,end-start),start))
 before=[x for x in fncache[start] if x.address<rv][-14:];ins=[];reg='ecx' if r['operation']=='NtUserCallNoParam' else 'edx' if r['operation']=='NtUserCallOneParam' else 'r8d';selector=None;source=None;regtable={}
 for x in before:
  ann=''
  for op in x.operands:
   if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:ann=im.get(x.address+x.size+op.mem.disp,'')
  ins.append(f'{x.address:x}: {x.mnemonic} {x.op_str} {ann}')
  if x.mnemonic=='call':selector=None;source=None;regtable={}
  if x.mnemonic=='mov' and len(x.operands)==2 and x.operands[0].type==capstone.x86.X86_OP_REG:
   dest=x.reg_name(x.operands[0].reg);src=x.operands[1]
   if ann=='gDispatchTableValues':regtable[dest]='gDispatchTableValues'
   if dest==reg:
    source=f'{x.address:x}: {x.mnemonic} {x.op_str}'
    selector=src.imm if src.type==capstone.x86.X86_OP_IMM else None
    if src.type==capstone.x86.X86_OP_MEM and x.reg_name(src.mem.base) in regtable:
     selector=struct.unpack('<I',w.get_data(table+src.mem.disp,4))[0]
     source+=' [old gDispatchTableValues+%x]'%src.mem.disp
 caller=r['publicSymbol'];hostContext=[]
 if caller in ex:
  hx=ex[caller]
  for x in c.disasm(h.get_data(hx.address,150),hx.address):
   ann=''
   for op in x.operands:
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:ann=him.get(x.address+x.size+op.mem.disp,'')
   hostContext.append(f'{x.address:x}: {x.mnemonic} {x.op_str} {ann}')
   if x.mnemonic=='ret' or (x.mnemonic=='jmp' and ann):break
 rows.append({**r,'runtimeFunctionStart':hex(start),'selectorRegister':reg,'selectorValue':selector,'selectorSource':source,'precedingInstructions':ins,'sameNamedHostUser32Exists':caller in ex,'hostUser32Context':hostContext,'sameNamedHostSyscallExists':('NtUser'+caller) in hwe})
Path('work/user32-legacy-selectors.json').write_text(json.dumps(rows,indent=2),encoding='utf8')
print('Legacy directcall sites',len(rows),'resolved selectors',sum(x['selectorValue'] is not None for x in rows))
for x in rows:
 if x['publicSymbol'] in ['SetCaretPos','GetCursorPos','RegisterLogonProcess','EnableShellWindowManagementBehavior','ClientThreadSetup','InitOemXlateTables']:
  print(x['operation'],x['instructionRVA'],x['publicSymbol'],x['selectorValue'],x['selectorSource'])
