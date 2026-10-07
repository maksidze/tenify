import sys,json,bisect
sys.path.insert(0,'work/pylib');import pefile,capstone
from capstone.x86_const import X86_OP_MEM
p=pefile.PE('outputs/Windows10-Components/Runtime/Explorer10/explorer.exe');s=json.load(open('work/explorer-public-symbols.json'));s.sort();starts=[r[0] for r in s];d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True;d.skipdata=True;a=[]
for sec in p.sections:
 if not sec.Characteristics&0x20000000:continue
 for i in d.disasm(p.get_data(sec.VirtualAddress,sec.Misc_VirtualSize),sec.VirtualAddress):
  if i.mnemonic not in ('call','jmp'):continue
  for op in i.operands:
   if op.type==X86_OP_MEM and i.reg_name(op.mem.base)=='rip' and i.address+i.size+op.mem.disp==0x39c098:
    index=bisect.bisect_right(starts,i.address)-1;a.append({'rva':hex(i.address),'symbolRva':hex(s[index][0]),'symbol':s[index][1],'instruction':i.mnemonic+' '+i.op_str})
json.dump(a,open('work/old-explorer-taskpool-context-xrefs.json','w'),indent=2);print(a)

