from pathlib import Path
import sys,json,bisect,hashlib
R=Path(__file__).resolve().parent.parent;B=R/'outputs/Windows10-Components';sys.path.insert(0,str(R/'work/pylib'))
import pefile,capstone
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
tasks=[('oldStart',B/'Lab/StartCompat/StartUI_.dll','old-startui',[0x3ae190,0x3c067c,0x3c1620,0x3bfb04,0x4fd030]),('nativePCS',B/'Lab/HostMultitaskingCompat/twinui.pcshell.dll','host-twinui',[0x2522e0,0x254c9c,0x254f48,0x24b6a0,0x39b480,0x3b08e0])]
out=[];callSummary=[]
for label,path,symbolDir,targets in tasks:
 pe=pefile.PE(str(path));rows=sorted((x['rva'],x['name'])for x in json.loads((R/'work/compat-research'/symbolDir/'all-public-symbols.json').read_text()));keys=[x[0]for x in rows]
 out.append(f'IMAGE {label} {path} SHA256 {hashlib.sha256(path.read_bytes()).hexdigest()}')
 for target in targets:
  rf=next(e.struct for e in pe.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=target<e.struct.EndAddress)
  k=bisect.bisect_right(keys,target)-1;heading=f'\n{label} {target:x} {rows[k][1]} FUNCTION{rf.BeginAddress:x}-{rf.EndAddress:x}';out.append(heading);callSummary.append(heading)
  for i in cs.disasm(pe.get_data(rf.BeginAddress,rf.EndAddress-rf.BeginAddress),rf.BeginAddress):
   comments=[]
   for op in i.operands:
    dest=None
    if op.type==capstone.x86.X86_OP_IMM and i.mnemonic in ('call','jmp'):dest=op.imm
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:dest=i.address+i.size+op.mem.disp
    if dest is not None:
     k=bisect.bisect_right(keys,dest)-1
     if k>=0 and dest-keys[k]<0x30:comments.append(rows[k][1]+f'+{dest-keys[k]:x}')
   line=f'{i.address:x} {i.bytes.hex()} {i.mnemonic} {i.op_str}'+(' ; '+' | '.join(comments)if comments else'');out.append(line)
   if i.mnemonic=='call' and comments:callSummary.append(line)
(R/'work/review-start-typing.txt').write_text('\n'.join(out));(R/'work/review-start-typing-calls.txt').write_text('\n'.join(callSummary));print('\n'.join(callSummary))
