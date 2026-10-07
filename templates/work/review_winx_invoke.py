from pathlib import Path
import sys,json,bisect
R=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(R/'work/pylib'))
import pefile,capstone
out=[]
for label,path,folder,targets in [('UDK','C:/Windows/System32/windowsudk.shellcommon.dll','host-udkshellcommon',[0x3acef0,0x3acf4c,0x3acfbc,0x3ad838,0x3ad4d8]),('PCS',str(R/'outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll'),'host-twinui',[0x5dd0b0,0x5ddbc4])]:
 pe=pefile.PE(path);rows=sorted((x['rva'],x['name']) for x in json.loads((R/'work/compat-research'/folder/'all-public-symbols.json').read_text()));keys=[x[0] for x in rows]
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 for start in targets:
  k=bisect.bisect_right(keys,start);end=min(keys[k],start+0x1800);out.append(f'\n{label} {start:x} {rows[k-1][1]}')
  for ins in cs.disasm(pe.get_data(start,end-start),start):
   notes=[]
   for op in ins.operands:
    dest=None
    if op.type==capstone.x86.X86_OP_IMM and ins.mnemonic in ('call','jmp'):dest=op.imm
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:dest=ins.address+ins.size+op.mem.disp
    if dest is not None:
     i=bisect.bisect_right(keys,dest)-1
     if i>=0 and dest-keys[i]<0x30:notes.append(rows[i][1]+f'+{dest-keys[i]:x}')
   out.append(f'{ins.address:x} {ins.mnemonic} {ins.op_str}'+(' ; '+' | '.join(notes) if notes else ''))
(R/'work/review-winx-invoke.txt').write_text('\n'.join(out));print('\n'.join(out[:90]))
