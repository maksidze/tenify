"""Read-only PE/PDB route extraction; no module loading or process access."""
from pathlib import Path
import sys,json,bisect
R=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(R/'work/pylib'))
import pefile,capstone
B=R/'outputs/Windows10-Components'
out=[]
for label,path,symbols,targets in [
 ('oldExplorer',B/'Runtime/Explorer10/explorer.exe',R/'work/explorer-public-symbols.json',[0x7750]),
 ('nativePCS',B/'Lab/HostMultitaskingCompat/twinui.pcshell.dll',R/'work/compat-research/host-twinui/all-public-symbols.json',[0x1bcd40,0x387130,0x4ed70]),
 ('nativeJump',Path('C:/Windows/ShellExperiences/JumpViewUI.dll'),R/'work/compat-research/host-jumpview/all-public-symbols.json',[0x6dee0,0x6e6f0,0x63064,0x14f20]),
 ('oldJump',B/'Image/4/Windows/ShellExperiences/JumpViewUI.dll',R/'work/compat-research/old-jumpview/all-public-symbols.json',[0x4ae0c,0xd6150]),
]:
 p=pefile.PE(str(path));rows=json.loads(symbols.read_text())
 rows=[(x['rva'],x['name']) if isinstance(x,dict) else tuple(x) for x in rows];rows.sort();keys=[r[0] for r in rows]
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 for target in targets:
  k=bisect.bisect_right(keys,target);end=min(keys[k] if k<len(keys) else target+0x1000,target+0x1800)
  while end<=target and k<len(keys)-1:k+=1;end=keys[k]
  out.append(f'\n{label} {target:x} {rows[k-1][1]} end{end:x}')
  for ins in cs.disasm(p.get_data(target,end-target),target):
   notes=[]
   for op in ins.operands:
    dest=None
    if op.type==capstone.x86.X86_OP_IMM and ins.mnemonic in ('call','jmp'):dest=op.imm
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:dest=ins.address+ins.size+op.mem.disp
    if dest is not None:
     i=bisect.bisect_right(keys,dest)-1
     if i>=0 and dest-keys[i]<0x40:notes.append(rows[i][1]+f'+{dest-keys[i]:x}')
     try:
      data=p.get_data(dest,200);s=data.decode('utf-16-le',errors='replace').split('\0')[0]
      if len(s)>5 and all(0x20<=ord(c)<0x7f for c in s[:6]):notes.append(repr(s))
     except Exception:pass
   out.append(f'{ins.address:x} {ins.mnemonic} {ins.op_str}'+(' ; '+' | '.join(notes) if notes else ''))
(R/'work/review-jumplist-route.txt').write_text('\n'.join(out),encoding='utf-8')
print('\n'.join(x for x in out if "'Windows" in x or 'Activation' in x or 'JumpView' in x or 'ShellExperience' in x))
