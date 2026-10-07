from pathlib import Path
import sys,json,bisect,uuid
R=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(R/'work/pylib'))
import pefile,capstone
out=[]
sets=[('PCS',R/'outputs/Windows10-Components/Lab/HostMultitaskingCompat/twinui.pcshell.dll','host-twinui',[0x1f0248,0x65e348,0x2510a0,0x254a30,0x21e934,0x254c9c,0x254f48])]
sets.append(('TwinUI',Path('C:/Windows/System32/twinui.dll'),'host-twinui-base',[0x2cd560,0xd7c90]))
for label,path,folder,targets in sets:
 pe=pefile.PE(str(path));rows=sorted((x['rva'],x['name'])for x in json.loads((R/'work/compat-research'/folder/'all-public-symbols.json').read_text()));keys=[x[0]for x in rows];cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 for start in targets:
  k=bisect.bisect_right(keys,start);fn=next((f.struct for f in pe.DIRECTORY_ENTRY_EXCEPTION if f.struct.BeginAddress==start),None);end=fn.EndAddress if fn else min(keys[k],start+0x3000);out.append(f'\n{label} {start:x} {rows[k-1][1]}')
  for ins in cs.disasm(pe.get_data(start,end-start),start):
   notes=[]
   for op in ins.operands:
    dest=None
    if op.type==capstone.x86.X86_OP_IMM and ins.mnemonic in ('call','jmp'):dest=op.imm
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:dest=ins.address+ins.size+op.mem.disp
    if dest is not None:
     i=bisect.bisect_right(keys,dest)-1
     if i>=0 and dest-keys[i]<0x30:notes.append(rows[i][1]+f'+{dest-keys[i]:x}')
   out.append(f'{ins.address:x} {ins.mnemonic} {ins.op_str}'+(' ; '+' | '.join(notes)if notes else ''))
(R/'work/review-search-route.txt').write_text('\n'.join(out));print('written',len(out),'lines')
shell=pefile.PE('C:/Windows/System32/shell32.dll');print('CortanaExperienceFlowCF',uuid.UUID(bytes_le=shell.get_data(0x64b5a8,16)))
pcs=pefile.PE(str(sets[0][1]));print('WinX Search launch string',pcs.get_data(0x792ba0,400).decode('utf-16le',errors='replace').split('\0')[0])
rows=sorted((x['rva'],x['name'])for x in json.loads((R/'work/compat-research/host-twinui/all-public-symbols.json').read_text()));keys=[x[0]for x in rows]
import struct
for index,address in enumerate(struct.unpack('<6Q',pcs.get_data(0x6f3328,48))):
 rva=address-pcs.OPTIONAL_HEADER.ImageBase;i=bisect.bisect_right(keys,rva)-1;print('IImmersiveLauncherCortana',index,hex(rva),rows[i][1])
