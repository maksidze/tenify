from pathlib import Path
import sys,json,struct
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Image/4/Windows/System32/twinui.pcshell.dll');sy=json.loads(Path('work/compat-research/old-twinui/all-public-symbols.json').read_text());sy.sort(key=lambda x:x['rva']);c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=[]
for s in p.sections:
 if not s.Characteristics&0x20000000:continue
 b=s.get_data()
 for disp in [0x90,0x98,0xa0]:
  pattern=b'\x48\x8b\x80'+struct.pack('<I',disp);start=0
  while True:
   k=b.find(pattern,start)
   if k<0:break
   start=k+1;rv=s.VirtualAddress+k;fn=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress),None)
   if not fn:continue
   inst=list(c.disasm(p.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress));idx=next((i for i,x in enumerate(inst) if x.address==rv),None)
   if idx is None:continue
   ctx=inst[max(0,idx-12):idx+3];t='\n'.join(f'{x.address:x}: {x.mnemonic} {x.op_str}' for x in ctx);symbol=[x for x in sy if x['rva']<=fn.BeginAddress][-1];rows.append({'rva':hex(rv),'disp':hex(disp),'runtimeFunction':hex(fn.BeginAddress),'nearestSymbol':symbol['name'],'hasWatcherOffsetC0':any('+ 0xc0]' in x.op_str for x in ctx),'context':t})
Path('work/windowwatcher/vtable-candidates.json').write_text(json.dumps(rows,indent=2));print('All',len(rows),'C0 context',sum(x['hasWatcherOffsetC0'] for x in rows));print('\n\n'.join(str(x) for x in rows if x['hasWatcherOffsetC0'] or 'WindowManagerBridge' in x['nearestSymbol']))
