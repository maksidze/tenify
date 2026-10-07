from pathlib import Path
import sys,struct,json
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Lab/PfnCompat/explorer.exe');rv=0x15412a;c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);c.detail=True
s=Path('work/inspect_shell_registration.py').read_text();func=s[s.index('def pdbStreams'):s.index('for s in downloads:')];exec(func)
streams=pdbStreams(next(Path('outputs/Windows10-Components/Symbols/explorer.pdb').rglob('*.pdb')).read_bytes());records=streams[struct.unpack_from('<H',streams[3],20)[0]];pos=0;syms=[]
while pos+4<len(records):
 length,kind=struct.unpack_from('<HH',records,pos);end=pos+length+2
 if length<2 or end>len(records):break
 if kind==0x110e and length>=12:
  flags,offset,seg=struct.unpack_from('<IIH',records,pos+4)
  if 0<seg<=len(p.sections):syms.append((p.sections[seg-1].VirtualAddress+offset,records[pos+14:end].split(b'\0')[0].decode(errors='replace')))
 pos=end
syms.sort();fn=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=rv<x.struct.EndAddress)
imp={x.address-p.OPTIONAL_HEADER.ImageBase:(x.name or b'ordinal').decode() for d in p.DIRECTORY_ENTRY_IMPORT for x in d.imports};lines=[]
print('AV',hex(rv),'function',hex(fn.BeginAddress),hex(fn.EndAddress));print([x for x in syms if fn.BeginAddress-16<=x[0]<=fn.EndAddress])
for i in c.disasm(p.get_data(fn.BeginAddress,fn.EndAddress-fn.BeginAddress),fn.BeginAddress):
 ann=''
 for x in i.operands:
  if x.type==capstone.x86.X86_OP_MEM and x.mem.base==capstone.x86.X86_REG_RIP:ann=imp.get(i.address+i.size+x.mem.disp,'')
 lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str} {ann}')
Path('work/pfn-compat-av-disassembly.txt').write_text('\n'.join(lines));Path('work/explorer-public-symbols.json').write_text(json.dumps(syms))
print('\n'.join(lines))

