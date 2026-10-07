import sys,json
sys.path.insert(0,'work/pylib');import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Runtime/Explorer10/explorer.exe');d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
s=dict(json.load(open('work/explorer-public-symbols.json')))
lines=[]
for a in (327424,2591216,59824):
 f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress);lines.append(str(s[a]))
 for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
  lines.append(f'{i.address:x} {i.mnemonic} {i.op_str}')
  if i.mnemonic=='call' and i.op_str.startswith('0x'):
   t=int(i.op_str,16);lines.append('CALLEE '+s.get(t,''))
open('work/inputswitch-callback-review.txt','w').write('\n'.join(lines))
print('\n'.join(l for l in lines if any(t in l for t in ('CALLEE',' + 0x38',' + 0x40',' + 0x58',' + 0x20',' + 0x18',' + 0x10'))))
