import sys,json
sys.path.insert(0,'work/pylib');import pefile,capstone
p=pefile.PE('outputs/Windows10-Components/Runtime/Explorer10/explorer.exe');d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);s=dict(json.load(open('work/explorer-public-symbols.json')));imports={i.address-p.OPTIONAL_HEADER.ImageBase:i.name for e in p.DIRECTORY_ENTRY_IMPORT for i in e.imports}
lines=[]
for a in (0x233990,0x6baa0,0x9c310):
 f=next(x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=a<x.struct.EndAddress);lines.append(s[a])
 for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):
  line=f'{i.address:x}: {i.mnemonic} {i.op_str}'
  if i.mnemonic=='call' and i.op_str.startswith('0x'):line+=' '+s.get(int(i.op_str,16),'')
  if 'rip + ' in i.op_str:
   v=int(i.op_str.split('rip + ')[1].split(']')[0],16);line+=' '+str(imports.get(i.address+i.size+v,s.get(i.address+i.size+v,'')))
  lines.append(line)
open('work/taskview-button-disassembly.txt','w').write('\n'.join(lines));print('\n'.join(lines))
