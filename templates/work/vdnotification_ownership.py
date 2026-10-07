exec(open('work/vdnotification_desktop_iids.py').read().split('for label,path')[0])
from pathlib import Path
lines=[]
for label,path,targets in [('old','outputs/Windows10-Components/Lab/XamlComponentCompat/twinui.pcshell.dll',(0x4bee50,0x4a54d0,0x4a5260,4870800)),('host','C:/Windows/System32/twinui.pcshell.dll',(0x5453d0,0x52a070,0x529fc0,0x1e7030))]:
 s=json.load(open(f'work/compat-research/{label}-twinui/all-public-symbols.json'));ns={x['rva']:x['name'] for x in s};p=pefile.PE(path);d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
 for target in targets:
  f=next((x.struct for x in p.DIRECTORY_ENTRY_EXCEPTION if x.struct.BeginAddress<=target<x.struct.EndAddress),None)
  if not f:continue
  lines.append(f'{label} {target:x} '+ns.get(target,''))
  for i in d.disasm(p.get_data(f.BeginAddress,f.EndAddress-f.BeginAddress),f.BeginAddress):lines.append(f'{i.address:x} {i.mnemonic} {i.op_str}')
Path('work/vdnotification-ownership-disassembly.txt').write_text('\n'.join(lines));print('\n'.join(lines[:65]))
