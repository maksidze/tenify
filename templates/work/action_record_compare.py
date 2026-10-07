from pathlib import Path
import sys,json
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
out=Path('outputs/Windows10-Components/Lab/FlyoutCompat')
c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for tag,src in [('old','outputs/Windows10-Components/Lab/FlyoutCompat/Runtime/Windows.UI.ActionCenter.dll'),('host','C:/Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy/Windows.UI.ActionCenter.dll')]:
 p=pefile.PE(src);s=json.loads(Path(f'work/compat-research/{tag}-action-center/all-public-symbols.json').read_text());lines=[]
 wanted=[x for x in s if 'NOC_REFINED_NOTIFICATION' in x['name'] and not any(w in x['name'] for w in ['?$','vector','allocator'])]
 for x in wanted:
  r=x['rva'];f=next((e.struct for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress==r),None);size=f.EndAddress-f.BeginAddress if f else 600
  lines.append(str(x));lines.extend(f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in c.disasm(p.get_data(r,size),r))
 (out/f'{tag}-notification-consumers.txt').write_text('\n'.join(lines))
 print(tag,len(wanted),len(lines))
