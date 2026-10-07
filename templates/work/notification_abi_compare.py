from pathlib import Path
import sys,json
sys.path.insert(0,str(Path('work/pylib').resolve()))
import pefile,capstone
out=Path('outputs/Windows10-Components/Lab/NotificationCompat');out.mkdir(parents=True,exist_ok=True)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for tag,path in [('host','C:/Windows/System32/NotificationControllerPS.dll'),('old','outputs/Windows10-Components/Image/4/Windows/System32/NotificationControllerPS.dll')]:
 p=pefile.PE(path)
 sy=json.loads(Path(f'work/compat-research/{tag}-notification-ps/all-public-symbols.json').read_text())
 lines=[]
 for x in sy:
  if not any(w in x['name'] for w in ['CopyStruct@RefinedNotification','CopyStruct@NotificationGroupInfo','CopyStruct@NotificationAppInfo','FreeStruct@RefinedNotification']):continue
  fn=next((r.struct for r in p.DIRECTORY_ENTRY_EXCEPTION if r.struct.BeginAddress==x['rva']),None)
  size=fn.EndAddress-fn.BeginAddress if fn else 1600
  lines.append(str(x))
  lines.extend(f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in cs.disasm(p.get_data(x['rva'],size),x['rva']))
 (out/f'{tag}-refined-disassembly.txt').write_text('\n'.join(lines))
 print(tag, len(lines))
